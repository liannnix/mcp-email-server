import email.utils
import re
import email
import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import datetime
from email.mime.text import MIMEText
from email.parser import BytesParser
from email.policy import default
from typing import Any

import aioimaplib
import aiosmtplib

from mcp_email_server.config import EmailServer, EmailSettings
from mcp_email_server.emails import EmailHandler
from mcp_email_server.emails.models import EmailData, EmailPageResponse
from mcp_email_server.utils.html_converter import determine_output_format
from mcp_email_server.log import logger


class EmailClient:
    def __init__(self, email_server: EmailServer, sender: str | None = None):
        self.email_server = email_server
        self.sender = sender or email_server.user_name

        self.imap_class = aioimaplib.IMAP4_SSL if self.email_server.use_ssl else aioimaplib.IMAP4

        self.smtp_use_tls = self.email_server.use_ssl
        self.smtp_start_tls = self.email_server.start_ssl

    @asynccontextmanager
    async def imap_connection(self, select_folder: str = "INBOX"):
        """Reusable IMAP connection context manager"""
        imap = self.imap_class(self.email_server.host, self.email_server.port)
        try:
            # Establish connection
            await imap._client_task
            await imap.wait_hello_from_server()
            
            # Login
            await imap.login(self.email_server.user_name, self.email_server.password)
            
            # Optional IMAP ID for compatibility
            try:
                await imap.id(name="mcp-email-server", version="1.0.0")
            except Exception as e:
                logger.warning(f"IMAP ID command failed: {e!s}")
            
            # Select folder if specified
            if select_folder:
                logger.debug(f"Selecting IMAP folder: {select_folder}")
                select_result = await imap.select(select_folder)
                
                # Verify the folder was actually selected
                if hasattr(select_result, 'result') and select_result.result == 'OK':
                    logger.debug(f"Successfully selected folder: {select_folder}")
                else:
                    logger.error(f"Failed to select folder {select_folder}: {select_result}")
                    raise Exception(f"Failed to select folder {select_folder}")
                
            yield imap
            
        finally:
            try:
                await imap.logout()
            except Exception as e:
                logger.info(f"Error during logout: {e}")

    async def _fetch_email_data(self, imap, identifier: str, by_uid: bool = True, include_flags: bool = True) -> tuple[bytes | None, list[str]]:
        """Unified email fetching with multiple format fallbacks"""
        
        fetch_cmd = imap.uid if by_uid else imap.fetch
        
        # Determine fetch formats based on needs
        if include_flags:
            fetch_formats = [
                "(BODY.PEEK[] FLAGS)",
                "(RFC822.PEEK FLAGS)", 
                "(BODY[] FLAGS)",
                "(RFC822 FLAGS)"
            ]
        else:
            fetch_formats = [
                "BODY.PEEK[]",
                "(BODY.PEEK[])",
                "BODY[]", 
                "RFC822"
            ]
        
        # Try each format until we get content
        for fetch_format in fetch_formats:
            try:
                response = await fetch_cmd("fetch", identifier, fetch_format)
                
                if response and response.result == 'OK' and response.lines:
                    raw_email, flags_data = self._extract_email_and_flags(response.lines)
                    
                    if raw_email and len(raw_email) > 100:  # Validate content
                        return raw_email, flags_data
                        
            except Exception as e:
                logger.debug(f"Fetch format {fetch_format} failed: {e}")
                continue
        
        return None, []

    def _extract_email_and_flags(self, response_lines) -> tuple[bytes | None, list[str]]:
        """Extract email content and flags from IMAP response"""
        raw_email = None
        flags_data = []
        
        # Extract flags from response
        for item in response_lines:
            if isinstance(item, str) and "FLAGS" in item:
                flags_match = re.search(r'FLAGS \(([^)]*)\)', item)
                if flags_match:
                    flags_str = flags_match.group(1)
                    flags_data = [flag.strip().replace('\\', '') for flag in flags_str.split() if flag.strip()]
                break
        
        # Find email content - try index 1 first (typical location)
        if len(response_lines) > 1 and isinstance(response_lines[1], bytearray):
            raw_email = bytes(response_lines[1])
        else:
            # Search through all items for email content
            for item in response_lines:
                if isinstance(item, (bytes, bytearray)) and len(item) > 100:
                    # Skip IMAP protocol responses
                    if isinstance(item, bytes) and b"FETCH" in item:
                        continue
                    # This is likely the email content
                    raw_email = bytes(item) if isinstance(item, bytearray) else item
                    break
        
        return raw_email, flags_data

    async def get_single_email(self, uid: str, format: str = "html", truncate_body: int | None = None, imap=None) -> dict[str, Any] | None:
        """Get a single email by UID - unified method used by both streaming and direct retrieval"""
        
        async def _fetch_and_parse(imap_conn):
            raw_email, flags_data = await self._fetch_email_data(imap_conn, uid, by_uid=True, include_flags=True)
            
            if raw_email:
                try:
                    return self._parse_email_data(raw_email, uid, flags_data, format, truncate_body)
                except Exception as e:
                    logger.error(f"Error parsing email {uid}: {e}")
                    return None
            else:
                logger.error(f"No email content found for UID {uid}")
                return None
        
        # Use provided IMAP connection or create a new one
        if imap is not None:
            return await _fetch_and_parse(imap)
        else:
            async with self.imap_connection() as imap:
                return await _fetch_and_parse(imap)

    def _parse_email_data(self, raw_email: bytes, uid: str, flags: list[str] | None = None, format: str = "html", truncate_body: int | None = None) -> dict[str, Any]:  # noqa: C901
        """Parse raw email data into a structured dictionary with format conversion."""
        parser = BytesParser(policy=default)
        email_message = parser.parsebytes(raw_email)

        # Extract email parts
        subject = email_message.get("Subject", "")
        sender = email_message.get("From", "")
        date_str = email_message.get("Date", "")

        # Parse date
        try:
            date_tuple = email.utils.parsedate_tz(date_str)
            date = datetime.fromtimestamp(email.utils.mktime_tz(date_tuple)) if date_tuple else datetime.now()
        except Exception:
            date = datetime.now()

        # Get body content and determine format
        body = ""
        content_type = ""
        attachments = []

        if email_message.is_multipart():
            # For multipart emails, prioritize HTML content for full information
            html_part = ""
            text_part = ""
            
            for part in email_message.walk():
                part_content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                # Handle attachments
                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        attachments.append(filename)
                # Handle HTML parts
                elif part_content_type == "text/html":
                    body_part = part.get_payload(decode=True)
                    if body_part:
                        charset = part.get_content_charset("utf-8")
                        try:
                            html_part = body_part.decode(charset)
                        except UnicodeDecodeError:
                            html_part = body_part.decode("utf-8", errors="replace")
                # Handle text parts
                elif part_content_type == "text/plain":
                    body_part = part.get_payload(decode=True)
                    if body_part:
                        charset = part.get_content_charset("utf-8")
                        try:
                            text_part = body_part.decode(charset)
                        except UnicodeDecodeError:
                            text_part = body_part.decode("utf-8", errors="replace")
            
            # Choose content based on what's available
            if html_part:
                body = html_part
                content_type = "text/html"
            elif text_part:
                body = text_part
                content_type = "text/plain"
            else:
                body = ""
                content_type = "text/plain"
            
            # Store content type as multipart for format processing
            content_type = "multipart/alternative"
        else:
            # Handle single-part emails
            content_type = email_message.get_content_type() or "text/plain"
            payload = email_message.get_payload(decode=True)
            if payload:
                charset = email_message.get_content_charset("utf-8")
                try:
                    body = payload.decode(charset)
                except UnicodeDecodeError:
                    body = payload.decode("utf-8", errors="replace")

        # Apply format conversion
        processed_body, body_format = determine_output_format(body, content_type, email_message, format)
        
        # Apply truncation if specified
        if truncate_body is not None and len(processed_body) > truncate_body:
            processed_body = processed_body[:truncate_body] + "... [truncated]"

        return {
            "uid": uid,
            "subject": subject,
            "from": sender,
            "body": processed_body,
            "body_format": body_format,
            "date": date,
            "attachments": attachments,
            "flags": flags or [],
        }

    async def get_emails_stream(  # noqa: C901
        self,
        page: int = 1,
        page_size: int = 10,
        before: datetime | None = None,
        since: datetime | None = None,
        subject: str | None = None,
        body: str | None = None,
        text: str | None = None,
        from_address: str | None = None,
        to_address: str | None = None,
        order: str = "desc",
        unread_only: bool = False,
        flagged_only: bool = False,
        format: str = "html",
        truncate_body: int | None = None,
        folder: str | None = None,
    ) -> AsyncGenerator[dict[str, Any], None]:
        effective_folder = folder or "INBOX"
        async with self.imap_connection(select_folder=effective_folder) as imap:
            search_criteria = self._build_search_criteria(before, since, subject, body, text, from_address, to_address, unread_only, flagged_only)
            logger.info(f"Get: Search criteria: {search_criteria}")

            # Search for messages - use UID SEARCH for better compatibility
            response, messages = await imap.uid_search(*search_criteria)
            logger.debug(f"Search response status: {response}")
            
            # Check if the search command failed
            if response and hasattr(response, 'result'):
                if response.result != 'OK':
                    logger.error(f"IMAP search failed with result: {response.result}")
                    logger.error(f"Search criteria: {search_criteria}")
                    if messages:
                        logger.error(f"Error details: {messages}")
                    message_ids = []
                    # Early return on search failure
                    return

            # Handle empty or None responses
            if not messages or not messages[0]:
                logger.warning("No messages returned from search")
                message_ids = []
            else:
                # Debug log the raw response
                logger.debug(f"Raw search response: {messages}")
                logger.debug(f"messages[0] type: {type(messages[0])}, value: {messages[0]}")
                
                # Validate that we have UIDs (should be numeric)
                try:
                    # First try to split the response
                    potential_ids = messages[0].split()
                    
                    # Verify at least one ID is numeric (UIDs should be numbers)
                    if potential_ids:
                        # Decode first ID and check if numeric
                        first_id = potential_ids[0].decode('utf-8') if isinstance(potential_ids[0], bytes) else str(potential_ids[0])
                        int(first_id)  # Will raise ValueError if not numeric
                    
                    message_ids = potential_ids
                    logger.info(f"Found {len(message_ids)} message IDs")
                    logger.debug(f"Parsed message IDs: {message_ids[:10] if len(message_ids) > 10 else message_ids}")
                except (ValueError, AttributeError) as e:
                    # Not valid UIDs - likely an error message
                    logger.error(f"Invalid IMAP search response (expected UIDs): {messages[0]}")
                    logger.error(f"Search criteria that triggered this: {search_criteria}")
                    message_ids = []
            start = (page - 1) * page_size
            end = start + page_size

            if order == "desc":
                message_ids.reverse()

            # Fetch each message using unified single email method
            for _, message_id in enumerate(message_ids[start:end]):
                try:
                    # Convert message_id from bytes to string
                    message_id_str = message_id.decode("utf-8")

                    # Use unified get_single_email method with shared IMAP connection
                    email_data = await self.get_single_email(message_id_str, format, truncate_body, imap=imap)
                    
                    if email_data:
                        yield email_data
                    else:
                        logger.error(f"Failed to retrieve email with UID {message_id_str}")
                        
                except Exception as e:
                    logger.error(f"Error processing email {message_id}: {e!s}")

    @staticmethod
    def _build_search_criteria(
        before: datetime | None = None,
        since: datetime | None = None,
        subject: str | None = None,
        body: str | None = None,
        text: str | None = None,
        from_address: str | None = None,
        to_address: str | None = None,
        unread_only: bool = False,
        flagged_only: bool = False,
    ):
        search_criteria = []
        if before:
            search_criteria.extend(["BEFORE", before.strftime("%d-%b-%Y").upper()])
        if since:
            search_criteria.extend(["SINCE", since.strftime("%d-%b-%Y").upper()])
        if subject:
            # Always quote search strings for IMAP consistency
            search_criteria.extend(["SUBJECT", f'"{subject}"'])
        if body:
            search_criteria.extend(["BODY", f'"{body}"'])
        if text:
            search_criteria.extend(["TEXT", f'"{text}"'])
        if from_address:
            search_criteria.extend(["FROM", f'"{from_address}"'])
        if to_address:
            search_criteria.extend(["TO", f'"{to_address}"'])
        if unread_only:
            search_criteria.append("UNSEEN")
        if flagged_only:
            search_criteria.append("FLAGGED")

        # If no specific criteria, search for ALL
        if not search_criteria:
            search_criteria = ["ALL"]

        return search_criteria

    async def get_email_count(
        self,
        before: datetime | None = None,
        since: datetime | None = None,
        subject: str | None = None,
        body: str | None = None,
        text: str | None = None,
        from_address: str | None = None,
        to_address: str | None = None,
        unread_only: bool = False,
        flagged_only: bool = False,
        folder: str | None = None,
    ) -> int:
        async with self.imap_connection(select_folder=folder or "INBOX") as imap:
            search_criteria = self._build_search_criteria(before, since, subject, body, text, from_address, to_address, unread_only, flagged_only)
            logger.info(f"Count: Search criteria: {search_criteria}")
            # Search for messages and count them - use UID SEARCH for consistency
            response, messages = await imap.uid_search(*search_criteria)
            
            # Check if search failed
            if response and hasattr(response, 'result') and response.result != 'OK':
                logger.error(f"IMAP count search failed with result: {response.result}")
                logger.error(f"Search criteria: {search_criteria}")
                return 0
            
            if not messages or not messages[0]:
                return 0
                
            # Validate we have UIDs, not an error message
            try:
                potential_ids = messages[0].split()
                if potential_ids:
                    # Check first ID is numeric
                    first_id = potential_ids[0].decode('utf-8') if isinstance(potential_ids[0], bytes) else str(potential_ids[0])
                    int(first_id)
                return len(potential_ids)
            except (ValueError, AttributeError):
                logger.error(f"Invalid count response: {messages[0]}")
                return 0

    async def list_folders(self, pattern: str = "*") -> list[dict[str, Any]]:
        """List all IMAP folders with details."""
        async with self.imap_connection(select_folder=None) as imap:
            # List folders matching pattern
            # list() expects reference_name and mailbox_pattern
            _, folders = await imap.list('""', pattern)
            folder_info = []

            for folder in folders:
                if isinstance(folder, bytes):
                    folder_str = folder.decode('utf-8')
                    # Parse IMAP LIST response: (\Flags) "delimiter" "folder name"
                    match = re.match(r'\(([^)]*)\)\s+"([^"]+)"\s+"([^"]+)"', folder_str)
                    if match:
                        flags, delimiter, name = match.groups()
                        folder_info.append({
                            "name": name,
                            "delimiter": delimiter,
                            "flags": flags.split() if flags else [],
                            "can_select": "\\Noselect" not in flags
                        })

            return folder_info

    async def create_folder_if_needed(self, folder_name: str) -> bool:
        """Create a folder if it doesn't exist."""
        try:
            async with self.imap_connection(select_folder=None) as imap:
                # Check if folder exists
                _, existing = await imap.list('""', folder_name)
                if existing and len(existing) > 0:
                    return True

                # Create folder
                await imap.create(folder_name)
                logger.info(f"Created folder: {folder_name}")
                return True

        except Exception as e:
            logger.error(f"Error creating folder {folder_name}: {e}")
            return False

    async def move_to_folder(self, uid: str, target_folder: str,
                            create_if_missing: bool = True) -> bool:
        """Move email to specified folder."""
        try:
            # Ensure target folder exists (do this before opening IMAP connection)
            if create_if_missing:
                folder_created = await self.create_folder_if_needed(target_folder)
                if not folder_created:
                    logger.error(f"Failed to create folder: {target_folder}")
                    return False

            async with self.imap_connection() as imap:
                # Try MOVE command first (RFC 6851)
                try:
                    await imap.uid("move", uid, target_folder)
                    logger.info(f"Moved email {uid} to {target_folder} using MOVE")
                    return True
                except Exception as move_error:
                    logger.debug(f"MOVE not supported: {move_error}")

                    # Fallback to COPY + DELETE
                    try:
                        # Copy to target folder
                        await imap.uid("copy", uid, target_folder)

                        # Mark as deleted in source
                        await imap.uid("store", uid, "+FLAGS", "\\Deleted")

                        # Expunge to remove from source
                        await imap.expunge()

                        logger.info(f"Moved email {uid} to {target_folder} using COPY+DELETE")
                        return True

                    except Exception as e:
                        logger.error(f"Failed to move email: {e}")
                        return False

        except Exception as e:
            logger.error(f"Error moving email {uid} to {target_folder}: {e}")
            return False

    async def get_email_by_uid(self, uid: str, format: str = "html") -> dict[str, Any] | None:
        """Get a single email by its UID without truncation."""
        return await self.get_single_email(uid, format, truncate_body=None)

    def _normalize_flags(self, flags: list[str]) -> list[str]:
        """Normalize flag format - ensure proper backslash prefix for system flags."""
        normalized = []
        for flag in flags:
            # Remove any existing backslashes and normalize
            clean_flag = flag.strip().lstrip('\\')
            
            # System flags should have backslash prefix
            system_flags = ['Seen', 'Answered', 'Flagged', 'Deleted', 'Draft', 'Recent']
            if clean_flag in system_flags:
                normalized.append(f'\\{clean_flag}')
            else:
                # Custom flags - add backslash if not present
                normalized.append(f'\\{clean_flag}')
                
        return normalized

    async def modify_flags(self, uids: list[str], flags: list[str], operation: str, silent: bool = False) -> dict[str, bool]:
        """Core flag modification method using IMAP STORE command.
        
        Args:
            uids: List of email UIDs to modify
            flags: List of flags to add/remove/replace
            operation: One of 'add' (+FLAGS), 'remove' (-FLAGS), 'replace' (FLAGS)
            silent: Use .SILENT suffix to suppress server responses
            
        Returns:
            Dict mapping UID to success/failure status
        """
        if not uids or not flags:
            return {}
            
        # Normalize flags
        normalized_flags = self._normalize_flags(flags)
        flags_str = f"({' '.join(normalized_flags)})"
        
        # Build STORE command
        if operation == "add":
            store_cmd = "+FLAGS.SILENT" if silent else "+FLAGS"
        elif operation == "remove":
            store_cmd = "-FLAGS.SILENT" if silent else "-FLAGS"
        elif operation == "replace":
            store_cmd = "FLAGS.SILENT" if silent else "FLAGS"
        else:
            raise ValueError(f"Invalid operation: {operation}")
            
        results = {}
        
        try:
            async with self.imap_connection() as imap:
                # Convert UIDs to comma-separated string for batch operation
                uid_list = ','.join(str(uid) for uid in uids)
                
                try:
                    # Execute UID STORE command
                    response = await imap.uid("store", uid_list, store_cmd, flags_str)
                    
                    if response and response.result == 'OK':
                        # For successful batch operation, mark all UIDs as successful
                        for uid in uids:
                            results[str(uid)] = True
                        logger.info(f"Successfully {operation} flags {flags_str} on {len(uids)} emails")
                    else:
                        # Batch failed, mark all as failed
                        for uid in uids:
                            results[str(uid)] = False
                        logger.error(f"Failed to {operation} flags {flags_str}: {response}")
                        
                except Exception as e:
                    # If batch fails, try individual operations for better error isolation
                    logger.warning(f"Batch flag operation failed, trying individual operations: {e}")
                    
                    for uid in uids:
                        try:
                            response = await imap.uid("store", str(uid), store_cmd, flags_str)
                            results[str(uid)] = response and response.result == 'OK'
                            if not results[str(uid)]:
                                logger.error(f"Failed to {operation} flags on UID {uid}: {response}")
                        except Exception as individual_error:
                            logger.error(f"Error modifying flags on UID {uid}: {individual_error}")
                            results[str(uid)] = False
                            
        except Exception as e:
            logger.error(f"Error in flag modification: {e}")
            for uid in uids:
                results[str(uid)] = False
                
        return results

    async def add_flags(self, uids: list[str], flags: list[str], silent: bool = False) -> dict[str, bool]:
        """Add flags to emails using +FLAGS operation."""
        return await self.modify_flags(uids, flags, "add", silent)

    async def remove_flags(self, uids: list[str], flags: list[str], silent: bool = False) -> dict[str, bool]:
        """Remove flags from emails using -FLAGS operation."""
        return await self.modify_flags(uids, flags, "remove", silent)

    async def replace_flags(self, uids: list[str], flags: list[str], silent: bool = False) -> dict[str, bool]:
        """Replace all flags on emails using FLAGS operation."""
        return await self.modify_flags(uids, flags, "replace", silent)

    async def send_email(
        self, recipients: list[str], subject: str, body: str, cc: list[str] | None = None, bcc: list[str] | None = None
    ):
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self.sender
        msg["To"] = ", ".join(recipients)

        # Add CC header if provided (visible to recipients)
        if cc:
            msg["Cc"] = ", ".join(cc)

        # Note: BCC recipients are not added to headers (they remain hidden)
        # but will be included in the actual recipients for SMTP delivery

        async with aiosmtplib.SMTP(
            hostname=self.email_server.host,
            port=self.email_server.port,
            start_tls=self.smtp_start_tls,
            use_tls=self.smtp_use_tls,
        ) as smtp:
            await smtp.login(self.email_server.user_name, self.email_server.password)

            # Create a combined list of all recipients for delivery
            all_recipients = recipients.copy()
            if cc:
                all_recipients.extend(cc)
            if bcc:
                all_recipients.extend(bcc)

            await smtp.send_message(msg, recipients=all_recipients)


class ClassicEmailHandler(EmailHandler):
    def __init__(self, email_settings: EmailSettings):
        self.email_settings = email_settings
        self.incoming_client = EmailClient(email_settings.incoming)
        self.outgoing_client = EmailClient(
            email_settings.outgoing,
            sender=f"{email_settings.full_name} <{email_settings.email_address}>",
        )

    async def get_emails(
        self,
        page: int = 1,
        page_size: int = 10,
        before: datetime | None = None,
        since: datetime | None = None,
        subject: str | None = None,
        body: str | None = None,
        text: str | None = None,
        from_address: str | None = None,
        to_address: str | None = None,
        order: str = "desc",
        unread_only: bool = False,
        flagged_only: bool = False,
        format: str = "html",
        truncate_body: int | None = None,
        folder: str | None = None,
    ) -> EmailPageResponse:
        emails = []
        async for email_data in self.incoming_client.get_emails_stream(
            page, page_size, before, since, subject, body, text, from_address, to_address, order, unread_only, flagged_only, format, truncate_body, folder
        ):
            emails.append(EmailData.from_email(email_data))
        total = await self.incoming_client.get_email_count(before, since, subject, body, text, from_address, to_address, unread_only, flagged_only, folder)
        return EmailPageResponse(
            page=page,
            page_size=page_size,
            before=before,
            since=since,
            subject=subject,
            body=body,
            text=text,
            emails=emails,
            total=total,
        )

    async def send_email(
        self, recipients: list[str], subject: str, body: str, cc: list[str] | None = None, bcc: list[str] | None = None
    ) -> None:
        await self.outgoing_client.send_email(recipients, subject, body, cc, bcc)

    async def list_folders(self, pattern: str = "*") -> list[dict[str, Any]]:
        return await self.incoming_client.list_folders(pattern)

    async def move_to_folder(self, uid: str, target_folder: str, create_if_missing: bool = True) -> bool:
        return await self.incoming_client.move_to_folder(uid, target_folder, create_if_missing)

    async def get_email_by_uid(self, uid: str, format: str = "html") -> dict[str, Any] | None:
        return await self.incoming_client.get_email_by_uid(uid, format)

    async def add_flags(self, uids: list[str], flags: list[str], silent: bool = False) -> dict[str, bool]:
        """Add flags to emails."""
        return await self.incoming_client.add_flags(uids, flags, silent)

    async def remove_flags(self, uids: list[str], flags: list[str], silent: bool = False) -> dict[str, bool]:
        """Remove flags from emails."""
        return await self.incoming_client.remove_flags(uids, flags, silent)

    async def replace_flags(self, uids: list[str], flags: list[str], silent: bool = False) -> dict[str, bool]:
        """Replace all flags on emails."""
        return await self.incoming_client.replace_flags(uids, flags, silent)
