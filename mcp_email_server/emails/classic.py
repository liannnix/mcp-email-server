import email.utils
import re
from collections.abc import AsyncGenerator
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
from mcp_email_server.log import logger


class EmailClient:
    def __init__(self, email_server: EmailServer, sender: str | None = None):
        self.email_server = email_server
        self.sender = sender or email_server.user_name

        self.imap_class = aioimaplib.IMAP4_SSL if self.email_server.use_ssl else aioimaplib.IMAP4

        self.smtp_use_tls = self.email_server.use_ssl
        self.smtp_start_tls = self.email_server.start_ssl

    def _parse_email_data(self, raw_email: bytes, uid: str, flags: list[str] | None = None) -> dict[str, Any]:  # noqa: C901
        """Parse raw email data into a structured dictionary."""
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

        # Get body content
        body = ""
        attachments = []

        if email_message.is_multipart():
            for part in email_message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                # Handle attachments
                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        attachments.append(filename)
                # Handle text parts
                elif content_type == "text/plain":
                    body_part = part.get_payload(decode=True)
                    if body_part:
                        charset = part.get_content_charset("utf-8")
                        try:
                            body += body_part.decode(charset)
                        except UnicodeDecodeError:
                            body += body_part.decode("utf-8", errors="replace")
        else:
            # Handle plain text emails
            payload = email_message.get_payload(decode=True)
            if payload:
                charset = email_message.get_content_charset("utf-8")
                try:
                    body = payload.decode(charset)
                except UnicodeDecodeError:
                    body = payload.decode("utf-8", errors="replace")

        return {
            "uid": uid,
            "subject": subject,
            "from": sender,
            "body": body,
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
    ) -> AsyncGenerator[dict[str, Any], None]:
        imap = self.imap_class(self.email_server.host, self.email_server.port)
        try:
            # Wait for the connection to be established
            await imap._client_task
            await imap.wait_hello_from_server()

            # Login and select inbox
            await imap.login(self.email_server.user_name, self.email_server.password)
            try:
                await imap.id(name="mcp-email-server", version="1.0.0")
            except Exception as e:
                logger.warning(f"IMAP ID command failed: {e!s}")
            await imap.select("INBOX")

            search_criteria = self._build_search_criteria(before, since, subject, body, text, from_address, to_address, unread_only, flagged_only)
            logger.info(f"Get: Search criteria: {search_criteria}")

            # Search for messages - use UID SEARCH for better compatibility
            _, messages = await imap.uid_search(*search_criteria)

            # Handle empty or None responses
            if not messages or not messages[0]:
                logger.warning("No messages returned from search")
                message_ids = []
            else:
                message_ids = messages[0].split()
                logger.info(f"Found {len(message_ids)} message IDs")
            start = (page - 1) * page_size
            end = start + page_size

            if order == "desc":
                message_ids.reverse()

            # Fetch each message
            for _, message_id in enumerate(message_ids[start:end]):
                try:
                    # Convert message_id from bytes to string
                    message_id_str = message_id.decode("utf-8")

                    # Fetch the email using UID - try different formats for compatibility
                    # Also fetch FLAGS to get read/unread status
                    data = None
                    flags_data = None
                    fetch_formats = ["RFC822", "BODY[]", "BODY.PEEK[]", "(BODY.PEEK[])"]

                    # First fetch the flags separately
                    try:
                        _, flags_response = await imap.uid("fetch", message_id_str, "FLAGS")
                        if flags_response and len(flags_response) > 0:
                            # Parse flags from response like: b'71998 (UID 71998 FLAGS (\\Seen))'
                            for item in flags_response:
                                if isinstance(item, bytes) and b"FLAGS" in item:
                                    flags_str = item.decode("utf-8")
                                    # Extract flags between parentheses after FLAGS
                                    import re
                                    flags_match = re.search(r'FLAGS \(([^)]*)\)', flags_str)
                                    if flags_match:
                                        flags_data = flags_match.group(1).split()
                                    break
                    except Exception as e:
                        logger.debug(f"Failed to fetch flags: {e}")
                        flags_data = []

                    for fetch_format in fetch_formats:
                        try:
                            _, data = await imap.uid("fetch", message_id_str, fetch_format)

                            if data and len(data) > 0:
                                # Check if we got actual email content or just metadata
                                has_content = False
                                for item in data:
                                    if (
                                        isinstance(item, bytes)
                                        and b"FETCH (" in item
                                        and b"RFC822" not in item
                                        and b"BODY" not in item
                                    ):
                                        # This is just metadata (like 'FETCH (UID 71998)'), not actual content
                                        continue
                                    elif isinstance(item, bytes | bytearray) and len(item) > 100:
                                        # This looks like email content
                                        has_content = True
                                        break

                                if has_content:
                                    break
                                else:
                                    data = None  # Try next format

                        except Exception as e:
                            logger.debug(f"Fetch format {fetch_format} failed: {e}")
                            data = None

                    if not data:
                        logger.error(f"Failed to fetch UID {message_id_str} with any format")
                        continue

                    # Find the email data in the response
                    raw_email = None

                    # The email content is typically at index 1 as a bytearray
                    if len(data) > 1 and isinstance(data[1], bytearray):
                        raw_email = bytes(data[1])
                    else:
                        # Search through all items for email content
                        for item in data:
                            if isinstance(item, bytes | bytearray) and len(item) > 100:
                                # Skip IMAP protocol responses
                                if isinstance(item, bytes) and b"FETCH" in item:
                                    continue
                                # This is likely the email content
                                raw_email = bytes(item) if isinstance(item, bytearray) else item
                                break

                    if raw_email:
                        try:
                            parsed_email = self._parse_email_data(raw_email, message_id_str, flags_data)
                            yield parsed_email
                        except Exception as e:
                            # Log error but continue with other emails
                            logger.error(f"Error parsing email: {e!s}")
                    else:
                        logger.error(f"Could not find email data in response for message ID: {message_id_str}")
                except Exception as e:
                    logger.error(f"Error fetching message {message_id}: {e!s}")
        finally:
            # Ensure we logout properly
            try:
                await imap.logout()
            except Exception as e:
                logger.info(f"Error during logout: {e}")

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
            search_criteria.extend(["SUBJECT", subject])
        if body:
            search_criteria.extend(["BODY", body])
        if text:
            search_criteria.extend(["TEXT", text])
        if from_address:
            search_criteria.extend(["FROM", from_address])
        if to_address:
            search_criteria.extend(["TO", to_address])
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
    ) -> int:
        imap = self.imap_class(self.email_server.host, self.email_server.port)
        try:
            # Wait for the connection to be established
            await imap._client_task
            await imap.wait_hello_from_server()

            # Login and select inbox
            await imap.login(self.email_server.user_name, self.email_server.password)
            await imap.select("INBOX")
            search_criteria = self._build_search_criteria(before, since, subject, body, text, from_address, to_address, unread_only, flagged_only)
            logger.info(f"Count: Search criteria: {search_criteria}")
            # Search for messages and count them - use UID SEARCH for consistency
            _, messages = await imap.uid_search(*search_criteria)
            return len(messages[0].split())
        finally:
            # Ensure we logout properly
            try:
                await imap.logout()
            except Exception as e:
                logger.info(f"Error during logout: {e}")

    async def list_folders(self, pattern: str = "*") -> list[dict[str, Any]]:
        """List all IMAP folders with details."""
        imap = self.imap_class(self.email_server.host, self.email_server.port)
        try:
            await imap._client_task
            await imap.wait_hello_from_server()
            await imap.login(self.email_server.user_name, self.email_server.password)

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
        finally:
            try:
                await imap.logout()
            except Exception as e:
                logger.info(f"Error during logout: {e}")

    async def create_folder_if_needed(self, folder_name: str) -> bool:
        """Create a folder if it doesn't exist."""
        imap = self.imap_class(self.email_server.host, self.email_server.port)
        try:
            await imap._client_task
            await imap.wait_hello_from_server()
            await imap.login(self.email_server.user_name, self.email_server.password)

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
        finally:
            try:
                await imap.logout()
            except Exception as e:
                logger.info(f"Error during logout: {e}")

    async def move_to_folder(self, uid: str, target_folder: str,
                            create_if_missing: bool = True) -> bool:
        """Move email to specified folder."""
        imap = self.imap_class(self.email_server.host, self.email_server.port)
        try:
            await imap._client_task
            await imap.wait_hello_from_server()
            await imap.login(self.email_server.user_name, self.email_server.password)
            await imap.select("INBOX")  # Or current folder

            # Ensure target folder exists
            if create_if_missing:
                folder_created = await self.create_folder_if_needed(target_folder)
                if not folder_created:
                    logger.error(f"Failed to create folder: {target_folder}")
                    return False

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
        finally:
            try:
                await imap.logout()
            except Exception as e:
                logger.info(f"Error during logout: {e}")

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
    ) -> EmailPageResponse:
        emails = []
        async for email_data in self.incoming_client.get_emails_stream(
            page, page_size, before, since, subject, body, text, from_address, to_address, order
        ):
            emails.append(EmailData.from_email(email_data))
        total = await self.incoming_client.get_email_count(before, since, subject, body, text, from_address, to_address)
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
