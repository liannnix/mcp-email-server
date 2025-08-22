from datetime import datetime
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from mcp_email_server.config import (
    AccountAttributes,
    EmailSettings,
    ProviderSettings,
    get_settings,
)
from mcp_email_server.emails.dispatcher import dispatch_handler
from mcp_email_server.emails.models import EmailPageResponse

mcp = FastMCP("email")


@mcp.resource("email://{account_name}")
async def get_account(account_name: str) -> EmailSettings | ProviderSettings | None:
    settings = get_settings()
    return settings.get_account(account_name, masked=True)


@mcp.tool()
async def list_available_accounts() -> list[AccountAttributes]:
    settings = get_settings()
    return [account.masked() for account in settings.get_accounts()]


@mcp.tool()
async def add_email_account(email: EmailSettings) -> None:
    settings = get_settings()
    settings.add_email(email)
    settings.store()


@mcp.tool(description="Paginate emails, page start at 1, before and since as UTC datetime.")
async def page_email(
    account_name: Annotated[str, Field(description="The name of the email account.")],
    page: Annotated[
        int,
        Field(default=1, description="The page number to retrieve (starting from 1)."),
    ] = 1,
    page_size: Annotated[int, Field(default=10, description="The number of emails to retrieve per page.")] = 10,
    before: Annotated[
        datetime | None,
        Field(default=None, description="Retrieve emails before this datetime (UTC)."),
    ] = None,
    since: Annotated[
        datetime | None,
        Field(default=None, description="Retrieve emails since this datetime (UTC)."),
    ] = None,
    subject: Annotated[str | None, Field(default=None, description="Filter emails by subject.")] = None,
    body: Annotated[str | None, Field(default=None, description="Filter emails by body.")] = None,
    text: Annotated[str | None, Field(default=None, description="Filter emails by text.")] = None,
    from_address: Annotated[str | None, Field(default=None, description="Filter emails by sender address.")] = None,
    to_address: Annotated[
        str | None,
        Field(default=None, description="Filter emails by recipient address."),
    ] = None,
    order: Annotated[
        Literal["asc", "desc"],
        Field(default=None, description="Order emails by field. `asc` or `desc`."),
    ] = "desc",
    unread_only: Annotated[bool, Field(default=False, description="Filter to show only unread emails.")] = False,
    flagged_only: Annotated[bool, Field(default=False, description="Filter to show only flagged emails.")] = False,
    output_format: Annotated[
        Literal["html", "markdown"],
        Field(
            default="html",
            description="Output format: 'html' returns original content, 'markdown' converts HTML to markdown or returns plain text as-is.",
        ),
    ] = "html",
    truncate_body: Annotated[
        int | None,
        Field(
            default=None,
            description="Maximum number of characters for email body content. If specified, body content longer than this will be truncated.",
        ),
    ] = None,
    folder: Annotated[
        str | None,
        Field(
            default=None,
            description="Email folder to search in (e.g., 'INBOX.Junk', 'INBOX.Spam'). If not specified, searches INBOX.",
        ),
    ] = None,
) -> EmailPageResponse:
    handler = dispatch_handler(account_name)

    return await handler.get_emails(
        page=page,
        page_size=page_size,
        before=before,
        since=since,
        subject=subject,
        body=body,
        text=text,
        from_address=from_address,
        to_address=to_address,
        order=order,
        unread_only=unread_only,
        flagged_only=flagged_only,
        output_format=output_format,
        truncate_body=truncate_body,
        folder=folder,
    )


@mcp.tool(
    description="Send an email using the specified account. Recipient should be a list of email addresses.",
)
async def send_email(
    account_name: Annotated[str, Field(description="The name of the email account to send from.")],
    recipients: Annotated[list[str], Field(description="A list of recipient email addresses.")],
    subject: Annotated[str, Field(description="The subject of the email.")],
    body: Annotated[str, Field(description="The body of the email.")],
    cc: Annotated[
        list[str] | None,
        Field(default=None, description="A list of CC email addresses."),
    ] = None,
    bcc: Annotated[
        list[str] | None,
        Field(default=None, description="A list of BCC email addresses."),
    ] = None,
) -> None:
    handler = dispatch_handler(account_name)
    await handler.send_email(recipients, subject, body, cc, bcc)
    return


@mcp.tool(description="List all available email folders/labels in the account.")
async def list_email_folders(
    account_name: Annotated[str, Field(description="The name of the email account.")],
    pattern: Annotated[str, Field(description="Pattern to filter folders (default: '*' for all)")] = "*",
) -> list[dict[str, Any]]:
    handler = dispatch_handler(account_name)
    return await handler.list_folders(pattern)


@mcp.tool(description="Move an email to a specific folder. Creates folder if it doesn't exist.")
async def move_email_to_folder(
    account_name: Annotated[str, Field(description="The name of the email account.")],
    uid: Annotated[str | int, Field(description="The UID of the email to move.")],
    target_folder: Annotated[str, Field(description="The target folder name (e.g., 'Archive', 'Trash', 'Important').")],
    create_if_missing: Annotated[bool, Field(description="Create folder if it doesn't exist (default: true)")] = True,
) -> dict[str, bool]:
    handler = dispatch_handler(account_name)
    # Convert uid to string if it comes in as an integer
    uid_str = str(uid)
    success = await handler.move_to_folder(uid_str, target_folder, create_if_missing)
    return {"success": success}


@mcp.tool(description="Move multiple emails to a specific folder.")
async def move_emails_to_folder(
    account_name: Annotated[str, Field(description="The name of the email account.")],
    uids: Annotated[list[str | int], Field(description="List of email UIDs to move.")],
    target_folder: Annotated[str, Field(description="The target folder name.")],
    create_if_missing: Annotated[bool, Field(description="Create folder if it doesn't exist")] = True,
) -> dict[str, Any]:
    handler = dispatch_handler(account_name)
    results = {}

    # Ensure folder exists once if needed by attempting to move to it with create_if_missing=True
    # for the first email, then False for the rest

    for i, uid in enumerate(uids):
        # Convert uid to string if it comes in as an integer
        uid_str = str(uid)
        # Create folder on first email if needed
        create_folder = create_if_missing if i == 0 else False
        results[uid_str] = await handler.move_to_folder(uid_str, target_folder, create_folder)

    successful = sum(results.values())
    return {
        "results": results,
        "total_moved": successful,
        "failed": len(uids) - successful,
        "target_folder": target_folder,
    }


@mcp.tool(description="Save a complete email to a file without truncation.")
async def save_email_to_file(
    account_name: Annotated[str, Field(description="The name of the email account.")],
    uid: Annotated[str | int, Field(description="The UID of the email to save.")],
    file_path: Annotated[str, Field(description="The file path where to save the email content.")],
    output_format: Annotated[
        Literal["html", "markdown"],
        Field(
            default="markdown",
            description="Output format: 'html' returns original content, 'markdown' converts HTML to markdown or returns plain text as-is.",
        ),
    ] = "markdown",
    include_headers: Annotated[
        bool, Field(default=True, description="Include email headers (subject, from, date, etc.) in the saved file.")
    ] = True,
) -> dict[str, Any]:
    handler = dispatch_handler(account_name)

    # Get the single email by UID without truncation
    uid_str = str(uid)
    email_data = await handler.get_email_by_uid(uid_str, output_format=output_format)

    if not email_data:
        return {"success": False, "error": f"Email with UID {uid_str} not found"}

    # Build the content to save
    content_parts = []

    if include_headers:
        content_parts.extend([
            f"Subject: {email_data.get('subject', 'N/A')}",
            f"From: {email_data.get('from', 'N/A')}",
            f"Date: {email_data.get('date', 'N/A')}",
            f"UID: {email_data.get('uid', 'N/A')}",
            f"Body Format: {email_data.get('body_format', 'unknown')}",
            "",  # Empty line separator
        ])

    # Add the body content
    body = email_data.get("body", "")
    content_parts.append(body)

    # Join all parts
    full_content = "\n".join(content_parts)

    try:
        # Write to file
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(full_content)

        return {
            "success": True,
            "file_path": file_path,
            "content_length": len(full_content),
            "body_length": len(body),
            "format": output_format,
            "includes_headers": include_headers,
        }
    except Exception as e:
        return {"success": False, "error": f"Failed to write file: {e!s}"}


@mcp.tool(description="Add flags to one or more emails.")
async def add_email_flags(
    account_name: Annotated[str, Field(description="The name of the email account.")],
    uids: Annotated[list[str | int], Field(description="List of email UIDs to add flags to.")],
    flags: Annotated[list[str], Field(description="List of flags to add (e.g., ['ProcessedByBot', 'Seen']).")],
    silent: Annotated[
        bool, Field(description="Use silent operation to suppress server responses (default: False)")
    ] = False,
) -> dict[str, Any]:
    handler = dispatch_handler(account_name)

    # Convert UIDs to strings
    uid_strings = [str(uid) for uid in uids]

    results = await handler.add_flags(uid_strings, flags, silent)

    successful = sum(results.values())
    return {
        "results": results,
        "total_modified": successful,
        "failed": len(uids) - successful,
        "operation": "add_flags",
        "flags": flags,
        "silent": silent,
    }


@mcp.tool(description="Remove flags from one or more emails.")
async def remove_email_flags(
    account_name: Annotated[str, Field(description="The name of the email account.")],
    uids: Annotated[list[str | int], Field(description="List of email UIDs to remove flags from.")],
    flags: Annotated[list[str], Field(description="List of flags to remove (e.g., ['ProcessedByBot', 'Flagged']).")],
    silent: Annotated[
        bool, Field(description="Use silent operation to suppress server responses (default: False)")
    ] = False,
) -> dict[str, Any]:
    handler = dispatch_handler(account_name)

    # Convert UIDs to strings
    uid_strings = [str(uid) for uid in uids]

    results = await handler.remove_flags(uid_strings, flags, silent)

    successful = sum(results.values())
    return {
        "results": results,
        "total_modified": successful,
        "failed": len(uids) - successful,
        "operation": "remove_flags",
        "flags": flags,
        "silent": silent,
    }


@mcp.tool(description="Replace all flags on one or more emails with the specified flags.")
async def replace_email_flags(
    account_name: Annotated[str, Field(description="The name of the email account.")],
    uids: Annotated[list[str | int], Field(description="List of email UIDs to replace flags on.")],
    flags: Annotated[list[str], Field(description="List of flags to set (replaces all existing flags).")],
    silent: Annotated[
        bool, Field(description="Use silent operation to suppress server responses (default: False)")
    ] = False,
) -> dict[str, Any]:
    handler = dispatch_handler(account_name)

    # Convert UIDs to strings
    uid_strings = [str(uid) for uid in uids]

    results = await handler.replace_flags(uid_strings, flags, silent)

    successful = sum(results.values())
    return {
        "results": results,
        "total_modified": successful,
        "failed": len(uids) - successful,
        "operation": "replace_flags",
        "flags": flags,
        "silent": silent,
    }
