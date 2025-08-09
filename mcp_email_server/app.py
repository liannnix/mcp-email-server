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
        "target_folder": target_folder
    }
