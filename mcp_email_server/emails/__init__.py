import abc
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcp_email_server.emails.models import EmailPageResponse


class EmailHandler(abc.ABC):
    @abc.abstractmethod
    async def get_emails(
        self,
        page: int = 1,
        page_size: int = 10,
        before: datetime | None = None,
        after: datetime | None = None,
        subject: str | None = None,
        body: str | None = None,
        text: str | None = None,
        from_address: str | None = None,
        to_address: str | None = None,
        order: str = "desc",
        unread_only: bool = False,
        flagged_only: bool = False,
    ) -> "EmailPageResponse":
        """
        Get emails
        """

    @abc.abstractmethod
    async def send_email(
        self, recipients: list[str], subject: str, body: str, cc: list[str] | None = None, bcc: list[str] | None = None
    ) -> None:
        """
        Send email
        """

    @abc.abstractmethod
    async def list_folders(self, pattern: str = "*") -> list[dict[str, Any]]:
        """
        List available folders
        """

    @abc.abstractmethod
    async def move_to_folder(self, uid: str, target_folder: str, create_if_missing: bool = True) -> bool:
        """
        Move email to specified folder
        """
