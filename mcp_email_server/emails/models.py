from datetime import datetime
from typing import Any

from pydantic import BaseModel


class EmailData(BaseModel):
    uid: str
    subject: str
    sender: str
    body: str
    date: datetime
    attachments: list[str]
    flags: list[str]
    is_read: bool
    is_flagged: bool
    is_answered: bool

    @classmethod
    def from_email(cls, email: dict[str, Any]):
        flags = email.get("flags", [])
        return cls(
            uid=email["uid"],
            subject=email["subject"],
            sender=email["from"],
            body=email["body"],
            date=email["date"],
            attachments=email["attachments"],
            flags=flags,
            is_read="\\Seen" in flags,
            is_flagged="\\Flagged" in flags,
            is_answered="\\Answered" in flags,
        )


class EmailPageResponse(BaseModel):
    page: int
    page_size: int
    before: datetime | None
    since: datetime | None
    subject: str | None
    body: str | None
    text: str | None
    emails: list[EmailData]
    total: int
