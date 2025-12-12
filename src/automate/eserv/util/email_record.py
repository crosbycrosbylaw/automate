from __future__ import annotations

import typing

__all__ = ['make_email_record']

from datetime import UTC, datetime
from uuid import uuid4

if typing.TYPE_CHECKING:
    from automate.eserv.types import EmailInfo, EmailRecord

    @typing.overload
    def make_email_record(
        *,
        uid: str | None = None,
        sender: str | None = 'unknown',
        subject: str | None = '',
    ) -> EmailInfo: ...
    @typing.overload
    def make_email_record(
        body: str,
        *,
        uid: str | None = None,
        received_at: datetime | None = None,
        subject: str | None = '',
        sender: str | None = 'unknown',
    ) -> EmailRecord: ...


def make_email_record(
    body: ... = None,
    *,
    uid: str | None = None,
    received_at: datetime | None = None,
    subject: str | None = '',
    sender: str | None = 'unknown',
) -> ...:
    """Initialize a new email record, with sensible defaults."""
    from automate.eserv.types.structs import EmailInfo, EmailRecord

    uid = uid or str(uuid4())
    subject = subject or ''
    sender = sender or 'unknown'

    if body is None:
        return EmailInfo(uid=uid, sender=sender, subject=subject)

    return EmailRecord(uid or str(uuid4()), sender, subject, received_at or datetime.now(UTC), body)
