from __future__ import annotations

__all__ = ['collect_unprocessed_emails']

import threading
from contextvars import ContextVar
from datetime import datetime
from typing import TYPE_CHECKING

from automate.eserv.monitor.request import build_request
from automate.eserv.util.email_record import make_email_record

if TYPE_CHECKING:
    from contextvars import Token
    from datetime import datetime

    from msgraph.generated.models.mail_folder import MailFolder
    from msgraph.graph_service_client import GraphServiceClient

    from automate.eserv.types import EmailRecord


_lock = threading.Lock()
_cache: dict[str, str] = {}


async def _resolve_mail_folders(
    app: GraphServiceClient,
    segments: list[str],
    folders: list[MailFolder],
) -> str:

    top = segments.pop(0)
    target = ContextVar[str]('target', default=top)

    mapping: dict[str, str] = dict.fromkeys(segments, '')

    def advance(id: str) -> Token[str] | None:
        mapping[target.get()] = id
        try:
            tkn = target.set(segments.pop(0))
        except IndexError:
            return None
        else:
            return tkn

    async def resolve(f: MailFolder) -> None:
        target_id = target.get()

        if fid := f and f.display_name == target_id and f.id:
            if not advance(fid):
                return

            if f.child_folder_count and not f.child_folders:
                request = build_request(
                    app.me.mail_folders.by_mail_folder_id(fid).child_folders,
                    filter=f"startswith(displayName, '{target_id}')",
                )
                subfolders = await request.get()

            else:
                subfolders = f.child_folders or []

            for sf in subfolders:
                await resolve(sf)

        if not mapping.get(target_id):
            raise LookupError(target_id)

    for f in folders:
        await resolve(f)

    name = target.get()
    return mapping[name]


async def collect_unprocessed_emails(
    app: GraphServiceClient,
    received_after: datetime,
    path_segments: list[str],
    processed_uids: set[str] | None = None,
    batch_size: int = 50,
    single_batch: bool = False,
) -> list[EmailRecord]:
    """Fetch emails from monitoring folder, excluding any that were already processed.

    Raises:
        ValueError:
            If the email's html body is empty.

    """
    records: list[EmailRecord] = []

    with _lock:
        fid = _cache.get('monitoring')

    if fid is None:
        request = build_request(
            app.me.mail_folders,
            select=['id', 'displayName', 'childFolders', 'childFolderCount'],
            top=50,
        )
        try:
            fid = await _resolve_mail_folders(app, path_segments, await request.get())
        except ValueError as e:
            raise FileNotFoundError from e
        else:
            with _lock:
                _cache.update(monitoring=fid)

    request = build_request(
        app.me.mail_folders.by_mail_folder_id(fid).messages,
        filter=f'receivedDateTime ge {received_after.isoformat()}Z',
        top=batch_size,
        select=['id', 'from', 'subject', 'receivedDateTime', 'bodyPreview', 'body'],
        count=not single_batch,
    )

    for m in await request.collect():
        if not m.id or (processed_uids and m.id in processed_uids):
            continue

        if not (content := getattr(m.body, 'content', None)):
            message = f'Missing HTML body for message {m.id}'
            raise ValueError(message)

        records.append(
            make_email_record(
                uid=m.id,
                sender=m.sender and m.sender.email_address and m.sender.email_address.address,
                subject=m.subject,
                body=content,
                received_at=m.received_date_time,
            )
        )

    return records
