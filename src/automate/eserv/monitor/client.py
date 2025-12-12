from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from functools import cached_property, partial
from typing import TYPE_CHECKING

from msgraph.graph_service_client import GraphServiceClient
from rampy import make_factory

from automate.eserv.monitor.utils import resolve_mail_folders
from automate.eserv.util.email_record import make_email_record

from .request import build_msgraph_query_request

if TYPE_CHECKING:
    from automate.eserv.types import Config, EmailRecord, StatusFlag

    from .client import GraphClient
    from .types import MailFolder, Message


class GraphClient:
    """Microsoft Graph API client for email monitoring."""

    def __init__(self, config: Config) -> None:
        """Initialize a Microsoft Graph client."""
        self._folder_id_cache: dict[str, str] = {}
        self._lock = threading.Lock()

        self.config = config
        self.cutoff = datetime.now(UTC) - timedelta(days=config.monitor_num_days)

        self.request = partial(build_msgraph_query_request, client=self.client)

    @cached_property
    def path_segments(self) -> list[str]:
        return [part.strip() for part in self.config.monitor_mail_folder_path]

    @cached_property
    def client(self) -> GraphServiceClient:
        return GraphServiceClient(self.config.creds.msal)

    async def _resolve_monitoring_folder_id(self) -> str:
        """Resolve monitoring folder path to folder ID.

        Raises:
            FileNotFoundError: If the folder does not exist or cannot be resolved.

        """
        with self._lock:
            if 'monitoring' in self._folder_id_cache:
                return self._folder_id_cache['monitoring']

        class _request:
            builder = self.client.me.mail_folders

            async def get(self) -> list[MailFolder]:
                response = await self.builder.get(
                    self.builder.MailFoldersRequestBuilderGetRequestConfiguration(
                        query_parameters=self.builder.MailFoldersRequestBuilderGetQueryParameters(
                            select=['id', 'displayName', 'childFolders', 'childFolderCount'],
                            top=50,
                        )
                    )
                )
                return getattr(response, 'value', [])

        request = _request()

        try:
            resolved_id = await resolve_mail_folders(
                service=self.client,
                segments=self.path_segments,
                folders=await request.get(),
            )

        except ValueError as e:
            raise FileNotFoundError from e

        with self._lock:
            self._folder_id_cache['monitoring'] = resolved_id
            return resolved_id

    async def fetch_unprocessed_emails(
        self,
        processed_uids: set[str],
        num_days: int | None = None,
    ) -> list[EmailRecord]:
        """Fetch emails from monitoring folder, excluding any that were already processed.

        Raises:
            ValueError:
                If the email's html body is empty.

        """
        mfid = await self._resolve_monitoring_folder_id()
        cutoff = self.cutoff.isoformat()

        class _request:
            builder = self.client.me.mail_folders.by_mail_folder_id(mfid).messages
            odata_next_link: str | None = None

            async def get(self) -> list[Message]:
                response = await _request.builder.get(
                    _request.builder.MessagesRequestBuilderGetRequestConfiguration(
                        query_parameters=_request.builder.MessagesRequestBuilderGetQueryParameters(
                            filter=f'receivedDateTime ge {cutoff}Z',
                            top=50,
                            select=['id', 'from', 'subject', 'receivedDateTime', 'bodyPreview', 'body'],
                            count=True,
                        )
                    )
                )
                self.odata_next_link = response and response.odata_next_link
                return getattr(response, 'value', [])

            async def __next__(self) -> bool:
                if onl := self.odata_next_link:
                    self.builder = self.builder.with_url(onl)
                    return True

                return False

        request = _request()

        records: list[EmailRecord] = []

        while True:
            for m in await request.get():
                if not m.id or m.id in processed_uids:
                    continue

                if content := m.body and m.body.content:
                    records.append(
                        make_email_record(
                            uid=m.id,
                            sender=m.sender and m.sender.email_address and m.sender.email_address.address,
                            subject=m.subject,
                            body=content,
                            received_at=m.received_date_time,
                        )
                    )

                else:
                    message = f'Email {m.id} has no HTML body'
                    raise ValueError(message)

            if not await next(request):
                break

        return records

    async def apply_flag(self, email_uid: str, flag: StatusFlag) -> None:
        """Apply MAPI flag to email (thread-safe)."""
        from .types import Message, SingleValueLegacyExtendedProperty

        body = Message(single_value_extended_properties=[SingleValueLegacyExtendedProperty(**flag)])
        await self.client.me.messages.by_message_id(email_uid).patch(body)


make_graph_client = make_factory(GraphClient)
