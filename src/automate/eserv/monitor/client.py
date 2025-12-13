from __future__ import annotations

import threading
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime, timedelta
from functools import cached_property
from typing import TYPE_CHECKING

from kiota_abstractions.base_request_configuration import RequestConfiguration
from msgraph.graph_service_client import GraphServiceClient
from rampy import make_factory

from automate.eserv.monitor.utils import resolve_mail_folders
from automate.eserv.util.email_record import make_email_record

if TYPE_CHECKING:
    from automate.eserv.types import Config, EmailRecord, StatusFlag

    from .client import GraphClient
    from .types import BuilderProto, GetQueryParameter


class GraphClient:
    """Microsoft Graph API client for email monitoring."""

    @dataclass
    class request[T]:
        builder: BuilderProto[T]

        count: bool | None = field(default=None, doc='Include count of items')
        expand: list[str] | None = field(default=None, doc='Expand related entities')
        filter: str | None = field(default=None, doc='Filter items by property values')
        orderby: list[str] | None = field(default=None, doc='Order items by property values')
        search: str | None = field(default=None, doc='Search items by search phrases')
        select: list[str] | None = field(default=None, doc='Select properties to be returned')
        skip: int | None = field(default=None, doc='Skip the first n items')
        top: int | None = field(default=None, doc='Show only the first n items')

        odata_next_link: str | None = field(init=False)

        def _qs(self) -> GetQueryParameter:
            cls = getattr(
                self.builder, next(a for a in dir(self.builder) if a.endswith('GetQueryParameters'))
            )
            return cls(**{f.name: getattr(self, f.name) for f in fields(self) if f.doc is not None})

        async def get(self) -> list[T]:
            response = await self.builder.get(RequestConfiguration(query_parameters=self._qs()))
            self.odata_next_link = getattr(response, 'odata_next_link', None)
            value = getattr(response, 'value', [])
            return value if isinstance(value, list) else [value]

        async def collect(self) -> list[T]:
            out: list[T] = []
            while next(self):
                out[:] = [*out, *await self.get()]
            return out

        def __next__(self) -> bool:
            if not hasattr(self, 'odata_next_link'):
                return True

            if self.odata_next_link is not None:
                self.builder = self.builder.with_url(self.odata_next_link)
                return True

            return False

    def __init__(self, config: Config) -> None:
        """Initialize a Microsoft Graph client."""
        self._folder_id_cache: dict[str, str] = {}
        self._lock = threading.Lock()

        self.config = config
        self.cutoff = datetime.now(UTC) - timedelta(days=config.monitor_num_days)

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

        request = self.request(
            self.client.me.mail_folders,
            select=['id', 'displayName', 'childFolders', 'childFolderCount'],
            top=50,
        )

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
    ) -> list[EmailRecord]:
        """Fetch emails from monitoring folder, excluding any that were already processed.

        Raises:
            ValueError:
                If the email's html body is empty.

        """
        mfid = await self._resolve_monitoring_folder_id()
        cutoff = self.cutoff.isoformat()

        records: list[EmailRecord] = []

        request = self.request(
            self.client.me.mail_folders.by_mail_folder_id(mfid).messages,
            filter=f'receivedDateTime ge {cutoff}Z',
            top=50,
            select=['id', 'from', 'subject', 'receivedDateTime', 'bodyPreview', 'body'],
            count=True,
        )

        for m in await request.collect():
            if not m.id or m.id in processed_uids:
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

    async def apply_flag(self, email_uid: str, flag: StatusFlag) -> None:
        """Apply MAPI flag to email (thread-safe)."""
        from .types import Message, SingleValueLegacyExtendedProperty

        body = Message(single_value_extended_properties=[SingleValueLegacyExtendedProperty(**flag)])
        await self.client.me.messages.by_message_id(email_uid).patch(body)


make_graph_client = make_factory(GraphClient)
