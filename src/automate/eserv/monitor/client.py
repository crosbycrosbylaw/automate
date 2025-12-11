from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from kiota_abstractions.base_request_configuration import RequestConfiguration
from msgraph.generated.models.message import Message
from msgraph.generated.models.single_value_legacy_extended_property import (
    SingleValueLegacyExtendedProperty,
)
from msgraph.graph_service_client import GraphServiceClient
from rampy import create_field_factory

from automate.eserv.util.email_record import make_email_record

if TYPE_CHECKING:
    from msgraph.generated.models.mail_folder import MailFolder

    from automate.eserv.types import Config, EmailRecord, StatusFlag

    from .client import GraphClient


class GraphClient:
    """Microsoft Graph API client for email monitoring."""

    def __init__(self, config: Config) -> None:
        """Initialize a Microsoft Graph client."""
        self.config = config

        self.cred = config.creds.msal
        self.token = self.cred.manager.get_token()

        self._folder_id_cache: dict[str, str] = {}
        self._lock = threading.Lock()

    @property
    def service(self) -> GraphServiceClient:
        if not hasattr(self, '_service'):
            self._service = GraphServiceClient(self.cred.manager)
        return self._service

    async def resolve_monitoring_folder_id(self) -> str:
        """Resolve monitoring folder path to folder ID.

        Raises:
            FileNotFoundError: If a folder in the path does not exist.

        """
        from .utils import verify_folder

        with self._lock:
            if 'monitoring' in self._folder_id_cache:
                return self._folder_id_cache['monitoring']

        segments = [part.strip() for part in self.config.monitor_mail_folder_path]
        inbox_name = segments.pop(0)

        print(segments)

        current_id: str = ''
        current_folder: MailFolder | None = None

        async def get_child_folders(folder_id: str, **kwds: Any):
            builder = self.service.me.mail_folders.by_mail_folder_id(folder_id)
            qs = builder.child_folders.ChildFoldersRequestBuilderGetQueryParameters(**kwds)

            return await builder.child_folders.get(RequestConfiguration(query_parameters=qs))

        response = await self.service.me.mail_folders.get()

        for f in (response and response.value) or []:
            if f.display_name == inbox_name:
                current_id, current_folder = verify_folder(f)
                break

        try:
            for s in segments:
                collection_response = await get_child_folders(
                    folder_id=current_id,
                    filter=f"startswith(displayName, '{s}')",
                )

                if collection_response and collection_response.value:
                    current_id, current_folder = verify_folder(next(iter(collection_response.value)))
                else:
                    raise ValueError(current_id)

        except Exception as e:
            from setup_console import console

            console.exception(current_id)

            raise FileNotFoundError(current_id) from e

        target_id, _ = verify_folder(current_folder)

        with self._lock:
            self._folder_id_cache['monitoring'] = target_id

        return target_id

    async def fetch_unprocessed_emails(
        self,
        num_days: int,
        processed_uids: set[str],
    ) -> list[EmailRecord]:
        """Fetch emails from monitoring folder, excluding any that were already processed.

        Raises:
            ValueError:
                If the email's html body is empty.

        """
        folder_id = await self.resolve_monitoring_folder_id()
        base_builder = self.service.me.mail_folders.by_mail_folder_id(folder_id).messages

        start_date = (datetime.now(UTC) - timedelta(days=num_days)).isoformat()

        records: list[EmailRecord] = []
        next_link: str | None = None

        while True:
            if next_link:
                response = await base_builder.with_url(next_link).get()
            else:
                response = await base_builder.get(
                    request_configuration=RequestConfiguration(
                        query_parameters=base_builder.MessagesRequestBuilderGetQueryParameters(
                            count=True,
                            filter=f'receivedDateTime ge {start_date}Z',
                            select=['id', 'from', 'subject', 'receivedDateTime', 'bodyPreview'],
                            top=50,
                        )
                    )
                )

            for item in (response and response.value) or []:
                if not item.id or item.id in processed_uids:
                    continue

                body_builder = self.service.me.messages.by_message_id(item.id)
                body_result = await body_builder.get(
                    request_configuration=RequestConfiguration(
                        query_parameters=body_builder.MessageItemRequestBuilderGetQueryParameters(
                            select=['body'],
                        )
                    )
                )

                content = body_result and body_result.body and body_result.body.content
                sender = item.from_ and item.from_.email_address and item.from_.email_address.address

                if content is not None:
                    records.append(
                        make_email_record(
                            uid=item.id,
                            sender=sender or '',
                            subject=item.subject or '',
                            received_at=item.received_date_time,
                            body=content,
                        ),
                    )

                else:
                    message = f'Email {item.id} has no HTML body'
                    raise ValueError(message)

                if next_link := response and response.odata_next_link:
                    pass
                else:
                    return records

    async def apply_flag(self, email_uid: str, flag: StatusFlag) -> None:
        """Apply MAPI flag to email (thread-safe)."""
        with self._lock:
            await self.service.me.messages.by_message_id(email_uid).patch(
                Message(
                    single_value_extended_properties=[
                        SingleValueLegacyExtendedProperty(**flag),
                    ]
                )
            )


make_graph_client = create_field_factory(GraphClient)
