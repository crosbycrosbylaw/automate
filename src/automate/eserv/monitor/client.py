from __future__ import annotations

import threading
import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import requests
from msgraph.graph_service_client import GraphServiceClient
from rampy import create_field_factory
from requests.exceptions import HTTPError

from automate.eserv.record import record_factory

if TYPE_CHECKING:
    from automate.eserv.types import (
        EmailRecord,
        MicrosoftAuthManager,
        MonitoringConfig,
        OAuthCredential,
        StatusFlag,
    )

_STATUS_CODES: Final[dict[str, int]] = {'rate-limit': 429, 'server-error': 500}


class GraphClient:
    """Microsoft Graph API client for email monitoring."""

    def __init__(
        self, credential: OAuthCredential[MicrosoftAuthManager], config: MonitoringConfig
    ) -> None:
        """Initialize a Microsoft Graph client."""
        self.config = config

        self.cred = credential
        self.token = self.cred.manager.acquire_token()

        self._folder_id_cache: dict[str, str] = {}
        self._lock = threading.Lock()

    def _get_headers(self) -> dict[str, str]:
        """Get authorization headers with current access token."""
        return {
            'Authorization': f'{self.cred.token_type} {self.cred.access_token}',
            'Content-Type': 'application/json',
        }

    @property
    def service(self) -> GraphServiceClient:
        if not hasattr(self, '_service'):
            self._service = GraphServiceClient(self.cred.manager)
        return self._service

    @staticmethod
    def _is_retryable_error(status_code: int) -> bool:
        """Check if HTTP error is retryable.

        Args:
            status_code: HTTP status code.

        Returns:
            True if error should be retried (429, 5xx), False for fatal errors (4xx).

        """
        return any([
            status_code == _STATUS_CODES['rate-limit'],
            status_code >= _STATUS_CODES['server-error'],
        ])

    def _request(self, method: str, path: str, **kwds: Any) -> dict[str, Any]:
        """Make Graph API request with retry logic for transient failures.

        Args:
            method: HTTP method (GET, POST, PATCH, etc.).
            path: API path (e.g., '/me/messages').
            **kwds: Additional arguments passed to requests.request().

        Returns:
            JSON response as dictionary.

        Raises:
            HTTPError: For fatal errors (4xx) or after max retries exhausted.

        """
        url = f'{self.config.graph_api_base_url}{path}'
        headers = self._get_headers()

        max_retries = 3
        base_delay = 1.0  # seconds

        for attempt in range(max_retries):
            try:
                response = requests.request(method, url, headers=headers, timeout=30, **kwds)
                response.raise_for_status()
                return response.json() if response.text else {}

            except HTTPError as e:
                status_code = e.response.status_code if e.response else 0

                # Check if error is retryable
                if not self._is_retryable_error(status_code):
                    # Fatal error (4xx) - don't retry
                    raise

                # Last attempt - don't retry
                if attempt == max_retries - 1:
                    raise

                # Calculate exponential backoff delay
                delay = base_delay * (2**attempt)
                time.sleep(delay)

                # Continue to next retry

        # Should never reach here, but satisfy type checker
        return {}

    def resolve_monitoring_folder_id(self) -> str:
        """Resolve monitoring folder path to folder ID.

        Raises:
            FileNotFoundError: If a folder in the path does not exist.

        """
        with self._lock:
            if 'monitoring' in self._folder_id_cache:
                return self._folder_id_cache['monitoring']

        # Split path and walk hierarchy
        path_parts = self.config.folder_path.split('/')
        current_id = 'root'

        # target = path_parts[-1]

        # response = await self.service.me.mail_folders.get()

        # if folders := response and response.value:
        #     for f in folders:
        #         if f.id and f.display_name == target:
        #             with self._lock:
        #                 self._folder_id_cache['monitoring'] = f.id
        #             return f.id

        for part in path_parts:
            # GET /me/mailFolders/{parentId}/childFolders to find child with matching name
            result = self._request(
                'GET',
                path=f'/me/mailFolders/{current_id}/childFolders',
                params={'$filter': f"displayName eq '{part}'"},
            )

            folders = result.get('value', [])

            if not folders:
                raise FileNotFoundError(part)

            current_id = folders[0]['id']

        with self._lock:
            self._folder_id_cache['monitoring'] = current_id

        return current_id

    def fetch_unprocessed_emails(
        self,
        num_days: int,
        processed_uids: set[str],
    ) -> list[EmailRecord]:
        """Fetch emails from monitoring folder, excluding any that were already processed.

        Raises:
            ValueError:
                If the email's html body is empty.

        """
        folder_id = self.resolve_monitoring_folder_id()

        # Calculate date range
        start_date = (datetime.now(UTC) - timedelta(days=num_days)).isoformat()

        # Graph API filter: receivedDateTime >= start_date AND has attachments
        filter_expr = f'receivedDateTime ge {start_date}Z and hasAttachments eq true'

        records: list[EmailRecord] = []
        next_link: str | None = None

        # Pagination loop to fetch all matching emails
        while True:
            if next_link:
                # Use next link for subsequent pages
                # Graph API returns full URL in @odata.nextLink
                response = requests.get(next_link, headers=self._get_headers(), timeout=30)
                response.raise_for_status()
                result = response.json() if response.text else {}
            else:
                # Initial request with filter
                result = self._request(
                    'GET',
                    path=f'/me/mailFolders/{folder_id}/messages',
                    params={
                        '$filter': filter_expr,
                        '$select': 'id,from,subject,receivedDateTime,bodyPreview',
                        '$top': 50,
                    },
                )

            # Process messages from current page
            for msg in result.get('value', []):
                uid = msg['id']

                # Skip if already processed
                if uid in processed_uids:
                    continue

                # Fetch full body (HTML)
                body_result = self._request(
                    'GET',
                    path=f'/me/messages/{uid}',
                    params={'$select': 'id,bodyPreview,body'},
                )

                html_body = body_result.get('body', {}).get('content', '')

                # Validate HTML body is not empty
                if not html_body:
                    message = f'Email {uid} has no HTML body'
                    raise ValueError(message)

                records.append(
                    record_factory(
                        uid=uid,
                        sender=msg.get('from', {}).get('emailAddress', {}).get('address', ''),
                        subject=msg.get('subject', ''),
                        received_at=datetime.fromisoformat(msg.get('receivedDateTime', '')),
                        body=html_body,
                    ),
                )

            # Check for next page
            next_link = result.get('@odata.nextLink')
            if not next_link:
                break

        return records

    def apply_flag(self, email_uid: str, flag: StatusFlag) -> None:
        """Apply MAPI flag to email (thread-safe)."""
        with self._lock:
            property_patch = {'singleValueExtendedProperties': [flag]}

            self._request('PATCH', path=f'/me/messages/{email_uid}', json=property_patch)


graph_client_factory = create_field_factory(GraphClient)
