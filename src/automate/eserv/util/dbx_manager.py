# pyright: reportUnknownMemberType=false
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

from dropbox import Dropbox
from dropbox.files import FolderMetadata, WriteMode
from rampy import create_field_factory

from automate.eserv.types.structs import TokenManager
from setup_console import console

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path
    from typing import Any

    from dropbox.files import Metadata


@dataclass(slots=True)
class DropboxManager(TokenManager[Dropbox]):
    """Dropbox client wrapper from an OAuth credential.

    Attributes:
        credential: OAuth credential containing access token.

    """

    uploaded: list[str] = field(init=False, default_factory=list[str])

    def index(self) -> dict[str, Any]:
        """Return the Dropbox folder index as a dictionary."""
        dropbox = self.client

        out: dict[str, Any] = {}

        console.info('Refreshing Dropbox index from API')

        if result := dropbox.files_list_folder('/Clio/', recursive=True):
            metadata_entries = cast('Iterable[Metadata]', result.entries)

            while True:
                for entry in metadata_entries:
                    if isinstance(entry, FolderMetadata):
                        out[entry.path_display] = {'name': entry.name, 'id': entry.id}

                if not result.has_more:
                    break

                cursor = cast('str', result.cursor)
                result = dropbox.files_list_folder_continue(cursor)
                metadata_entries = cast('Iterable[Metadata]', result.entries)

        return out

    def upload(self, path: Path, dropbox_path: str) -> None:
        with path.open('rb') as f:
            self.client.files_upload(f.read(), dropbox_path, mode=WriteMode.overwrite)

        console.info('Uploaded file to Dropbox', path=path.as_posix(), dropbox_path=dropbox_path)

        self.uploaded.append(dropbox_path)

    def _refresh_token(self) -> dict[str, Any]:
        self.client.check_and_refresh_access_token()
        return {
            'access_token': self.client._oauth2_access_token,
            'expires_at': self.client._oauth2_access_token_expiration,
            'refresh_token': self.client._oauth2_refresh_token,
            'scope': ' '.join(str(x) for x in self.client._scope or []),
        }

    @property
    def client(self) -> Dropbox:
        """Lazily create Dropbox client from credential.

        Returns:
            Dropbox client instance.

        """
        if self._client is None:
            from dropbox import Dropbox

            self._client = Dropbox(
                oauth2_access_token=self.credential.access_token,
                oauth2_refresh_token=self.credential.refresh_token,
                app_key=self.credential.client_id,
                app_secret=self.credential.client_secret,
            )

        return self._client


dropbox_manager_factory = create_field_factory(DropboxManager)
