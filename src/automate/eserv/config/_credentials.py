from __future__ import annotations

__all__ = ['CredentialsConfig']

import threading
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, overload

import orjson

if TYPE_CHECKING:
    from pathlib import Path
    from threading import Lock

    from automate.eserv.types import *


def parse_credential_json(
    data: CredentialsJSON | dict[str, Any],
) -> tuple[CredentialType, OAuthCredential[Any]]:
    """Parse fields from token data."""
    keywords: dict[str, Any] = {}

    keywords.update((f.name, value) for f in fields(OAuthCredential) if (value := data.get(f.name)))
    keywords['properties'] = {key: val for key, val in data.items() if key not in keywords}

    match key := data['type']:
        case 'dropbox':
            from automate.eserv._module import make_dbx_cred

            cred = make_dbx_cred(**keywords)

        case 'msal':
            from automate.eserv._module import make_ms_cred

            cred = make_ms_cred(**keywords)

        case _:
            cred = OAuthCredential(**keywords)

    return key, cred


@dataclass(slots=True, frozen=True)
class CredentialsConfig:
    """Manages OAuth credentials for Dropbox and Outlook."""

    path: Path = field(metadata={'updated_at': None})

    _mapping: dict[CredentialType, OAuthCredential[Any]] = field(init=False, default_factory=dict)
    _lock: Lock = field(init=False, repr=False, default_factory=threading.Lock)

    def __post_init__(self) -> None:
        """Initialize the credential manager."""
        with self.path.open('rb') as f:
            data = orjson.loads(f.read())

        for json in data:
            self._mapping.update([parse_credential_json(json)])

    def __setitem__(self, name: CredentialType, value: OAuthCredential[Any]) -> None:
        self._mapping[name] = value

    if TYPE_CHECKING:

        @overload
        def get(
            self,
            name: Literal['msal'],
        ) -> OAuthCredential[MSALManager]: ...
        @overload
        def get(
            self,
            name: Literal['dropbox'],
        ) -> OAuthCredential[DropboxManager]: ...

    def get(self, name: CredentialType) -> OAuthCredential[Any]:
        """Retrieve the named authorization credential, storing the value if not found in cache."""
        with self._lock:
            cred = self._mapping[name]
            return cred if not cred.outdated else self._refresh(cred)

    if TYPE_CHECKING:
        __getitem__ = get
    else:

        def __getitem__(self, name: ...) -> ...:
            """Retrieve the named OAuth2 credential directly from the cache."""
            return self._mapping[name]

    __getattr__ = get

    @staticmethod
    def is_expired(cred: OAuthCredential) -> bool:
        """Check if credential needs refresh."""
        return cred.outdated

    def _refresh(self, cred: OAuthCredential) -> OAuthCredential:
        """Refresh an OAuth2 token.

        Raises:
            ValueError:
                If the type of the credential does not match any of those configured.

        """
        refreshed = cred.refresh()

        if cred.type == 'msal':
            refreshed.properties.setdefault('msal_migrated', True)

        self._mapping[cred.type] = refreshed
        self.persist()

        return refreshed

    def persist(self, mapping: dict[CredentialType, OAuthCredential[Any]] | None = None) -> None:
        """Write updated credentials back to disk."""
        self._mapping.update(mapping or ())

        data: list[dict[str, Any]] = [cred.export() for cred in self._mapping.values()]

        with self.path.open('wb') as f:
            f.write(orjson.dumps(data, option=orjson.OPT_INDENT_2))

        self.__dataclass_fields__['json_path'].metadata['updated_at'] = datetime.now(UTC)
