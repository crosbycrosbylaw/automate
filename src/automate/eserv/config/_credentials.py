from __future__ import annotations

__all__ = ['CredentialsConfig']

import threading
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, ClassVar, Literal, Self, overload

import orjson

from automate.eserv.util.oauth_credential import OAuthCredential

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
            from automate.eserv import new_dropbox_credential

            cred = new_dropbox_credential(**keywords)

        case 'msal':
            from automate.eserv import new_msal_credential

            cred = new_msal_credential(**keywords)

        case _:
            cred = OAuthCredential(**keywords)

    return key, cred


@dataclass(slots=True, frozen=True)
class CredentialsConfig:
    """Manages OAuth credentials for Dropbox and Outlook."""

    _instance: ClassVar[Self | None] = None

    path: Path = field(metadata={'updated_at': None})

    _mapping: dict[CredentialType, OAuthCredential[Any]] = field(init=False, default_factory=dict)
    _lock: Lock = field(init=False, repr=False, default_factory=threading.Lock)

    def __new__(cls, path: Path) -> Self:
        if not cls._instance:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __post_init__(self) -> None:
        """Initialize the credential manager."""
        with self.path.open('rb') as f:
            data = orjson.loads(f.read())

        for json in data:
            self._mapping.update([parse_credential_json(json)])

    def __setitem__(self, name: CredentialType, value: OAuthCredential[Any]) -> None:
        """Update or add a cached OAuth2 credential."""
        with self._lock:
            self._mapping[name] = value

    if TYPE_CHECKING:

        @overload
        def __getitem__(
            self,
            name: Literal['msal'],
        ) -> OAuthCredential[MSALManager]: ...
        @overload
        def __getitem__(
            self,
            name: Literal['dropbox'],
        ) -> OAuthCredential[DropboxManager]: ...

    def __getitem__(self, name: CredentialType) -> OAuthCredential[Any]:
        """Retrieve the named OAuth2 credential directly from the cache."""
        with self._lock:
            return self._mapping[name]

    if TYPE_CHECKING:

        @overload
        def __getattr__(
            self,
            name: Literal['msal'],
        ) -> OAuthCredential[MSALManager]: ...
        @overload
        def __getattr__(
            self,
            name: Literal['dropbox'],
        ) -> OAuthCredential[DropboxManager]: ...

    def __getattr__(self, name: CredentialType) -> OAuthCredential[Any]:
        """Retrieve the named authorization credential, storing the value if not found in cache.

        This method automatically refreshes expired credentials.
        """
        # Handle special attributes that should not trigger credential lookup
        if name.startswith('_'):
            raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")

        with self._lock:
            cred = self._mapping[name]
            return cred if not cred.outdated else self._refresh(cred)

    def _refresh(self, cred: OAuthCredential[Any]) -> OAuthCredential:
        """Refresh an OAuth2 token.

        Raises:
            ValueError:
                If the type of the credential does not match any of those configured.

        """
        refreshed = cred.refresh()

        with self._lock:
            self._mapping[cred.type] = refreshed
            self.persist()

        return refreshed

    def persist(self, mapping: dict[CredentialType, OAuthCredential[Any]] | None = None) -> None:
        """Write updated credentials back to disk."""
        with self._lock:
            self._mapping.update(mapping or {})

        data = [cred.export() for cred in self._mapping.values()]

        with self.path.open('wb') as f:
            f.write(orjson.dumps(data, option=orjson.OPT_INDENT_2))

        self.__dataclass_fields__['path'].metadata['updated_at'] = datetime.now(UTC)


def get_credentials() -> CredentialsConfig:
    from ._paths import get_paths

    return CredentialsConfig(get_paths().credentials)
