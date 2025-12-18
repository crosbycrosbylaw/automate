from __future__ import annotations

import threading
from dataclasses import dataclass, field, fields
from typing import TYPE_CHECKING, Any, ClassVar, Literal, Self, cast, no_type_check, overload

import orjson

from automate.eserv.util.oauth_credential import OAuthCredential

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path
    from threading import Lock

    from automate.eserv.types import *


def _nest_properties(data: CredentialsJSON | dict[str, Any]) -> dict[str, Any]:
    field_names = {f.name for f in fields(OAuthCredential) if 'internal' not in f.metadata}
    kwds: dict[str, Any] = dict.fromkeys(field_names, '')
    properties: dict[str, Any] = {}

    for key, value in data.items():
        if key in field_names:
            kwds[key] = value
        else:
            properties[key] = value

    kwds['properties'] = properties
    return kwds


def parse_credential_json(
    json: CredentialsJSON | dict[str, Any],
) -> OAuthCredential[Any]:
    """Parse fields from token data."""
    from automate.eserv import new_dropbox_credential, new_msal_credential

    data = _nest_properties(json)
    match json['type']:
        case 'dropbox':
            return new_dropbox_credential(**data)
        case 'msal':
            return new_msal_credential(**data)
        case _:
            return OAuthCredential(**data)


@no_type_check
def _credential_map_factory() -> CredentialMap:
    return {}


@dataclass(slots=True, frozen=True)
class CredentialsConfig:
    """Manages OAuth credentials for Dropbox and Outlook."""

    _instance: ClassVar[Self]

    path: Path = field(doc='path to the credentials JSON file')

    @property
    def msal(self) -> MSALCredential:
        """Retrieve an MSAL credential, refreshing and caching the value as needed."""
        with self._lock:
            cred: MSALCredential = self._mapping['msal']
            return cred if not cred.expired else self._refresh(cred)

    @property
    def dropbox(self) -> DropboxCredential:
        """Retrieve a Dropbox credential, refreshing and caching the value as needed."""
        with self._lock:
            cred: DropboxCredential = self._mapping['dropbox']
            return cred if not cred.expired else self._refresh(cred)

    _lock: Lock = field(init=False, repr=False, default_factory=threading.Lock)
    _mapping: CredentialMap = field(init=False, repr=False, default_factory=_credential_map_factory)

    def __new__(cls, path: Path) -> Self:
        if not hasattr(cls, '_instance'):
            resolved_path = path.resolve(strict=True)
            this = super().__new__(cls)
            object.__setattr__(this, 'path', resolved_path)
            object.__setattr__(this, '_lock', threading.Lock())
            object.__setattr__(this, '_mapping', {})
            this.__init__(resolved_path)

            cls._instance = this

        return cls._instance

    def __post_init__(self) -> None:
        with self.path.open('rb') as f:
            data = orjson.loads(f.read())

        for json in data:
            cred = parse_credential_json(json)
            self._mapping[cred.type] = cred

    def __setitem__(self, name: CredentialType, value: OAuthCredential[Any]) -> None:
        """Update or add a cached OAuth2 credential."""
        with self._lock:
            self._mapping[name] = value

    @overload
    def __getitem__(self, name: Literal['msal']) -> MSALCredential: ...
    @overload
    def __getitem__(self, name: Literal['dropbox']) -> DropboxCredential: ...
    def __getitem__(self, name: ...) -> ...:
        """Retrieve the named OAuth2 credential directly from the cache."""
        with self._lock:
            return self._mapping[name]

    def _refresh[T: OAuthCredential[Any]](self, cred: T) -> T:
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

    @no_type_check
    def persist(self, **mapping: OAuthCredential[Any]) -> None:
        """Write updated credentials back to disk."""
        with self._lock:
            self._mapping.update(mapping or {})

        data = [cred.export() for cred in cast('Iterable[OAuthCredential]', self._mapping.values())]
        with self.path.open('wb') as f:
            f.write(orjson.dumps(data, option=orjson.OPT_INDENT_2))


def get_credentials() -> CredentialsConfig:
    from ._paths import get_paths

    return CredentialsConfig(path=get_paths().credentials)
