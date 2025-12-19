from __future__ import annotations

import threading
from contextlib import contextmanager
from dataclasses import dataclass, field, fields
from typing import TYPE_CHECKING, Any, ClassVar, Literal, Self, TypeGuard, overload

import orjson

from automate.eserv.util.oauth_credential import OAuthCredential
from setup_console import mode, mode_console

if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path
    from threading import Lock

    from automate.eserv.types import *
    from setup_console import *


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


def _path_factory():
    from automate.eserv._module import get_paths

    return get_paths().credentials


@dataclass(frozen=True, slots=True)
class CredentialsConfig:
    """Manages OAuth credentials for Dropbox and Outlook."""

    _instance: ClassVar[Self]

    path: Path = field(doc='path to the credentials JSON file', default_factory=_path_factory)

    _verbose: ModeConsole = field(init=False, repr=False)

    @property
    def msal(self) -> MSALCredential:
        """Retrieve an MSAL credential, refreshing and caching the value as needed."""
        with self._map() as mapping:
            cred = mapping['msal']
            return cred if not cred.expired else self._refresh(cred)

    @property
    def dropbox(self) -> DropboxCredential:
        """Retrieve a Dropbox credential, refreshing and caching the value as needed."""
        with self._map() as mapping:
            cred = mapping['dropbox']
            return cred if not cred.expired else self._refresh(cred)

    _lock: Lock = field(init=False, repr=False)
    _mapping: CredentialMap = field(init=False, repr=False)

    def __new__(cls, path: Path) -> Self:
        self = getattr(cls, '_instance', cls._setup(path))

        if path != self.path:
            object.__setattr__(self, 'path', path)
            self._reload()

        return self

    @classmethod
    def _setup(cls, path: Path) -> Self:
        path = path.resolve(strict=True)

        self = super().__new__(cls)
        # Initialize mutable state BEFORE calling __init__ to prevent re-initialization
        object.__setattr__(self, '_lock', threading.Lock())
        object.__setattr__(self, '_mapping', {})
        object.__setattr__(self, '_verbose', mode_console(mode.VERBOSE)())
        self.__init__(path)

        cls._instance = self

        console = self._verbose.unwrap().bind(**dict.fromkeys(self._mapping, True))
        self._reload()

        console.info(event='Loaded credentials')
        return self

    def _reload(self) -> None:
        with self.path.open('rb') as f:
            data = orjson.loads(f.read())

        for json in data:
            self._verbose.info(event=f'Processing {json["type"]} credential', **json)
            cred = parse_credential_json(json)
            self._mapping[cred.type] = cred

    def __setitem__(self, name: CredentialType, value: OAuthCredential[Any]) -> None:
        """Update or add a cached OAuth2 credential."""
        with self._map() as mapping:
            mapping[name] = value

    @overload
    def __getitem__(self, name: Literal['msal']) -> MSALCredential: ...
    @overload
    def __getitem__(self, name: Literal['dropbox']) -> DropboxCredential: ...
    def __getitem__(self, name: ...) -> ...:
        """Retrieve the named OAuth2 credential directly from the cache."""
        with self._map() as mapping:
            return mapping[name]

    def _refresh[T: OAuthCredential[Any]](self, cred: T) -> T:
        """Refresh an OAuth2 token.

        Raises:
            ValueError:
                If the type of the credential does not match any of those configured.

        """
        new = cred.refresh()
        self.persist(**{new.type: new})
        return new

    def persist(
        self,
        **updates: OAuthCredential[Any],
    ) -> None:
        """Write updated credentials back to disk."""
        with self._map() as mapping:
            if self._guard(updates):
                mapping.update(updates)

            data = orjson.dumps([mapping[key].export() for key in mapping], option=orjson.OPT_INDENT_2)

        self.path.write_bytes(data)

    def _guard(self, mapping: ...) -> TypeGuard[PartialCredentialMap]:
        gen = (key in {'msal', 'dropbox'} and isinstance(mapping[key], OAuthCredential) for key in mapping)
        return all([isinstance(mapping, dict), *gen])

    @contextmanager
    def _map(self) -> Generator[CredentialMap]:
        try:
            yield self._mapping
        finally:
            pass


def get_credentials() -> CredentialsConfig:
    return CredentialsConfig()
