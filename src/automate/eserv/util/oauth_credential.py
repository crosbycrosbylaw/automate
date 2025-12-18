from __future__ import annotations

from dataclasses import dataclass, field, fields
from datetime import UTC, datetime, timedelta
from functools import cached_property
from typing import TYPE_CHECKING, Any, NewType, Self, TypeGuard, overload

from azure.core.credentials import AccessToken
from rampy import make_factory

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from rampy.structs.jseq import serializable

    from automate.eserv.types import *


ISODateString = NewType('ISODateString', str)


def is_isodatestring(x: object) -> TypeGuard[ISODateString]:
    if not isinstance(x, str):
        return False
    try:
        _ = datetime.fromisoformat(x)
    except ValueError, TypeError:
        return False
    else:
        return True


def _update_expiration(cred: OAuthCredential[Any]) -> datetime:
    props = cred.properties

    def _update(value: datetime | None = None) -> datetime:
        if value is None:
            value = datetime.now(UTC) - timedelta(days=1)
        props.setdefault('expires_at', value.isoformat())
        return value

    if 'expires_in' in props:
        issued_at = props.pop('issued_at', datetime.now(UTC).isoformat())
        seconds = props.pop('expires_in', 3600)
        if is_isodatestring(issued_at) and isinstance(seconds, int | float):
            return _update(datetime.fromisoformat(issued_at) + timedelta(seconds=seconds))

    if 'expires_at' in props:
        if is_isodatestring(raw := props.pop('expires_at')):
            return _update(datetime.fromisoformat(raw))
        if isinstance(raw, datetime):
            return _update(raw)

    return _update()


@dataclass
class BaseCredential:
    type: CredentialType
    client_id: str
    client_secret: str
    token_type: str
    scope: str
    access_token: str
    refresh_token: str

    factory: Callable[[Self], Any] = field(repr=False, metadata={'internal': True})
    account: str | None = field(default=None)


@dataclass
class OAuthCredential[T: TokenManager = TokenManager[Any]](BaseCredential):
    """OAuth credential with token and expiry.

    The string representation of an `OAuthCredential` evaluates to it's access token.
    """

    properties: dict[str, serializable] = field(
        default_factory=dict,
        metadata={'internal': True},
    )

    @cached_property
    def manager(self) -> T:
        return self.factory(self)

    @property
    def expired(self) -> bool:
        return not self.__bool__()

    @property
    def expiration(self) -> datetime:
        if current := self.get('expires_at'):
            if is_isodatestring(current):
                return datetime.fromisoformat(current)
            if isinstance(current, datetime):
                return current
        return _update_expiration(self)

    def __str__(self) -> str:
        """Return the access token as string representation."""
        return self.access_token

    def __int__(self) -> int:
        """Return the expiration datetime as a UNIX timestamp."""
        return int(self.expiration.timestamp())

    def __bool__(self) -> bool:
        """Return True if the credential has not yet expired."""
        return datetime.now(UTC) <= (self.expiration - timedelta(minutes=5))

    def __getitem__(self, name: str) -> Any:
        return self.properties[name]

    def __setitem__(self, name: str, value: Any) -> None:
        self.properties[name] = value

    def __contains__(self, name: str) -> bool:
        return self.properties.__contains__(name)

    def get(self, name: str, default: serializable = None) -> serializable:
        return self.properties.get(name, default)

    def print(
        self,
        *,
        insecure: bool = False,
        select: Sequence[str] = (),
    ) -> None:
        from setup_console import console

        console.info(
            f'{(self.type.capitalize if len(self.type) > 5 else self.type.upper)()} credential',
            **{
                key: str(value)
                for key, value in self.export().items()
                if any([
                    select and key in select,
                    insecure or not any(x in key for x in ('token', 'secret')),
                ])
            },
        )

    def export(self) -> CredentialsJSON | dict[str, Any]:
        """Convert credential to JSON serializable dictionary (flat format).

        Returns:
            Flat dictionary with all credential fields.

        """
        data: dict[str, Any] = {}

        for f in fields(self):
            if 'internal' not in f.metadata:
                data[f.name] = getattr(self, f.name)

        return {**data, **self.properties}

    def reconstruct(self, token_data: dict[str, Any]) -> Self:
        """Create new credential with updated token information.

        Args:
            token_data: OAuth2 token response (access_token, expires_in, etc.)

        Returns:
            New OAuthCredential instance with updated values.

        """
        from dataclasses import replace

        changes: dict[str, Any] = {
            'access_token': token_data.setdefault('access_token', str(self)),
            'refresh_token': token_data.setdefault('refresh_token', self.refresh_token),
            'token_type': token_data.setdefault('token_type', self.token_type),
        }

        if scopes := token_data.get('scopes', token_data.get('scope')):
            if isinstance(scopes, list):
                changes['scope'] = ' '.join(scopes)
            elif isinstance(scopes, str):
                changes['scope'] = scopes

        if expires_at := token_data.pop('expires_at', None):
            changes['properties'] = {**self.properties, 'expires_at': expires_at}

        elif expires_in := token_data.pop('expires_in', None):
            issued_at = token_data.get('issued_at', datetime.now(UTC).isoformat())
            changes['properties'] = {**self.properties, 'expires_in': expires_in, 'issued_at': issued_at}

        return replace(self, **changes)

    def refresh(self) -> Self:
        """Create new credential with refreshed token.

        Returns:
            New OAuthCredential instance with updated token information.

        """
        data = self.manager._refresh_token()
        return self.reconstruct(data)

    @overload
    def get_token(self, *args: ..., **kwds: ...) -> AccessToken: ...
    @overload
    def get_token(self) -> AccessToken: ...
    def get_token(self) -> AccessToken:
        return AccessToken(str(self), int(self))


make_oauth_credential = make_factory(OAuthCredential)
