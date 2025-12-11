from __future__ import annotations

from dataclasses import InitVar, dataclass, field, fields
from datetime import UTC, datetime, timedelta
from operator import methodcaller
from typing import TYPE_CHECKING, Any, Self

from rampy import create_field_factory

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from automate.eserv.types import *


@dataclass(slots=True)
class OAuthCredential[T: TokenManager = TokenManager[Any]]:
    """OAuth credential with token and expiry.

    The string representation of an `OAuthCredential` evaluates to it's access token.
    """

    factory: InitVar[Callable[[Self], T]] = field(repr=False, metadata={'internal': True})
    manager: T = field(init=False, metadata={'internal': True})

    type: CredentialType
    client_id: str
    client_secret: str
    token_type: str
    scope: str
    access_token: str
    refresh_token: str
    account: str | None = None
    properties: dict[str, Any] = field(default_factory=dict, metadata={'internal': True})

    expires_at: str | datetime | None = field(
        default=None,
        metadata={'dynamic': methodcaller('_resolve_expiration')},
    )

    def _resolve_expiration(self) -> datetime:
        if self.expires_at:
            if isinstance(self.expires_at, datetime):
                return self.expires_at

            return datetime.fromisoformat(self.expires_at)

        if expires_in := self.get('expires_in', 0):
            issued_at = self.get('issued_at', datetime.now(UTC).isoformat())
            return datetime.fromisoformat(issued_at) + timedelta(seconds=expires_in)

        return datetime.now(UTC) - timedelta(days=1)  # force refresh

    @property
    def outdated(self) -> bool:
        return datetime.now(UTC) > (self._resolve_expiration() - timedelta(minutes=5))

    def __post_init__(self, factory: Callable[[Self], T]) -> None:
        self.manager = factory(self)

    def __getitem__(self, name: str) -> Any:
        return self.properties[name]

    def __setitem__(self, name: str, value: Any) -> None:
        self.properties[name] = value

    def __contains__(self, name: str) -> bool:
        return self.properties.__contains__(name)

    def get[D = object](self, name: str, default: D | None = None) -> D:
        return self.properties.get(name, default)

    def __str__(self) -> str:
        """Return the access token as string representation."""
        return self.access_token

    def print(
        self,
        *,
        insecure: bool = False,
        select: Sequence[str] = (),
    ) -> None:
        from setup_console import console

        console.info(
            f'{self.type} credential',
            **{
                key: value
                for key, value in self.export().items()
                if any([
                    select and key in select,
                    insecure is True,
                    any(x in key for x in ('token', 'secret')),
                ])
            },
        )

    def export(self) -> dict[str, Any]:
        """Convert credential to JSON serializable dictionary (flat format).

        Returns:
            Flat dictionary with all credential fields.

        """
        data: dict[str, Any] = {}

        for f in fields(self):
            if not f.metadata:
                data[f.name] = getattr(self, f.name)
            elif 'internal' in f.metadata:
                continue
            elif isinstance(caller := f.metadata.get('dynamic'), methodcaller):
                data[f.name] = caller(self)

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

        if expires_at := token_data.get('expires_at'):
            changes['expires_at'] = expires_at
        elif expires_in := token_data.get('expires_in'):
            changes['expires_in'] = expires_in
            changes['issued_at'] = token_data.get('issued_at', datetime.now(UTC).isoformat())

        return replace(self, **changes)

    def refresh(self) -> Self:
        """Create new credential with refreshed token.

        Returns:
            New OAuthCredential instance with updated token information.

        """
        data = self.manager._refresh_token()
        return self.reconstruct(data)


credential_factory = create_field_factory(OAuthCredential)
