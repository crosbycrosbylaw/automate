from __future__ import annotations

import threading
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Literal, Self, overload

import orjson
from azure.core.credentials import AccessToken
from rampy.util import create_field_factory

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

    from automate.eserv.types import DropboxManager, MicrosoftAuthManager
    from automate.eserv.types.typechecking import CredentialsJSON, CredentialType

type RefreshHandler = Callable[[], dict[str, Any]]


def _parse_expiry(data: CredentialsJSON | dict[str, Any]) -> datetime | None:
    expires_key = next((k for k in data if k.startswith('expires')), '')
    expires_val = data.pop(expires_key, None)

    if not isinstance(expires_val, int | datetime) or (
        isinstance(expires_val, str) and not all(x in expires_val for x in ('-', 'T', ':', '.'))
    ):
        return None

    match expires_key:
        case 'expires_in':
            issued = data.pop('issued_at', '') or datetime.now(UTC).isoformat()
            if isinstance(expires_val, int | str):
                duration = timedelta(seconds=int(expires_val))
                return datetime.fromisoformat(issued) + duration
        case 'expires_at':
            if isinstance(expires_val, datetime):
                return expires_val
            if isinstance(expires_val, str):
                return datetime.fromisoformat(expires_val)
        case _:
            return None


def _parse_credential_json(data: CredentialsJSON | dict[str, Any]) -> OAuthCredential[Any]:
    """Parse fields from token data."""
    keywords: dict[str, Any] = {}

    match data['type']:
        case 'dropbox':
            from automate.eserv.util.dbx_manager import dropbox_manager_factory

            keywords['manager_factory'] = dropbox_manager_factory
        case 'microsoft-outlook':
            from automate.eserv.util.msal_manager import msauth_manager_factory

            keywords['manager_factory'] = msauth_manager_factory

    keywords.update((f.name, value) for f in fields(OAuthCredential) if (value := data.get(f.name)))
    keywords['expires_at'] = _parse_expiry(data)

    return OAuthCredential(
        **keywords,
        extra_properties={key: val for key, val in data.items() if key not in keywords},
    )


@dataclass(slots=True)
class OAuthCredential[T = Any]:
    """OAuth credential with token and expiry.

    The string representation of an `OAuthCredential` evaluates to it's access token.
    """

    manager_factory: Callable[[Self], T] = field(repr=False, metadata={'internal_only': True})

    type: CredentialType
    client_id: str
    client_secret: str
    token_type: str
    scope: str
    access_token: str
    refresh_token: str
    account: str | None = None
    expires_at: datetime | None = None
    extra_properties: dict[str, Any] = field(default_factory=dict, metadata={'internal_only': True})

    handler: RefreshHandler = field(
        init=False,
        repr=False,
        metadata={'internal_only': True},
    )
    manager: T = field(
        init=False,
        repr=False,
        metadata={'internal_only': True},
    )

    def __post_init__(self) -> None:
        from automate.eserv.types import TokenManager

        self.manager = self.manager_factory(self)

        if not isinstance(self.manager, TokenManager):
            raise TypeError(self.manager)

        self.handler = self.manager._refresh_token

    def __getitem__(self, name: str) -> Any:
        return self.extra_properties[name]

    def __setitem__(self, name: str, value: Any) -> None:
        self.extra_properties[name] = value

    def __contains__(self, name: str) -> bool:
        return self.extra_properties.__contains__(name)

    def get[D = None](self, name: str, default: D | None = None) -> D:
        return self.extra_properties.get(name, default)

    def __str__(self) -> str:
        """Return the access token as string representation."""
        return self.access_token

    def show(
        self,
        *,
        insecure: bool = False,
        properties: Sequence[str] = (),
    ) -> dict[str, Any]:
        from setup_console import console

        def selector(x: str) -> bool:
            if properties:
                return x in properties

            return insecure or not any(_ in x for _ in ('token', 'secret'))

        name = f'{"".join(x.capitalize() for x in self.type.split("-"))}Credential'
        data = {key: value for key, value in self.export().items() if selector(key)}

        console.info(name, **data)

        return data

    def export(self) -> dict[str, Any]:
        """Convert credential to JSON serializable dictionary (flat format).

        Returns:
            Flat dictionary with all credential fields.

        """
        data = {
            f.name: f'{getattr(self, f.name)!s}'
            for f in fields(self)
            if 'internal_only' not in f.metadata
        }

        if isinstance(exp := data['expires_at'], datetime):
            data.update(expires_at=exp.isoformat())

        return {**data, **self.extra_properties}

    def update_from_refresh(self, token_data: dict[str, Any]) -> Self:
        """Create new credential with updated token information.

        Args:
            token_data: OAuth2 token response (access_token, expires_in, etc.)

        Returns:
            New OAuthCredential instance with updated values.

        """
        from dataclasses import replace

        # Create new instance with updated fields
        return replace(
            self,
            access_token=token_data.get('access_token', self.access_token),
            refresh_token=token_data.get('refresh_token', self.refresh_token),
            scope=token_data.get('scope', self.scope),
            token_type=token_data.get('token_type', self.token_type),
            expires_at=_parse_expiry(token_data),
        )

    def refresh(self) -> OAuthCredential:
        """Create new credential with refreshed token.

        Returns:
            New OAuthCredential instance with updated token information.

        Raises:
            ValueError:
                If the `handler` property for this instance has not been set.

        """
        if self.handler is None:
            message = 'There is no configuration set for this credential.'
            raise ValueError(message)

        token_data = self.handler()
        return self.update_from_refresh(token_data)

    def object_hook(self, obj: dict[str, Any]) -> Self:
        """Return this credential with information updated from the given dictionary.

        DEPRECATED: Use update_from_refresh() instead. This method is kept for
        backward compatibility with JSON deserialization during Phase 5 migration.

        """
        expiration_key = next((key for key in obj if key.startswith('expires_')), None)
        expiration = obj.pop(expiration_key, 3600) if expiration_key else 3600

        if isinstance(expiration, datetime):
            self.expires_at = expiration
        elif isinstance(expiration, int | float):
            self.expires_at = datetime.now(UTC) + timedelta(seconds=expiration)

        for key, value in obj.items():
            if key in {'token_type', 'scope', 'access_token', 'refresh_token'} and value:
                setattr(self, key, value)

        return self

    @property
    def token(self) -> AccessToken:
        if not self.expires_at:
            expires_on = (datetime.now(UTC) + timedelta(seconds=3600)).timestamp()
        else:
            expires_on = self.expires_at.timestamp()

        return AccessToken(token=str(self), expires_on=int(expires_on))


class CredentialManager:
    """Manages OAuth credentials for Dropbox and Outlook."""

    def __init__(self, json_path: Path) -> None:
        """Initialize the credential manager.

        Args:
            json_path: Path to the JSON file containing OAuth credentials.

        """
        self.credentials_path = json_path
        self._credentials: dict[CredentialType, OAuthCredential] = {}
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        """Load credentials from JSON file (flat format).

        Supports flat format where all fields are at the top level.

        """
        with self.credentials_path.open('rb') as f:
            data = orjson.loads(f.read())

        for json in data:
            cred = _parse_credential_json(json)
            cred.manager.persist = lambda self: self.persist({self.type: self})
            self._credentials[cred.type] = cred

    def get_credential(self, cred_type: CredentialType):
        """Get credential by type, refreshing if expired."""
        with self._lock:
            cred = self._credentials[cred_type]

            if self._is_expired(cred):
                cred = self._refresh(cred)
                self._credentials[cred_type] = cred
                self.persist()

            return cred

    if TYPE_CHECKING:

        @overload
        def __getitem__(
            self, name: Literal['microsoft-outlook']
        ) -> OAuthCredential[MicrosoftAuthManager]: ...
        @overload
        def __getitem__(self, name: Literal['dropbox']) -> OAuthCredential[DropboxManager]: ...

    def __getitem__(self, name: CredentialType) -> ...:
        """Retrieve the named authorization credential, storing the value if not found in cache."""
        return self._credentials[name]

    @staticmethod
    def _is_expired(cred: OAuthCredential) -> bool:
        """Check if credential needs refresh."""
        if not cred.expires_at:
            return False
        # Refresh if within 5 minutes of expiry
        return datetime.now(UTC) > (cred.expires_at - timedelta(minutes=5))

    @staticmethod
    def _refresh(cred: OAuthCredential) -> OAuthCredential:
        """Refresh an OAuth2 token.

        Raises:
            ValueError:
                If the type of the credential does not match any of those configured.

        """
        refreshed = cred.refresh()

        # Mark MSAL credentials as migrated after first successful refresh
        if cred.type == 'microsoft-outlook' and not cred.extra_properties.get('msal_migrated'):
            # Update extra_properties dict directly (msal_migrated is not a field)
            refreshed.extra_properties['msal_migrated'] = True

        return refreshed

    def persist(self, mapping: dict[CredentialType, OAuthCredential[Any]] | None = None) -> None:
        """Write updated credentials back to disk."""
        self._credentials.update(mapping or ())

        data: list[dict[str, Any]] = [cred.export() for cred in self._credentials.values()]

        with self.credentials_path.open('wb') as f:
            f.write(orjson.dumps(data, option=orjson.OPT_INDENT_2))


cred_manager_factory = create_field_factory(CredentialManager)
