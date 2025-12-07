from __future__ import annotations

import threading
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Self

import orjson
import requests
from rampy.util import create_field_factory

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path
    from typing import Literal

    from dropbox import Dropbox

    from automate.eserv.monitor.client import GraphClient

type CredentialType = Literal['dropbox', 'microsoft-outlook']
type RefreshHandler = Callable[[OAuthCredential], dict[str, Any]]


def _refresh_dropbox(cred: OAuthCredential[Dropbox]) -> dict[str, Any]:
    """Refresh Dropbox token and return updated token data."""
    response = requests.post(
        'https://api.dropbox.com/oauth2/token',
        data={
            'grant_type': 'refresh_token',
            'refresh_token': cred.refresh_token,
            'client_id': cred.client_id,
            'client_secret': cred.client_secret,
        },
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def _refresh_outlook_msal(cred: OAuthCredential[GraphClient]) -> dict[str, Any]:
    """Refresh Microsoft Outlook token using MSAL.

    Handles two modes:
    1. Migration mode: First refresh uses acquire_token_by_refresh_token()
    2. Normal mode: Subsequent refreshes use acquire_token_silent()

    Args:
        cred: Outlook credential with MSAL app instance

    Returns:
        Token data dict with access_token, refresh_token, expires_in

    Raises:
        RuntimeError: If token refresh fails
    """
    import msal

    if cred.msal_app is None:
        # Initialize MSAL app (lazy creation)
        cred.msal_app = msal.ConfidentialClientApplication(
            client_id=cred.client_id,
            client_credential=cred.client_secret,
            authority='https://login.microsoftonline.com/common',
        )

    # Migration mode: Import existing refresh token into MSAL
    if not cred.msal_migrated:
        result = cred.msal_app.acquire_token_by_refresh_token(
            refresh_token=cred.refresh_token,
            scopes=cred.scope.split(),
        )
        # Note: Migration flag updated by caller after persist()

    # Normal mode: Use MSAL cache for automatic refresh
    else:
        accounts = cred.msal_app.get_accounts()
        if not accounts:
            # Fallback: Rebuild cache from refresh token
            result = cred.msal_app.acquire_token_by_refresh_token(
                refresh_token=cred.refresh_token,
                scopes=cred.scope.split(),
            )
        else:
            result = cred.msal_app.acquire_token_silent(
                scopes=cred.scope.split(),
                account=accounts[0],
            )

            # If silent refresh fails, fallback to refresh token
            if result is None or 'error' in result:
                result = cred.msal_app.acquire_token_by_refresh_token(
                    refresh_token=cred.refresh_token,
                    scopes=cred.scope.split(),
                )

    # Check for errors
    if result is None or 'error' in result:
        error_msg = result.get('error_description', 'Unknown error') if result else 'No result'
        raise RuntimeError(f'MSAL token refresh failed: {error_msg}')

    # Return normalized token data (matches requests.post() format)
    return {
        'access_token': result['access_token'],
        'refresh_token': result.get('refresh_token', cred.refresh_token),  # May not return new RT
        'token_type': result.get('token_type', 'bearer'),
        'scope': ' '.join(result.get('scope', cred.scope.split())),
        'expires_in': result.get('expires_in', 3600),
    }


@dataclass(slots=True)
class OAuthCredential[T = Any]:
    """OAuth credential with token and expiry.

    The string representation of an `OAuthCredential` evaluates to it's access token.
    """

    type: CredentialType
    account: str
    client_id: str
    client_secret: str
    token_type: str
    scope: str
    access_token: str
    refresh_token: str
    expires_at: datetime | None = None

    handler: RefreshHandler | None = field(default=None, repr=False)
    msal_app: Any = field(default=None, repr=False)  # msal.ConfidentialClientApplication
    msal_migrated: bool = False

    def __str__(self) -> str:
        """Return the access token as string representation."""
        return self.access_token

    def export(self) -> dict[str, Any]:
        """Convert credential to JSON serializable dictionary (flat format).

        Returns:
            Flat dictionary with all credential fields.

        """
        data = asdict(self)

        # Convert datetime to ISO string
        if self.expires_at:
            data['expires_at'] = self.expires_at.isoformat()

        # Remove internal fields
        data.pop('handler', None)
        data.pop('msal_app', None)
        # Note: msal_migrated IS serialized (persistence needed)

        return data

    def update_from_refresh(self, token_data: dict[str, Any]) -> OAuthCredential:
        """Create new credential with updated token information.

        Args:
            token_data: OAuth2 token response (access_token, expires_in, etc.)

        Returns:
            New OAuthCredential instance with updated values.

        """
        from dataclasses import replace

        # Parse expiration
        if 'expires_at' in token_data:
            expires_at = datetime.fromisoformat(token_data['expires_at'])
        elif 'expires_in' in token_data:
            expires_at = datetime.now(UTC) + timedelta(seconds=token_data['expires_in'])
        else:
            expires_at = self.expires_at  # Keep existing

        # Update only relevant fields
        return replace(
            self,
            access_token=token_data.get('access_token', self.access_token),
            refresh_token=token_data.get('refresh_token', self.refresh_token),
            scope=token_data.get('scope', self.scope),
            token_type=token_data.get('token_type', self.token_type),
            expires_at=expires_at,
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

        token_data = self.handler(self)
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

        for item in data:
            cred_type = item['type']

            # Parse expiration
            expires_at = None
            if 'expires_at' in item:
                expires_at = datetime.fromisoformat(item['expires_at'])

            # Parse MSAL migration status (default False for backward compat)
            msal_migrated = item.get('msal_migrated', False)

            # Initialize MSAL app for Outlook credentials
            msal_app = None
            if cred_type == 'microsoft-outlook':
                import msal

                msal_app = msal.ConfidentialClientApplication(
                    client_id=item['client_id'],
                    client_credential=item['client_secret'],
                    authority='https://login.microsoftonline.com/common',
                )

            self._credentials[cred_type] = OAuthCredential(
                type=cred_type,
                account=item['account'],
                client_id=item['client_id'],
                client_secret=item['client_secret'],
                token_type=item['token_type'],
                scope=item['scope'],
                access_token=item['access_token'],
                refresh_token=item['refresh_token'],
                expires_at=expires_at,
                handler=self._resolve_refresh_handler(cred_type),
                msal_app=msal_app,
                msal_migrated=msal_migrated,
            )

    @staticmethod
    def _resolve_refresh_handler(cred_type: str) -> RefreshHandler | None:
        match cred_type:
            case 'dropbox':
                return _refresh_dropbox
            case 'microsoft-outlook':
                return _refresh_outlook_msal

        return None

    @staticmethod
    def _parse_expiry(data: dict[str, Any]) -> datetime | None:
        """Parse expiry from token data if present."""
        if 'expires_at' in data:
            return datetime.fromisoformat(data['expires_at'])
        if 'expires_in' in data:
            # Compute from issued_at + expires_in
            issued = datetime.fromisoformat(data.get('issued_at', datetime.now(UTC).isoformat()))
            return issued + timedelta(seconds=data['expires_in'])
        return None

    def get_credential(self, cred_type: CredentialType) -> OAuthCredential:
        """Get credential by type, refreshing if expired."""
        with self._lock:
            cred = self._credentials[cred_type]

            if self._is_expired(cred):
                cred = self._refresh(cred)
                self._credentials[cred_type] = cred
                self.persist()

            return cred

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
        if cred.handler is None:
            message = f'Unknown credential type: {cred.type}'
            raise ValueError(message)

        refreshed = cred.refresh()

        # Mark MSAL credentials as migrated after first successful refresh
        if cred.type == 'microsoft-outlook' and not cred.msal_migrated:
            from dataclasses import replace

            refreshed = replace(refreshed, msal_migrated=True)

        return refreshed

    def persist(self) -> None:
        """Write updated credentials back to disk."""
        data: list[dict[str, Any]] = [cred.export() for cred in self._credentials.values()]

        with self.credentials_path.open('wb') as f:
            f.write(orjson.dumps(data, option=orjson.OPT_INDENT_2))


if TYPE_CHECKING:

    def credential_manager(json_path: Path) -> CredentialManager:
        """Initialize the credential manager.

        Args:
            json_path: Path to the JSON file containing OAuth credentials.

        """
        ...


credential_manager = create_field_factory(CredentialManager)
