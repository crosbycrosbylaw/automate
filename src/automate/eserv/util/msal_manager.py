from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, ClassVar

from azure.core.credentials import TokenCredential
from msal import ConfidentialClientApplication
from rampy import make_factory

from automate.eserv.errors.authentication import raise_from_auth_response
from automate.eserv.types.structs import TokenManager
from setup_console import console

if TYPE_CHECKING:
    from azure.core.credentials import AccessToken


def _validate_token_data(
    data: object,
) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise TypeError(f'Expected dict, got {type(data).__name__}')

    if 'error' in data:
        raise_from_auth_response(data)

    return data


def _parse_auth_response(result: dict[str, Any] | None) -> dict[str, Any] | None:
    if result and 'access_token' in result:
        console.info('Access Token acquired')

        seconds = int(result.pop('expires_in', 3600))
        result['expires_at'] = datetime.now(UTC) + timedelta(seconds=seconds)

        return result

    result = result or {}
    console.error(event='Authentication failed', **result)

    return None


def _build_app_cred() -> dict[str, str]:
    from automate.eserv.config import get_config
    from automate.eserv.errors.types import MissingVariableError

    config = get_config()

    if raw := config.certificate_thumbprint:
        thumbprint = ''.join(raw.split(':'))
    else:
        raise MissingVariableError('CERT_THUMBPRINT')

    return {'thumbprint': thumbprint, 'private_key': f'{config.paths.private_key!s}'}


@dataclass(slots=True)
class MSALManager(TokenManager[ConfidentialClientApplication], TokenCredential):
    """Microsoft authentication wrapper from an OAuth credential.

    Attributes:
        credential: OAuth credential containing access token.

    """

    _RESERVED_SCOPES: ClassVar[set[str]] = {'offline_access', 'openid', 'profile'}

    @property
    def tenant_id(self) -> str:
        return self.credential.get('authority', '').rsplit('/', maxsplit=1)[-1]

    @property
    def scopes(self) -> list[str]:
        """Return scope list with reserved scopes filtered out."""
        return [scope for scope in self.credential.scope.split() if scope not in self._RESERVED_SCOPES] or ['.default']  # fmt: skip

    @property
    def client(self) -> ConfidentialClientApplication:
        """Lazily create MSAL confidential client application.

        Returns:
            ConfidentialClientApplication instance.

        """
        if self._client:
            return self._client

        from automate.eserv.errors.types import MissingVariableError

        try:
            cred = _build_app_cred()
        except MissingVariableError:
            cred = self.credential.client_secret

        client = self._client = ConfidentialClientApplication(
            client_id=self.credential.client_id,
            client_credential=cred,
            authority=self.credential['authority'],
        )

        return client

    def get_token(self, *_: ..., **__: ...) -> AccessToken: ...

    def __post_init__(self) -> None:
        self.credential.properties.setdefault('authority', 'https://login.microsoftonline.com/common')

    def _acquire_token_silent(self) -> dict[str, Any] | None:
        account = None if not (accounts := self.client.get_accounts()) else accounts[0]
        response = self.client.acquire_token_silent(self.scopes, account)
        return _parse_auth_response(response)

    def _acquire_token_by_refresh_token(self) -> dict[str, Any] | None:
        response = self.client.acquire_token_by_refresh_token(self.credential.refresh_token, self.scopes)
        return _parse_auth_response(response)

    def _acquire_token_for_client(self) -> dict[str, Any] | None:
        response = self.client.acquire_token_for_client(scopes=self.scopes)
        return _parse_auth_response(response)

    def _refresh_token(self) -> dict[str, Any]:
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
        data: dict[str, Any] | None = None

        for method in [
            self._acquire_token_silent,
            self._acquire_token_by_refresh_token,
            self._acquire_token_for_client,
        ]:
            if data := method():
                break

            console.warning(f'Failed to authenticate with: {method.__name__.strip("_")}')

        return _validate_token_data(data)


make_msal_manager = make_factory(MSALManager)
