from __future__ import annotations

import contextlib
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, ClassVar

from azure.core.credentials import TokenCredential
from msal import ConfidentialClientApplication
from rampy import make_factory

from automate.eserv.errors.authentication import AuthError
from automate.eserv.types.structs import TokenManager
from setup_console import console

if TYPE_CHECKING:
    from azure.core.credentials import AccessToken


def _validate_token_data(
    data: object,
) -> dict[str, Any]:
    if data is None:
        raise AuthError({
            'error': 'bad_response',
            'error_description': 'received empty authentication response',
        })

    if not isinstance(data, dict):
        raise AuthError({
            'error': 'invalid_type',
            'error_description': f'expected {dict}, recieved {type(data)}',
        })

    if 'error' in data:
        raise AuthError(data)

    return data


def _parse_auth_response(result: dict[str, Any] | None) -> dict[str, Any] | None:
    if result and 'access_token' in result:
        console.info('Access Token acquired')

        seconds = int(result.pop('expires_in', 3600))
        result['expires_at'] = datetime.now(UTC) + timedelta(seconds=seconds)

    return result


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
        return str(self.credential.get('authority', '')).rsplit('/', maxsplit=1)[-1]

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

        auth = self.credential.properties.setdefault(
            'authority',
            'https://login.microsoftonline.com/common',
        )

        client = self._client = ConfidentialClientApplication(
            client_id=self.credential.client_id,
            client_credential=cred,
            authority=auth,
        )

        return client

    def get_token(self, *_: ..., **__: ...) -> AccessToken: ...

    def _acquire_token_silent(self) -> dict[str, Any] | None:
        account = None if not (accounts := self.client.get_accounts()) else accounts[0]
        response = self.client.acquire_token_silent(self.scopes, account)
        return _parse_auth_response(response)

    def _acquire_token_by_refresh_token(self) -> dict[str, Any] | None:
        response = self.client.acquire_token_by_refresh_token(self.credential.refresh_token, self.scopes)
        return _parse_auth_response(response)

    def _acquire_token_for_client(self) -> dict[str, Any] | None:
        with contextlib.suppress(DeprecationWarning):
            response = self.client.acquire_token_for_client(scopes=['.default'])
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
        funcs = [
            self._acquire_token_silent,
            self._acquire_token_by_refresh_token,
            self._acquire_token_for_client,
        ]

        errors: list[Exception | None] = [None for _ in range(3)]

        for i, f in enumerate(funcs):
            name = f.__name__.strip('_')
            parsed = f()

            try:
                data = _validate_token_data(parsed)
            except AuthError as err:
                errors[i] = err
            else:
                return data

            console.warning('Authentication failed', method=name)

        console.error(
            event='MSAL token refresh failed',
            **{f.__name__.strip('_'): str(e) for f, e in zip(funcs, errors, strict=True) if e},
        )

        raise sys.exit(1)


make_msal_manager = make_factory(MSALManager)
