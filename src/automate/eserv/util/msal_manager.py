from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import new_class
from typing import TYPE_CHECKING, Any, ClassVar, NoReturn

from azure.core.credentials import TokenCredential
from msal import ConfidentialClientApplication
from rampy import make_factory

from automate.eserv.types.structs import TokenManager
from setup_console import console

if TYPE_CHECKING:
    from azure.core.credentials import AccessToken


def _raise_dynamic_exception(token_data: dict[str, Any]) -> NoReturn:
    error_name: str = token_data.pop('error', 'Error')

    if not error_name.endswith('_error'):
        error_name = f'{error_name}_error'

    error_desc: str = token_data.pop('error_description', 'something went wrong')

    error_cls: type[Exception] = new_class(
        name=''.join(x.capitalize() for x in error_name.split('_')),
        bases=(Exception,),
    )

    message = f'{error_desc}\n\n{"\n".join(f"{k}={v}" for k, v in token_data.items())}'
    raise error_cls(message)


def _validate_token_data(
    token_data: object,
    errors: bool = True,
) -> dict[str, Any] | None:
    """Validate token data and handle errors.

    Args:
        token_data: Raw token response from MSAL
        errors: If True, raise exception on error; if False, return None on error

    Returns:
        Validated token data dict, or None if errors=False and data is invalid

    Raises:
        TypeError: If token_data is not a dict
        DynamicException: If token_data contains error (when errors=True)

    """
    if errors is False:
        with contextlib.suppress(Exception):
            return _validate_token_data(token_data)

    if not isinstance(token_data, dict):
        raise TypeError(f'Expected dict, got {type(token_data).__name__}')

    if 'error' in token_data:
        _raise_dynamic_exception(token_data)

    return token_data


def _parse_auth_response(result: dict[str, Any] | None) -> dict[str, Any] | None:

    if result and 'access_token' in result:
        console.info('Access Token acquired')

        seconds = int(result.pop('expires_in', 3600))
        result['expires_at'] = datetime.now(UTC) + timedelta(seconds=seconds)

    else:
        result = result or {}
        console.error(event='Authentication failed', **result)

    return _validate_token_data(result, errors=True)


def _set_certificate_path_from_input() -> bool:
    if strpath := input('Enter the path to private key file: '):
        if not Path(strpath).is_absolute():
            strpath = f'{Path(os.environ["PROJECT_ROOT"]) / strpath}'

        cert_private_key_path = Path(strpath).resolve(strict=True)
        os.environ['CERT_PRIVATE_KEY_PATH'] = str(cert_private_key_path)

        return True
    return False


def _build_app_cred() -> dict[str, str]:
    try:
        project_root = Path(os.environ['PROJECT_ROOT'])

        cert_key_path = project_root / os.environ['CERT_PRIVATE_KEY_PATH']
        cert_key_path.resolve(strict=True)
        private_key = cert_key_path.read_text()

        raw_thumbprint = os.environ['CERT_THUMBPRINT']
        thumbprint = ''.join(raw_thumbprint.split(':'))

    except KeyError as e:
        from automate.eserv.errors.types import MissingVariableError

        raise MissingVariableError(name=e.args[0]) from e

    else:
        return {'thumbprint': thumbprint, 'private_key': private_key}


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
    def app_uri(self) -> str:
        return f'api://{self.credential.client_id}'

    @property
    def scopes(self) -> list[str]:
        """Return scope list with reserved scopes filtered out."""
        return [scope for scope in self.credential.scope.split() if scope not in self._RESERVED_SCOPES] or [
            '.default'
        ]

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

        if 'authority' not in self.credential:
            self.credential['authority'] = 'https://login.microsoftonline.com/common'

    def _authenticate_silent(self) -> dict[str, Any] | None:
        return _parse_auth_response(
            self.client.acquire_token_silent(
                scopes=self.scopes,
                account=None if not (accounts := self.client.get_accounts()) else accounts[0],
            )
        )

    def _authenticate_with_refresh_token(self) -> dict[str, Any] | None:
        return _parse_auth_response(
            self.client.acquire_token_by_refresh_token(
                refresh_token=self.credential.refresh_token,
                scopes=self.scopes,
            )
        )

    def _authenticate_with_certificate(self) -> dict[str, Any] | None:
        """Authenticate using certificate and return token data.

        Returns:
            Token data dict with access_token, expires_in, etc.

        Raises:
            FileNotFoundError: If certificate file not found
            Exception: If certificate authentication fails

        """
        try:
            result = _parse_auth_response(self.client.acquire_token_for_client(scopes=['.default']))
        except FileNotFoundError:
            if _set_certificate_path_from_input():
                return self._authenticate_with_certificate()

            console.exception('Certificate file not found', path=os.getenv('CERT_PRIVATE_KEY_PATH'))
            raise

        else:
            return result

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
        authentication_methods = [
            self._authenticate_with_refresh_token,
            self._authenticate_with_certificate,
        ]

        if bool(self.credential.get('msal_migrated')):
            authentication_methods.insert(0, self._authenticate_silent)

        token_data: dict[str, Any] | None = None

        for method in authentication_methods:
            if token_data := method():
                break

            console.warning(f'Failed to authenticate with: {method.__name__}')

        if token_data is not None:
            return token_data

        _raise_dynamic_exception({
            'error': 'auth_error',
            'error_description': 'Token refresh was unsuccessful',
        })


make_msal_manager = make_factory(MSALManager)
