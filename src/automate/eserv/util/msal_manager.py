from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import new_class
from typing import TYPE_CHECKING, Any, ClassVar, TypeGuard

from azure.core.credentials import AccessToken, TokenCredential
from msal import ConfidentialClientApplication
from rampy import create_field_factory

from automate.eserv.types.structs import TokenManager
from setup_console import console

if TYPE_CHECKING:
    from collections.abc import Generator


def _build_client_credential() -> dict[str, str]:
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
class MicrosoftAuthManager(TokenManager[ConfidentialClientApplication], TokenCredential):
    """Microsoft authentication wrapper from an OAuth credential.

    Attributes:
        credential: OAuth credential containing access token.

    """

    _RESERVED_SCOPES: ClassVar[set[str]] = {'offline_access', 'openid', 'profile'}

    @property
    def tenant_id(self) -> str:
        return self.credential.get('authority', '').rsplit('/', maxsplit=1)[-1]

    _client_cred: dict[str, str] | None = field(init=False, default=None)

    @property
    def client_credential(self) -> dict[str, str]:
        if not self._client_cred:
            self._client_cred = _build_client_credential()

        return self._client_cred

    def _authenticate_with_certificate(self) -> AccessToken:
        try:
            app = ConfidentialClientApplication(
                client_id=self.credential.client_id,
                authority=self.credential['authority'],
                client_credential=self.client_credential,
            )

            result = app.acquire_token_for_client(scopes=['.default']) or {}

            if result and 'access_token' in result:
                console.info('Access Token acquired')
            else:
                console.error(
                    event='Authentication failed',
                    **{k: v for k, v in result.items() if k.startswith('error')},
                )

        except FileNotFoundError:
            console.exception(
                event='Certificate file not found',
                private_key_path=os.getenv('CERT_PRIVATE_KEY_PATH'),
            )

            if not (strpath := input('Enter the path to private key file: ')):
                raise

            if not Path(strpath).is_absolute():
                strpath = f'{Path(os.environ["PROJECT_ROOT"]) / strpath}'

            cert_private_key_path = Path(strpath).resolve(strict=True)
            os.environ['CERT_PRIVATE_KEY_PATH'] = str(cert_private_key_path)

            return self._authenticate_with_certificate()

        except Exception:
            console.exception(event='An unexpected exception occurred')
            raise

        else:
            seconds = int(result.pop('expires_in', 3600))
            result['expires_at'] = datetime.now(UTC) + timedelta(seconds=seconds)

            self.credential = self.credential.update_from_refresh(result)
            return self.credential.token

    def _verify_token_data(
        self,
        token_data: object,
        errors: bool = True,
    ) -> TypeGuard[dict[str, Any]]:
        if not isinstance(token_data, dict):
            return False

        if errors is False:
            return 'error' not in token_data

        if 'error' not in token_data:
            return True

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
        # Filter out MSAL reserved scopes (offline_access, openid, profile)
        # MSAL handles these automatically and raises ValueError if passed explicitly

        token_data = None

        migrated = bool(self.credential.get('msal_migrated'))

        if migrated:
            token_data = self.client.acquire_token_silent(
                scopes=self.scopes,
                account=None if not (accounts := self.client.get_accounts()) else accounts[0],
            )

        if not self._verify_token_data(token_data, errors=False):
            token_data = self.client.acquire_token_by_refresh_token(
                refresh_token=self.credential.refresh_token,
                scopes=self.scopes,
            )

        try:
            self._verify_token_data(token_data, errors=True)
        except Exception:
            console.exception('Refresh token authentication failed; attempting certificate auth.')
            self._authenticate_with_certificate()
            return {}  # inner auth method handles update

        self.credential.extra_properties.update(
            id_token=token_data.get('id_token'),
            id_token_claims=token_data.get('id_token_claims'),
            client_info=token_data.get('client_info'),
            token_source=token_data.get('token_source'),
        )

        out: dict[str, Any] = {}

        for key, value in token_data.items():
            if not value and hasattr(self.credential, key):
                out[key] = getattr(self.credential, key)
            elif key.startswith('expires') or 'token' in key:
                out[key] = value

        if isinstance(scope := out.get('scope'), list):
            out['scope'] = ' '.join(scope)

        return out

    def get_token(self, *_: ..., **__: ...) -> AccessToken:

        token_data = self._refresh_token()

        old_expiration = self.credential.expires_at
        self.credential = self.credential.update_from_refresh(token_data)

        if not (exp := old_expiration or self.credential.expires_at):
            raise ValueError(self.credential)

        return AccessToken(str(self.credential), int(exp.timestamp()))

    def iter_scopes(self) -> Generator[str]:
        yield from (x for x in self.credential.scope.split() if x not in self._RESERVED_SCOPES)

    @property
    def app_uri(self) -> str:
        return f'api://{self.credential.client_id}'

    @property
    def scopes(self) -> list[str]:
        return [*self.iter_scopes()]

    @property
    def client(self):
        """Lazily create Dropbox client from credential.

        Returns:
            Dropbox client instance.

        """
        if self._client is None:
            self._client = ConfidentialClientApplication(
                client_id=self.credential.client_id,
                client_credential=self.credential.client_secret,
                authority=self.credential['authority']
                or 'https://login.microsoftonline.com/common',
            )

        return self._client


msauth_manager_factory = create_field_factory(MicrosoftAuthManager)
