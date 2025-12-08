from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from azure.core.credentials import AccessToken, TokenCredential
from msal import ConfidentialClientApplication
from rampy import create_field_factory

if TYPE_CHECKING:
    from automate.eserv.types import OAuthCredential


@dataclass(slots=True)
class MicrosoftAuthManager(TokenCredential):
    """Microsoft authentication wrapper from an OAuth credential.

    Attributes:
        credential: OAuth credential containing access token.

    """

    _RESERVED_SCOPES: ClassVar[set[str]] = {'offline_access', 'openid', 'profile'}

    credential: OAuthCredential

    id_token: str | None = field(init=False, default=None)
    _client: ConfidentialClientApplication | None = field(init=False, default=None, repr=False)

    def _acquire_token(self) -> Any:
        token_data = None
        with contextlib.suppress(Exception):
            token_data = self.client.acquire_token_by_refresh_token(
                refresh_token=self.credential.refresh_token,
                scopes=self.scopes,
            )
        if token_data is None:
            if password := os.getenv('MS_PASSWORD'):
                token_data = self.client.acquire_token_by_username_password(
                    username=self.credential.account,
                    password=password,
                    scopes=self.scopes,
                )

            else:
                message = 'Failed to obtain token + "MS_PASSWORD" is not set.'
                raise ValueError(message)

        return token_data

    def acquire_token(self, *args: ..., **kwds: ...) -> AccessToken:

        if not isinstance(token_data := self._acquire_token(), dict):
            raise TypeError(f'{token_data=}')

        self.credential = self.credential.update_from_refresh(token_data)
        self.credential.extra_properties.update(
            id_token=token_data.get('id_token'),
            id_token_claism=token_data.get('id_token_claims'),
            client_info=token_data.get('client_info'),
            token_source=token_data.get('token_source'),
        )

        if not self.credential.expires_at:
            raise ValueError

        return AccessToken(
            token=self.credential.access_token,
            expires_on=int(self.credential.expires_at.timestamp()),
        )

    get_token: ... = acquire_token

    @property
    def scopes(self) -> list[str]:
        return [s for s in self.credential.scope.split() if s not in self._RESERVED_SCOPES]

    @property
    def client(self) -> ConfidentialClientApplication:
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
