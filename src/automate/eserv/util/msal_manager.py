from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from msal import ConfidentialClientApplication
from rampy import create_field_factory

if TYPE_CHECKING:
    from automate.eserv.types import OAuthCredential


@dataclass(slots=True)
class MicrosoftAuthManager:
    """Dropbox client wrapper from an OAuth credential.

    Attributes:
        credential: OAuth credential containing access token.

    """

    credential: OAuthCredential
    _client: ConfidentialClientApplication | None = field(init=False, default=None, repr=False)

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
