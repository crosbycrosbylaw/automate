"""Test suite for util/oauth_manager.py OAuth credential management."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Self, TypedDict
from unittest.mock import patch

import pytest
from pytest_fixture_classes import fixture_class

from automate.eserv import *
from automate.eserv.types import *
from tests.eserv.conftest import *

if TYPE_CHECKING:
    from datetime import datetime

    from dropbox import Dropbox
    from msal import ConfidentialClientApplication


@pytest.fixture
def mock_creds(mock_deps: MockDependencies) -> Mocked[CredentialsConfig]:
    return mock_deps.creds


@fixture_class(name='mock_dbx')
class MockDropbox:
    mock_creds: Mocked[CredentialsConfig]

    _cred: Mocked[DropboxCredential] = field(init=False)

    @property
    def cred(self) -> Mocked[DropboxCredential]:
        return self._cred

    _app: Mocked[Dropbox] = field(init=False)

    @property
    def app(self) -> Mocked[Dropbox]:
        return self._app

    def __post_init__(self) -> None:
        creds: Mocked[CredentialsConfig] = self.mock_creds
        object.__setattr__(self, '_cred', creds.get('dropbox'))

    @contextmanager
    def __call__(
        self,
        access_token: str | None = None,
        refresh_token: str | None = None,
        expiration: datetime | None = None,
        side_effect: Any | None = None,
        **patches: Any,
    ) -> Generator[Self]:
        import dropbox

        app = mock(
            spec=dropbox.Dropbox,
            namespace={
                'check_and_refresh_access_token.return_value': None,
                'check_and_refresh_access_token.side_effect': side_effect,
                '_oauth2_access_token': access_token or self.cred.access_token,
                '_oauth2_refresh_token': refresh_token or self.cred.refresh_token,
                '_oauth2_access_token_expiration': expiration or self.cred.expiration,
                '_scope': ['files.content.write', 'files.metadata.read'],
            },
        )
        object.__setattr__(self, '_app', app)
        patches['Dropbox'] = app

        with patch.multiple('automate.eserv.util.dbx_manager', **patches):
            yield self


class MSALAuthResponse(TypedDict):
    access_token: str
    refresh_token: str
    expires_in: int


class MSALErrorResponse(TypedDict):
    error: str
    error_description: str


type MSALResponse = MSALAuthResponse | MSALErrorResponse


@fixture_class(name='mock_ms_app')
class MockConfidentialClientApplication:
    mock_creds: Mocked[CredentialsConfig]

    _cred: Mocked[MSALCredential] = field(init=False)

    @property
    def cred(self) -> Mocked[MSALCredential]:
        return self._cred

    _app: Mocked[ConfidentialClientApplication] = field(init=False)

    @property
    def app(self) -> Mocked[ConfidentialClientApplication]:
        return self._app

    def __post_init__(self) -> None:
        creds: Mocked[CredentialsConfig] = self.mock_creds
        object.__setattr__(self, '_cred', creds.get('dropbox'))

    @contextmanager
    def __call__(
        self,
        acquire_token_silent: MSALResponse,
        acquire_token_by_refresh_token: MSALResponse,
        acquire_token_for_client: MSALResponse,
        **patches: Any,
    ) -> Generator[Self]:
        import msal

        app = mock(
            spec=msal.ConfidentialClientApplication,
            namespace={
                'acquire_token_silent.return_value': acquire_token_silent,
                'acquire_token_by_refresh_token.return_value': acquire_token_by_refresh_token,
                'acquire_token_for_client.return_value': acquire_token_for_client,
            },
        )

        object.__setattr__(self, '_app', app)
        patches['ConfidentialClientApplication'] = app

        with patch.multiple('automate.eserv.util.msal_manager', **patches):
            yield self
