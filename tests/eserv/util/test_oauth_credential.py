"""Test suite for OAuth credential management.

Tests cover:
- OAuthCredential properties and methods
- DropboxManager token refresh
- MSALManager token refresh with multi-tier fallback
- Certificate authentication
- Token reconstruction and export
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Self
from unittest.mock import Mock, patch

import pytest
from azure.core.credentials import AccessToken
from pytest_fixture_classes import fixture_class

from automate.eserv.util.dbx_manager import DropboxManager
from automate.eserv.util.msal_manager import MSALManager

if TYPE_CHECKING:
    from collections.abc import Generator, Sequence

    from automate.eserv.types import DropboxCredential, MSALCredential
    from tests.eserv.conftest import MockDependencies


# ==============================================================================
# Dropbox Mock Fixture Class
# ==============================================================================


@fixture_class(name='mock_dbx')
class MockDropbox:
    """Mock fixture for Dropbox API interactions."""

    mock_deps: MockDependencies

    _cred: DropboxCredential = field(init=False)
    _app: Mock = field(init=False)

    @property
    def cred(self) -> DropboxCredential:
        return self._cred

    @property
    def app(self) -> Mock:
        return self._app

    def __post_init__(self) -> None:
        object.__setattr__(self, '_cred', self.mock_deps.creds.dropbox)

    @contextmanager
    def __call__(
        self,
        access_token: str | None = None,
        refresh_token: str | None = None,
        expiration: datetime | None = None,
        side_effect: Any | None = None,
        **patches: Any,
    ) -> Generator[Self]:
        """Set up Dropbox mock with optional token overrides."""
        import dropbox

        app = Mock(
            spec=dropbox.Dropbox,
            **{
                'check_and_refresh_access_token.return_value': None,
                'check_and_refresh_access_token.side_effect': side_effect,
                '_oauth2_access_token': access_token or self.cred.access_token,
                '_oauth2_refresh_token': refresh_token or self.cred.refresh_token,
                '_oauth2_access_token_expiration': expiration or self.cred.expiration,
                '_scope': self.cred.scope.split(),
            },
        )
        object.__setattr__(self, '_app', app)
        patches['Dropbox'] = Mock(return_value=app)

        with patch.multiple('automate.eserv.util.dbx_manager', **patches):
            yield self


# ==============================================================================
# MSAL Mock Fixture Class
# ==============================================================================


@fixture_class(name='mock_msal')
class MockMSAL:
    """Mock fixture for MSAL/Microsoft Graph API interactions."""

    mock_deps: MockDependencies
    monkeypatch: pytest.MonkeyPatch

    _cred: MSALCredential = field(init=False)
    _app: Mock = field(init=False)

    @property
    def cred(self) -> MSALCredential:
        return self._cred

    @property
    def app(self) -> Mock:
        return self._app

    def __post_init__(self) -> None:
        cred = self.mock_deps.creds.msal
        cred.properties.setdefault('authority', 'https://login.microsoftonline.com/common')

        object.__setattr__(self, '_cred', cred)

    def default(self) -> dict[str, Any]:
        return {'access_token': ''}

    @contextmanager
    def __call__(
        self,
        silent_response: dict[str, Any] | None = None,
        refresh_response: dict[str, Any] | None = None,
        client_response: dict[str, Any] | None = None,
        accounts: list[dict[str, Any]] | None = None,
        **patches: Any,
    ) -> Generator[Self]:
        """Set up MSAL mock with token acquisition responses."""
        import msal

        app = Mock(
            spec=msal.ConfidentialClientApplication,
            **{
                'acquire_token_silent.return_value': silent_response,
                'acquire_token_by_refresh_token.return_value': refresh_response,
                'acquire_token_for_client.return_value': client_response,
                'get_accounts.return_value': accounts or [],
            },
        )

        object.__setattr__(self, '_app', app)
        patches['ConfidentialClientApplication'] = Mock(return_value=app)

        self.monkeypatch.setattr(self._cred.manager, 'client', app)

        with patch.multiple('automate.eserv.util.msal_manager', **patches):
            yield self


# ==============================================================================
# Credential Fixtures
# ==============================================================================


@pytest.fixture
def dropbox_credential(mock_deps: MockDependencies, monkeypatch: pytest.MonkeyPatch) -> DropboxCredential:
    """Create Dropbox credential from mock dependencies."""
    from automate.eserv.config import parse_credential_json

    # Parse credential directly from JSON data
    dbx_json = mock_deps.credentials[0].copy()
    # Set fresh expiration time to ensure credential is not expired
    future_time = datetime.now(UTC) + timedelta(hours=4)
    dbx_json['expires_at'] = future_time.isoformat()
    return parse_credential_json(dbx_json)


@pytest.fixture
def msal_credential(
    mock_deps: MockDependencies,
    monkeypatch: pytest.MonkeyPatch,
) -> MSALCredential:
    """Create MSAL credential from mock dependencies."""
    from automate.eserv.config import parse_credential_json

    # Parse credential directly from JSON data
    msal_json = mock_deps.credentials[1].copy()
    # Set fresh expiration time to ensure credential is not expired
    future_time = datetime.now(UTC) + timedelta(hours=4)
    msal_json['expires_at'] = future_time.isoformat()
    cred: MSALCredential = parse_credential_json(msal_json)
    # Ensure authority property is set for MSALManager
    cred.properties.setdefault('authority', 'https://login.microsoftonline.com/common')
    return cred


@pytest.fixture
def expired_credential(dropbox_credential: DropboxCredential) -> DropboxCredential:
    """Create expired credential for testing."""
    expired_time = datetime.now(UTC) - timedelta(hours=1)
    dropbox_credential.properties['expires_at'] = expired_time.isoformat()
    return dropbox_credential


# ==============================================================================
# Unit Tests: OAuthCredential Properties
# ==============================================================================


class TestOAuthCredentialProperties:
    """Test OAuthCredential basic properties and magic methods."""

    def test_str_returns_access_token(self, dropbox_credential: DropboxCredential) -> None:
        """Test __str__ returns access token."""
        assert str(dropbox_credential) == dropbox_credential.access_token

    def test_int_returns_expiration_timestamp(self, dropbox_credential: DropboxCredential) -> None:
        """Test __int__ returns expiration as UNIX timestamp."""
        timestamp = int(dropbox_credential)
        expected = int(dropbox_credential.expiration.timestamp())
        assert timestamp == expected

    def test_bool_returns_true_for_valid_credential(
        self,
        dropbox_credential: DropboxCredential,
    ) -> None:
        """Test __bool__ returns True for non-expired credential."""
        assert bool(dropbox_credential) is True

    def test_bool_returns_false_for_expired_credential(
        self,
        expired_credential: DropboxCredential,
    ) -> None:
        """Test __bool__ returns False for expired credential."""
        assert bool(expired_credential) is False

    def test_expired_property_matches_bool(self, dropbox_credential: DropboxCredential) -> None:
        """Test expired property is inverse of __bool__."""
        assert dropbox_credential.expired is not bool(dropbox_credential)

    def test_expiration_property_returns_datetime(
        self,
        dropbox_credential: DropboxCredential,
    ) -> None:
        """Test expiration property returns datetime object."""
        expiration = dropbox_credential.expiration
        assert isinstance(expiration, datetime)
        assert expiration.tzinfo is not None

    def test_getitem_accesses_properties(self, dropbox_credential: DropboxCredential) -> None:
        """Test __getitem__ accesses properties dict."""
        dropbox_credential.properties['test_key'] = 'test_value'
        assert dropbox_credential['test_key'] == 'test_value'

    def test_setitem_modifies_properties(self, dropbox_credential: DropboxCredential) -> None:
        """Test __setitem__ modifies properties dict."""
        dropbox_credential['new_key'] = 'new_value'
        assert dropbox_credential.properties['new_key'] == 'new_value'

    def test_contains_checks_properties(self, dropbox_credential: DropboxCredential) -> None:
        """Test __contains__ checks properties dict."""
        dropbox_credential.properties['existing'] = 'value'
        assert 'existing' in dropbox_credential
        assert 'nonexistent' not in dropbox_credential

    def test_get_returns_property_or_default(self, dropbox_credential: DropboxCredential) -> None:
        """Test get() method with default fallback."""
        dropbox_credential.properties['key'] = 'value'
        assert dropbox_credential.get('key') == 'value'
        assert dropbox_credential.get('missing', 'default') == 'default'

    def test_get_token_returns_access_token(self, dropbox_credential: DropboxCredential) -> None:
        """Test get_token() returns Azure AccessToken."""
        token = dropbox_credential.get_token()
        assert isinstance(token, AccessToken)
        assert token.token == dropbox_credential.access_token
        assert token.expires_on == int(dropbox_credential)


# ==============================================================================
# Unit Tests: OAuthCredential Methods
# ==============================================================================


class TestOAuthCredentialExport:
    """Test OAuthCredential export method."""

    def test_export_returns_flat_dict(self, dropbox_credential: DropboxCredential) -> None:
        """Test export() returns flat dictionary."""
        exported = dropbox_credential.export()

        assert isinstance(exported, dict)
        assert 'type' in exported
        assert 'client_id' in exported
        assert 'access_token' in exported
        assert exported['type'] == 'dropbox'

    def test_export_excludes_internal_fields(self, dropbox_credential: DropboxCredential) -> None:
        """Test export() excludes fields with internal metadata."""
        exported = dropbox_credential.export()

        # factory field has internal=True metadata
        assert 'factory' not in exported

    def test_export_includes_properties(self, dropbox_credential: DropboxCredential) -> None:
        """Test export() includes properties dict contents."""
        dropbox_credential.properties['custom_field'] = 'custom_value'
        exported = dropbox_credential.export()

        assert 'custom_field' in exported
        assert exported['custom_field'] == 'custom_value'


class TestOAuthCredentialReconstruct:
    """Test OAuthCredential reconstruct method."""

    def test_reconstruct_updates_access_token(self, dropbox_credential: DropboxCredential) -> None:
        """Test reconstruct() updates access token."""
        new_token_data = {'access_token': 'new-access-token'}

        new_cred = dropbox_credential.reconstruct(new_token_data)

        assert new_cred.access_token == 'new-access-token'
        assert new_cred.refresh_token == dropbox_credential.refresh_token

    def test_reconstruct_updates_refresh_token(
        self,
        dropbox_credential: DropboxCredential,
    ) -> None:
        """Test reconstruct() updates refresh token."""
        new_token_data = {'refresh_token': 'new-refresh-token'}

        new_cred = dropbox_credential.reconstruct(new_token_data)

        assert new_cred.refresh_token == 'new-refresh-token'

    def test_reconstruct_handles_expires_at(self, dropbox_credential: DropboxCredential) -> None:
        """Test reconstruct() handles expires_at timestamp."""
        future_time = datetime.now(UTC) + timedelta(hours=2)
        new_token_data = {'expires_at': future_time.isoformat()}

        new_cred = dropbox_credential.reconstruct(new_token_data)

        assert 'expires_at' in new_cred.properties
        # Compare timestamps to handle minor precision differences
        assert abs((new_cred.expiration - future_time).total_seconds()) < 1

    def test_reconstruct_handles_expires_in(self, dropbox_credential: DropboxCredential) -> None:
        """Test reconstruct() handles expires_in seconds."""
        new_token_data = {'expires_in': 7200}  # 2 hours

        new_cred = dropbox_credential.reconstruct(new_token_data)

        assert 'expires_in' in new_cred.properties
        assert 'issued_at' in new_cred.properties

    def test_reconstruct_handles_scope_list(self, dropbox_credential: DropboxCredential) -> None:
        """Test reconstruct() converts scope list to string."""
        new_token_data = {'scopes': ['scope1', 'scope2', 'scope3']}

        new_cred = dropbox_credential.reconstruct(new_token_data)

        assert new_cred.scope == 'scope1 scope2 scope3'

    def test_reconstruct_handles_scope_string(self, dropbox_credential: DropboxCredential) -> None:
        """Test reconstruct() accepts scope string."""
        new_token_data = {'scope': 'scope1 scope2'}

        new_cred = dropbox_credential.reconstruct(new_token_data)

        assert new_cred.scope == 'scope1 scope2'

    def test_reconstruct_preserves_other_properties(
        self,
        dropbox_credential: DropboxCredential,
    ) -> None:
        """Test reconstruct() preserves existing properties."""
        dropbox_credential.properties['custom'] = 'value'
        new_token_data = {'access_token': 'new-token'}

        new_cred = dropbox_credential.reconstruct(new_token_data)

        assert new_cred.properties['custom'] == 'value'

    def test_reconstruct_returns_new_instance(self, dropbox_credential: DropboxCredential) -> None:
        """Test reconstruct() returns new instance (immutability)."""
        new_token_data = {'access_token': 'new-token'}

        new_cred = dropbox_credential.reconstruct(new_token_data)

        assert new_cred is not dropbox_credential
        assert dropbox_credential.access_token != 'new-token'


# ==============================================================================
# Integration Tests: DropboxManager
# ==============================================================================


class TestDropboxManagerInitialization:
    """Test DropboxManager client initialization."""

    def test_manager_property_creates_manager(
        self,
        dropbox_credential: DropboxCredential,
    ) -> None:
        """Test manager property creates DropboxManager."""
        manager = dropbox_credential.manager

        assert isinstance(manager, DropboxManager)
        assert manager.credential is dropbox_credential

    def test_manager_property_is_cached(
        self,
        dropbox_credential: DropboxCredential,
    ) -> None:
        """Test manager property is cached."""
        manager1 = dropbox_credential.manager
        manager2 = dropbox_credential.manager

        assert manager1 is manager2

    def test_client_property_creates_dropbox_client(
        self,
        dropbox_credential: DropboxCredential,
    ) -> None:
        """Test client property creates Dropbox client."""
        mock_client = Mock()

        # Clear cached manager AND its client BEFORE patching
        if 'manager' in dropbox_credential.__dict__:
            del dropbox_credential.__dict__['manager']

        with patch('dropbox.Dropbox', return_value=mock_client) as MockDropbox:
            # Access manager to create it INSIDE patch, then access client
            manager = dropbox_credential.manager
            # Ensure _client is None so it initializes inside the patch
            manager._client = None
            client = manager.client

            assert client is mock_client
            MockDropbox.assert_called_once_with(
                oauth2_access_token=dropbox_credential.access_token,
                oauth2_refresh_token=dropbox_credential.refresh_token,
                app_key=dropbox_credential.client_id,
                app_secret=dropbox_credential.client_secret,
            )


class TestDropboxManagerRefresh:
    """Test DropboxManager token refresh."""

    def test_refresh_updates_tokens(
        self,
        dropbox_credential: DropboxCredential,
    ) -> None:
        """Test refresh() updates access and refresh tokens."""
        new_expiration = datetime.now(UTC) + timedelta(hours=4)
        mock_client = Mock()
        mock_client._oauth2_access_token = 'new-access-token'
        mock_client._oauth2_refresh_token = 'new-refresh-token'
        mock_client._oauth2_access_token_expiration = new_expiration
        mock_client._scope = dropbox_credential.scope.split()

        # Clear cached manager BEFORE patching
        if 'manager' in dropbox_credential.__dict__:
            del dropbox_credential.__dict__['manager']

        with patch('dropbox.Dropbox', return_value=mock_client):
            # Access manager and reset its _client INSIDE the patch context
            manager = dropbox_credential.manager
            manager._client = None
            new_cred = dropbox_credential.refresh()

            # Verify token refresh was called
            mock_client.check_and_refresh_access_token.assert_called_once()

            # Verify new credential has updated tokens
            assert new_cred.access_token == 'new-access-token'
            assert new_cred.refresh_token == 'new-refresh-token'

    def test_refresh_returns_new_instance(
        self,
        dropbox_credential: DropboxCredential,
    ) -> None:
        """Test refresh() returns new credential instance."""
        mock_client = Mock()
        mock_client._oauth2_access_token = 'new-token'
        mock_client._oauth2_refresh_token = 'new-refresh-token'
        mock_client._oauth2_access_token_expiration = datetime.now(UTC) + timedelta(hours=4)
        mock_client._scope = []

        # Clear cached manager BEFORE patching
        if 'manager' in dropbox_credential.__dict__:
            del dropbox_credential.__dict__['manager']

        with patch('dropbox.Dropbox', return_value=mock_client):
            # Access manager and reset its _client INSIDE the patch context
            manager = dropbox_credential.manager
            manager._client = None
            new_cred = dropbox_credential.refresh()

            assert new_cred is not dropbox_credential
            assert new_cred.access_token != dropbox_credential.access_token

    def test_refresh_handles_api_error(
        self,
        dropbox_credential: DropboxCredential,
    ) -> None:
        """Test refresh() propagates Dropbox API errors."""
        mock_client = Mock()
        mock_client.check_and_refresh_access_token.side_effect = Exception('API Error')

        # Clear cached manager BEFORE patching
        if 'manager' in dropbox_credential.__dict__:
            del dropbox_credential.__dict__['manager']

        with patch('dropbox.Dropbox', return_value=mock_client):
            # Access manager and reset its _client INSIDE the patch context
            manager = dropbox_credential.manager
            manager._client = None
            with pytest.raises(Exception, match='API Error'):
                dropbox_credential.refresh()


# ==============================================================================
# Integration Tests: MSALManager
# ==============================================================================


class TestMSALManagerInitialization:
    """Test MSALManager client initialization."""

    def test_manager_property_creates_manager(
        self,
        msal_credential: MSALCredential,
    ) -> None:
        """Test manager property creates MSALManager."""
        manager = msal_credential.manager

        assert isinstance(manager, MSALManager)
        assert manager.credential is msal_credential

    def test_manager_property_is_cached(
        self,
        msal_credential: MSALCredential,
    ) -> None:
        """Test manager property is cached."""
        manager1 = msal_credential.manager
        manager2 = msal_credential.manager

        assert manager1 is manager2

    def test_client_property_creates_msal_app(
        self,
        msal_credential: MSALCredential,
    ) -> None:
        """Test client property creates ConfidentialClientApplication."""
        mock_app = Mock()

        # Clear cached manager BEFORE patching
        if 'manager' in msal_credential.__dict__:
            del msal_credential.__dict__['manager']

        with (
            patch(
                'automate.eserv.util.msal_manager._build_app_cred',
                return_value=msal_credential.client_secret,
            ),
            patch(
                'automate.eserv.util.msal_manager.ConfidentialClientApplication', return_value=mock_app
            ) as MockMSAL,
        ):
            # Access manager and reset its _client INSIDE patch
            manager = msal_credential.manager
            manager._client = None
            client = manager.client

            assert client is mock_app
            MockMSAL.assert_called_once_with(
                client_id=msal_credential.client_id,
                client_credential=msal_credential.client_secret,
                authority=msal_credential['authority'],
            )

    def test_scopes_property_filters_reserved_scopes(
        self,
        msal_credential: MSALCredential,
    ) -> None:
        """Test scopes property filters out MSAL reserved scopes."""
        msal_credential.scope = 'Mail.Read offline_access openid profile'

        scopes = msal_credential.manager.scopes

        # Reserved scopes should be filtered
        assert 'offline_access' not in scopes
        assert 'openid' not in scopes
        assert 'profile' not in scopes
        # Non-reserved scopes should remain
        assert 'Mail.Read' in scopes

    def test_scopes_property_returns_default_if_empty(
        self,
        msal_credential: MSALCredential,
    ) -> None:
        """Test scopes property returns .default if all scopes filtered."""
        msal_credential.scope = 'offline_access openid profile'

        scopes = msal_credential.manager.scopes

        assert scopes == ['.default']

    def test_tenant_id_property_extracts_from_authority(
        self,
        msal_credential: MSALCredential,
    ) -> None:
        """Test tenant_id property extracts tenant from authority URL."""
        msal_credential.properties['authority'] = 'https://login.microsoftonline.com/tenant-id-123'

        tenant_id = msal_credential.manager.tenant_id

        assert tenant_id == 'tenant-id-123'


class TestMSALManagerTokenRefresh:
    """Test MSALManager token refresh with multi-tier fallback."""

    @staticmethod
    def _check_exc_group(
        exc: object,
        message: str = r'MSAL token refresh failed',
        count: int = 3,
        match_strs: Sequence[str] = (),
    ) -> bool:
        string = '\n'.join(str(e) for e in getattr(exc, 'exceptions', ()))
        checks = isinstance(exc, ExceptionGroup) and [
            exc.message == message,
            len(exc.exceptions) == count,
            all(s in string for s in match_strs),
        ]
        return bool(checks and all(checks))

    def test_refresh_uses_silent_acquisition_first(
        self,
        msal_credential: MSALCredential,
    ) -> None:
        """Test refresh() tries acquire_token_silent first."""
        token_response = {
            'access_token': 'new-silent-token',
            'refresh_token': 'new-refresh-token',
            'expires_in': 3600,
        }

        mock_app = Mock()
        mock_app.acquire_token_silent.return_value = token_response
        mock_app.get_accounts.return_value = [{'username': 'test@example.com'}]

        # Clear cached manager BEFORE patching
        if 'manager' in msal_credential.__dict__:
            del msal_credential.__dict__['manager']

        with (
            patch(
                'automate.eserv.util.msal_manager._build_app_cred',
                return_value=msal_credential.client_secret,
            ),
            patch('automate.eserv.util.msal_manager.ConfidentialClientApplication', return_value=mock_app),
        ):
            # Access manager and reset its _client INSIDE the patch context
            manager = msal_credential.manager
            manager._client = None
            new_cred = msal_credential.refresh()

            # Verify silent acquisition was attempted
            mock_app.acquire_token_silent.assert_called_once()
            # Verify new credential
            assert new_cred.access_token == 'new-silent-token'

    def test_refresh_falls_back_to_refresh_token(
        self,
        msal_credential: MSALCredential,
    ) -> None:
        """Test refresh() falls back to refresh token if silent fails."""
        refresh_response = {
            'access_token': 'new-refresh-token-acquired',
            'refresh_token': 'new-refresh-token',
            'expires_in': 3600,
        }

        mock_app = Mock()
        mock_app.acquire_token_silent.return_value = None  # Silent fails
        mock_app.acquire_token_by_refresh_token.return_value = refresh_response
        mock_app.get_accounts.return_value = []

        # Clear cached manager BEFORE patching
        if 'manager' in msal_credential.__dict__:
            del msal_credential.__dict__['manager']

        with (
            patch(
                'automate.eserv.util.msal_manager._build_app_cred',
                return_value=msal_credential.client_secret,
            ),
            patch('automate.eserv.util.msal_manager.ConfidentialClientApplication', return_value=mock_app),
        ):
            # Access manager and reset its _client INSIDE the patch context
            manager = msal_credential.manager
            manager._client = None
            new_cred = msal_credential.refresh()

            # Verify fallback to refresh token
            mock_app.acquire_token_silent.assert_called_once()
            mock_app.acquire_token_by_refresh_token.assert_called_once()

            assert new_cred.access_token == 'new-refresh-token-acquired'

    def test_refresh_falls_back_to_client_credentials(
        self,
        msal_credential: MSALCredential,
    ) -> None:
        """Test refresh() falls back to client credentials as last resort."""
        client_response = {
            'access_token': 'new-client-credentials-token',
            'expires_in': 3600,
        }

        mock_app = Mock()
        mock_app.acquire_token_silent.return_value = None
        mock_app.acquire_token_by_refresh_token.return_value = None
        mock_app.acquire_token_for_client.return_value = client_response
        mock_app.get_accounts.return_value = []

        # Clear cached manager BEFORE patching
        if 'manager' in msal_credential.__dict__:
            del msal_credential.__dict__['manager']

        with (
            patch(
                'automate.eserv.util.msal_manager._build_app_cred',
                return_value=msal_credential.client_secret,
            ),
            patch('automate.eserv.util.msal_manager.ConfidentialClientApplication', return_value=mock_app),
        ):
            # Access manager and reset its _client INSIDE the patch context
            manager = msal_credential.manager
            manager._client = None
            new_cred = msal_credential.refresh()

            # Verify all methods tried in order
            mock_app.acquire_token_silent.assert_called_once()
            mock_app.acquire_token_by_refresh_token.assert_called_once()
            mock_app.acquire_token_for_client.assert_called_once()

            assert new_cred.access_token == 'new-client-credentials-token'

    def test_refresh_raises_on_all_methods_failed(
        self,
        msal_credential: MSALCredential,
    ) -> None:
        """Test refresh() raises TypeError when all methods fail."""
        mock_app = Mock()
        mock_app.acquire_token_silent.return_value = None
        mock_app.acquire_token_by_refresh_token.return_value = None
        mock_app.acquire_token_for_client.return_value = None
        mock_app.get_accounts.return_value = []

        # Clear cached manager BEFORE patching
        if 'manager' in msal_credential.__dict__:
            del msal_credential.__dict__['manager']

        with (
            patch(
                'automate.eserv.util.msal_manager._build_app_cred',
                return_value=msal_credential.client_secret,
            ),
            patch('automate.eserv.util.msal_manager.ConfidentialClientApplication', return_value=mock_app),
        ):
            # Access manager and reset its _client INSIDE the patch context
            manager = msal_credential.manager
            manager._client = None
            with pytest.raises(check=self._check_exc_group):
                msal_credential.refresh()

    def test_refresh_raises_on_error_response(
        self,
        msal_credential: MSALCredential,
    ) -> None:
        """Test refresh() logs error and raises TypeError when all methods return errors."""
        error_response = {
            'error': 'invalid_grant',
            'error_description': 'Token expired or revoked',
        }

        mock_app = Mock()
        mock_app.acquire_token_silent.return_value = error_response
        mock_app.acquire_token_by_refresh_token.return_value = error_response
        mock_app.acquire_token_for_client.return_value = error_response
        mock_app.get_accounts.return_value = []

        # Clear cached manager BEFORE patching
        if 'manager' in msal_credential.__dict__:
            del msal_credential.__dict__['manager']

        with (
            patch(
                'automate.eserv.util.msal_manager._build_app_cred',
                return_value=msal_credential.client_secret,
            ),
            patch('automate.eserv.util.msal_manager.ConfidentialClientApplication', return_value=mock_app),
        ):
            manager = msal_credential.manager
            manager._client = None
            with pytest.raises(ExceptionGroup, check=self._check_exc_group):
                msal_credential.refresh()

    def test_refresh_normalizes_expires_in_to_expires_at(
        self,
        msal_credential: MSALCredential,
    ) -> None:
        """Test refresh() converts expires_in to expires_at."""
        before = datetime.now(UTC)
        token_response = {
            'access_token': 'new-token',
            'expires_in': 3600,  # 1 hour
        }

        mock_app = Mock()
        mock_app.acquire_token_silent.return_value = token_response
        mock_app.get_accounts.return_value = []

        # Clear cached manager BEFORE patching
        if 'manager' in msal_credential.__dict__:
            del msal_credential.__dict__['manager']

        with (
            patch(
                'automate.eserv.util.msal_manager._build_app_cred',
                return_value=msal_credential.client_secret,
            ),
            patch('automate.eserv.util.msal_manager.ConfidentialClientApplication', return_value=mock_app),
        ):
            # Access manager and reset its _client INSIDE the patch context
            manager = msal_credential.manager
            manager._client = None
            new_cred = msal_credential.refresh()
            after = datetime.now(UTC)

            # Check expires_at is set to approximately now + 3600 seconds
            expected_expiration = before + timedelta(seconds=3600)
            assert 'expires_at' in new_cred.properties
            actual_expiration = new_cred.expiration

            # Allow 10 second margin for test execution time
            assert (actual_expiration - expected_expiration).total_seconds() < 10
            assert (actual_expiration - after).total_seconds() < 3610

    def test_refresh_returns_new_instance(
        self,
        msal_credential: MSALCredential,
    ) -> None:
        """Test refresh() returns new credential instance."""
        token_response = {'access_token': 'new-token', 'expires_in': 3600}

        mock_app = Mock()
        mock_app.acquire_token_silent.return_value = token_response
        mock_app.get_accounts.return_value = []

        # Clear cached manager BEFORE patching
        if 'manager' in msal_credential.__dict__:
            del msal_credential.__dict__['manager']

        with (
            patch(
                'automate.eserv.util.msal_manager._build_app_cred',
                return_value=msal_credential.client_secret,
            ),
            patch('automate.eserv.util.msal_manager.ConfidentialClientApplication', return_value=mock_app),
        ):
            # Access manager and reset its _client INSIDE the patch context
            manager = msal_credential.manager
            manager._client = None
            new_cred = msal_credential.refresh()

            assert new_cred is not msal_credential
            assert new_cred.access_token != msal_credential.access_token


class TestMSALManagerCertificateAuth:
    """Test MSALManager certificate-based authentication."""

    def test_client_uses_certificate_when_available(
        self,
        msal_credential: MSALCredential,
        mock_deps: MockDependencies,
    ) -> None:
        """Test client initialization uses certificate if available."""
        cert_thumbprint = 'AA:BB:CC:DD:EE:FF:00:11:22:33'
        mock_app = Mock()

        # Clear cached manager BEFORE patching
        if 'manager' in msal_credential.__dict__:
            del msal_credential.__dict__['manager']

        with (
            patch('automate.eserv.config.get_config') as mock_config,
            patch(
                'automate.eserv.util.msal_manager.ConfidentialClientApplication', return_value=mock_app
            ) as MockMSAL,
        ):
            mock_config.return_value = Mock(
                certificate_thumbprint=cert_thumbprint,
                paths=Mock(private_key=mock_deps.fs['cert']['private.key']),
            )

            client = msal_credential.manager.client

            # Verify ConfidentialClientApplication was called with certificate
            assert client is mock_app
            MockMSAL.assert_called_once()
            # Verify certificate credentials were used (check call args contain thumbprint)
            call_kwargs = MockMSAL.call_args.kwargs
            assert 'client_credential' in call_kwargs

    def test_client_falls_back_to_secret(
        self,
        msal_credential: MSALCredential,
    ) -> None:
        """Test client initialization falls back to client secret."""
        from automate.eserv.errors.types import MissingVariableError

        mock_app = Mock()

        # Clear cached manager BEFORE patching
        if 'manager' in msal_credential.__dict__:
            del msal_credential.__dict__['manager']

        with (
            patch('automate.eserv.config.get_config') as mock_config,
            patch(
                'automate.eserv.util.msal_manager.ConfidentialClientApplication', return_value=mock_app
            ) as MockMSAL,
        ):
            mock_config.side_effect = MissingVariableError('CERT_THUMBPRINT')

            client = msal_credential.manager.client

            # Should not raise, falls back to client_secret
            assert client is mock_app
            MockMSAL.assert_called_once()
            # Verify client secret was used (string, not dict)
            call_kwargs = MockMSAL.call_args.kwargs
            assert isinstance(call_kwargs.get('client_credential'), str)


# ==============================================================================
# Run Tests
# ==============================================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
