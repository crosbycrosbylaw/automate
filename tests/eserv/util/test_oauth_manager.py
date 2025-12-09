"""Test suite for util/oauth_manager.py OAuth credential management."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, TypedDict, Unpack
from unittest.mock import Mock, patch

import orjson
import pytest

from automate.eserv.util import dropbox_manager_factory, msauth_manager_factory
from automate.eserv.util.oauth_manager import CredentialManager, OAuthCredential

if TYPE_CHECKING:
    from pathlib import Path

    from automate.eserv.types import *


def _refresh_dropbox(cred: OAuthCredential[DropboxManager]) -> dict[str, Any]:
    return cred.manager._refresh_token()


def _refresh_outlook_msal(cred: OAuthCredential[MicrosoftAuthManager]) -> dict[str, Any]:
    return cred.manager._refresh_token()


@pytest.fixture
def dropbox_credential():
    return OAuthCredential(
        manager_factory=dropbox_manager_factory,
        type='dropbox',
        account='test-business',
        client_id='test_client_id',
        client_secret='test_client_secret',
        token_type='bearer',
        scope='files.content.write',
        access_token='old_access_token',
        refresh_token='test_refresh_token',
        expires_at=datetime.now(UTC) - timedelta(hours=1),  # Expired
    )


@pytest.fixture
def mock_dropbox():
    return Mock(
        spec=[
            '_oauth2_access_token',
            '_oauth2_refresh_token',
            '_oauth2_access_token_expiration',
            '_scope',
            'check_and_refresh_access_token',
        ]
    )


@pytest.fixture
def microsoft_credential():
    return OAuthCredential(
        manager_factory=msauth_manager_factory,
        type='microsoft-outlook',
        account='test-account',
        client_id='outlook_client_id',
        client_secret='outlook_client_secret',
        token_type='bearer',
        scope='Mail.Read offline_access',
        access_token='old_outlook_token',
        refresh_token='outlook_refresh_token',
        expires_at=datetime.now(UTC) - timedelta(hours=1),  # Expired
        extra_properties={'msal_migrated': False},
    )


class TokenManagerClientConfig(TypedDict, total=False):
    _oauth2_access_token: str
    _oauth2_refresh_token: str
    _oauth2_access_token_expiration: datetime
    _scope: list[str]

    side_effect: Any


class TestTokenRefresh:
    """Test unified refresh mechanism for both Dropbox and Outlook."""

    @staticmethod
    def _refresh_outlook_msal(
        cred: OAuthCredential[Any],
    ) -> dict[str, Any]:
        return cred.manager._refresh_token()

    @staticmethod
    def _refresh_dropbox(
        cred: OAuthCredential[Any],
        **config: Unpack[TokenManagerClientConfig],
    ) -> None:
        mock_client = Mock(
            spec=[
                '_oauth2_access_token',
                '_oauth2_refresh_token',
                '_oauth2_access_token_expiration',
                '_scope',
                'check_and_refresh_access_token',
            ]
        )
        mock_client.configure_mock(**{
            '_oauth2_access_token': config.get('_oauth2_access_token', 'dropbox_token'),
            '_oauth2_refresh_token': config.get('_oauth2_refresh_token', 'refresh_token'),
            '_oauth2_access_token_expiration': config.get(
                '_oauth2_access_token_expiration', datetime.now(UTC) + timedelta(hours=4)
            ),
            '_scope': config.get('_scope', ['files.content.write', 'files.metadata.read']),
            'check_and_refresh_access_token.return_value': None,
            'check_and_refresh_access_token.side_effect': config.get('side_effect'),
        })

        mock_manager = Mock()
        mock_manager.client.return_value = mock_client

        with patch('dropbox.Dropbox', Mock(return_value=mock_client)):
            result = cred.refresh()

            mock_client.check_and_refresh_access_token.assert_called_once()

            # Assert returned data has correct structure
            assert result.access_token == mock_client._oauth2_access_token
            assert result.refresh_token == mock_client._oauth2_refresh_token
            assert result.expires_at == mock_client._oauth2_access_token_expiration
            assert result.scope.split() == mock_client._scope

    def test_refresh_dropbox_success(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
    ):
        """Test successful Dropbox token refresh."""
        self._refresh_dropbox(
            dropbox_credential,
            _oauth2_access_token='new_dropbox_token',
            _oauth2_refresh_token='new_refresh_token',
            _scope=['files.content.write', 'files.metadata.read'],
            _oauth2_access_token_expiration=datetime.now(UTC) + timedelta(hours=4),
        )

    def test_refresh_outlook_msal_success(
        self,
        microsoft_credential: OAuthCredential[MicrosoftAuthManager],
    ):
        """Test successful Outlook token refresh using MSAL (migration mode)."""
        cred = microsoft_credential

        # Mock MSAL app
        mock_app = Mock()
        mock_msal_result = {
            'access_token': 'new_outlook_token',
            'refresh_token': 'new_refresh_token',
            'token_type': 'bearer',
            'scope': ['Mail.Read', 'offline_access'],
            'expires_in': 3600,
        }
        mock_app.get_accounts.return_value = []  # No accounts (migration mode)
        mock_app.acquire_token_by_refresh_token.return_value = mock_msal_result

        # Create mock manager with MSAL client
        mock_manager = Mock()
        mock_manager.client = mock_app

        # Patch the manager property
        with patch.object(type(cred), 'manager', property(lambda _: mock_manager)):
            result = _refresh_outlook_msal(cred)

            # Assert acquire_token_by_refresh_token was called
            # Note: offline_access is filtered out (reserved scope)
            mock_app.acquire_token_by_refresh_token.assert_called_once_with(
                refresh_token=cred.refresh_token,
                scopes=['Mail.Read'],  # offline_access filtered out
            )

            # Assert returned data has correct structure
            assert result['access_token'] == 'new_outlook_token'
            assert result['refresh_token'] == 'new_refresh_token'
            assert result['token_type'] == 'bearer'
            assert result['scope'] == 'Mail.Read offline_access'
            assert result['expires_in'] == 3600

    def test_refresh_dropbox_connection_error(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
    ):
        """Test refresh handles network errors gracefully."""
        with pytest.raises(ConnectionError, match='Network unreachable'):
            self._refresh_dropbox(
                cred=dropbox_credential,
                side_effect=ConnectionError('Network unreachable'),
            )

    def test_refresh_dropbox_auth_error(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
    ):
        from dropbox.exceptions import AuthError

        with pytest.raises(AuthError):
            self._refresh_dropbox(
                cred=dropbox_credential,
                side_effect=AuthError('req_id', None),
            )

    def test_credential_refresh_integration(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
    ):
        """Test OAuthCredential.refresh() uses handler correctly."""
        # Create credential with mocked handler
        mock_handler = Mock(return_value={'access_token': 'new_token', 'expires_in': 3600})

        cred = replace(dropbox_credential, handler=mock_handler)

        # Call refresh
        refreshed = cred.refresh()

        # Assert handler was called
        mock_handler.assert_called_once_with(cred)

        # Assert new credential returned
        assert refreshed.access_token == 'new_token'
        assert refreshed.expires_at is not None
        assert refreshed.expires_at > datetime.now(UTC)

    def test_refresh_without_handler_raises_error(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
    ):
        """Test that refresh without handler raises ValueError."""
        cred = replace(dropbox_credential, handler=None)

        with pytest.raises(ValueError, match='no configuration set'):
            cred.refresh()


class TestCredentialUpdate:
    """Test credential update logic."""

    def test_update_from_refresh_with_expires_in(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
    ):
        """Test updating credential from token data with expires_in."""
        # Create original credential with old values
        original = replace(
            dropbox_credential,
            access_token='old_token',
            refresh_token='old_refresh',
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )

        # Update with new token data
        token_data = {
            'access_token': 'new_token',
            'refresh_token': 'new_refresh',
            'expires_in': 3600,
        }

        updated = original.update_from_refresh(token_data)

        # Assert new credential returned with correct values
        assert updated.access_token == 'new_token'
        assert updated.refresh_token == 'new_refresh'
        assert updated.expires_at is not None
        assert updated.expires_at > datetime.now(UTC)
        assert updated.expires_at < datetime.now(UTC) + timedelta(hours=2)

        # Assert original unchanged (immutable pattern)
        assert original.access_token == 'old_token'
        assert original.refresh_token == 'old_refresh'

    def test_update_from_refresh_with_expires_at(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
    ):
        """Test updating credential with expires_at timestamp."""
        original = replace(
            dropbox_credential,
            access_token='old_token',
            refresh_token='refresh',
        )

        future_time = datetime.now(UTC) + timedelta(hours=2)
        token_data = {
            'access_token': 'new_token',
            'expires_at': future_time.isoformat(),
        }

        updated = original.update_from_refresh(token_data)

        assert updated.access_token == 'new_token'
        assert updated.expires_at == future_time

    def test_update_preserves_unchanged_fields(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
    ):
        """Test that fields not in token data are preserved."""
        original = dropbox_credential

        # Update with minimal data (only access_token)
        token_data = {
            'access_token': 'new_token',
            'expires_in': 3600,
        }

        updated = original.update_from_refresh(token_data)

        # Assert updated field changed
        assert updated.access_token == token_data['access_token']

        # Assert other fields preserved
        assert updated.account == original.account
        assert updated.client_id == original.client_id
        assert updated.client_secret == original.client_secret
        assert updated.scope == original.scope
        assert updated.refresh_token == original.refresh_token

    def test_update_with_partial_data(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
    ):
        """Test update with only some fields in token response."""
        original = dropbox_credential

        # Outlook might return scope in refresh response
        token_data = {
            'access_token': 'new_token',
            'scope': 'Mail.Read Mail.Send',
            'expires_in': 3600,
        }

        updated = original.update_from_refresh(token_data)

        assert updated.access_token == token_data['access_token']
        assert updated.scope == token_data['scope']
        assert updated.refresh_token == original.refresh_token

    def test_update_immutability(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
    ):
        """Test that update_from_refresh follows immutable pattern."""
        original = replace(dropbox_credential, access_token='token1')

        # Multiple updates should create new instances
        updated1 = original.update_from_refresh({'access_token': 'token2', 'expires_in': 3600})
        updated2 = updated1.update_from_refresh({'access_token': 'token3', 'expires_in': 3600})

        # All should be different objects
        assert original is not updated1
        assert updated1 is not updated2
        assert original is not updated2

        # Each should have correct value
        assert original.access_token == 'token1'
        assert updated1.access_token == 'token2'
        assert updated2.access_token == 'token3'


class TestDropboxManager:
    """Test DropboxManager client creation and lifecycle."""

    def test_client_created_lazily(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
    ):
        """Test client is created only when accessed."""
        # Create credential
        cred = dropbox_credential

        # Create manager
        manager = dropbox_manager_factory(cred)

        # Assert _client is None initially
        assert manager._client is None

        # Access client property
        with patch('dropbox.Dropbox') as MockDropbox:
            mock_client = Mock()
            MockDropbox.return_value = mock_client

            client = manager.client

            # Assert Dropbox constructor called with correct params
            MockDropbox.assert_called_once_with(
                oauth2_access_token='old_access_token',  # Matches fixture value
                oauth2_refresh_token='test_refresh_token',
                app_key='test_client_id',
                app_secret='test_client_secret',
            )

            # Assert client instance stored
            assert manager._client is mock_client
            assert client is mock_client

    def test_client_reused_on_subsequent_access(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
    ):
        """Test client is reused across accesses."""
        cred = dropbox_credential

        manager = dropbox_manager_factory(cred)

        with patch('dropbox.Dropbox') as MockDropbox:
            mock_client = Mock()
            MockDropbox.return_value = mock_client

            # Access client twice
            client1 = manager.client
            client2 = manager.client

            # Assert Dropbox constructor called only once
            assert MockDropbox.call_count == 1

            # Assert same instance returned
            assert client1 is client2
            assert client1 is mock_client

    def test_manager_uses_credential_values(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
    ):
        """Test that DropboxManager uses credential's current values."""
        cred = dropbox_credential

        manager = dropbox_manager_factory(cred)

        with patch('dropbox.Dropbox') as MockDropbox:
            _ = manager.client

            # Verify original credential values were used
            call_kwargs = MockDropbox.call_args.kwargs
            assert call_kwargs['oauth2_access_token'] == cred.access_token
            assert call_kwargs['oauth2_refresh_token'] == cred.refresh_token
            assert call_kwargs['app_key'] == cred.client_id
            assert call_kwargs['app_secret'] == cred.client_secret


class TestCredentialSerialization:
    """Test credential serialization (export/load)."""

    def test_export_flat_format(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
    ):
        """Test credential exports to flat JSON format."""
        cred = dropbox_credential

        exported = cred.export()

        # Assert flat structure
        assert exported['type'] == cred.type
        assert exported['account'] == cred.account
        assert exported['client_id'] == cred.client_id
        assert exported['client_secret'] == cred.client_secret
        assert exported['token_type'] == cred.token_type
        assert exported['scope'] == cred.scope
        assert exported['access_token'] == cred.access_token
        assert exported['refresh_token'] == cred.refresh_token

        assert cred.expires_at
        assert exported['expires_at'] == cred.expires_at.isoformat()

        # Assert no nested dicts
        assert 'client' not in exported
        assert 'data' not in exported

        # Assert no handler field
        assert 'handler' not in exported

    def test_export_without_expires_at(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
    ):
        """Test export handles missing expires_at."""
        cred = replace(dropbox_credential, expires_at=None)

        exported = cred.export()

        assert 'expires_at' in exported
        assert exported['expires_at'] is None


class TestCredentialManager:
    """Test credential manager loading and expiry checking."""

    def test_load_credentials_flat_format(self, tempdir: Path):
        """Test loading credentials from flat JSON format."""
        # Create test credentials file with flat format
        creds_file = tempdir / 'credentials.json'
        test_data = [
            {
                'type': 'dropbox',
                'account': 'business',
                'client_id': 'dbx_client',
                'client_secret': 'dbx_secret',
                'token_type': 'bearer',
                'scope': 'files.content.write',
                'access_token': 'dbx_access',
                'refresh_token': 'dbx_refresh',
                'expires_at': (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            },
        ]

        with creds_file.open('wb') as f:
            f.write(orjson.dumps(test_data))

        # Load credentials
        manager = CredentialManager(creds_file)

        # Assert credential loaded correctly
        cred = manager.get_credential('dropbox')
        assert cred.type == 'dropbox'
        assert cred.account == 'business'
        assert cred.client_id == 'dbx_client'
        assert cred.client_secret == 'dbx_secret'
        assert cred.access_token == 'dbx_access'
        assert cred.refresh_token == 'dbx_refresh'
        assert cred.handler is not None

    def test_get_credential_refreshes_when_expired(self, tempdir: Path):
        """Test that get_credential auto-refreshes expired tokens."""
        # Create credentials with past expiry (flat format)
        creds_file = tempdir / 'credentials.json'
        test_data = [
            {
                'type': 'dropbox',
                'account': 'test',
                'client_id': 'client',
                'client_secret': 'secret',
                'token_type': 'bearer',
                'scope': 'files',
                'access_token': 'old_token',
                'refresh_token': 'refresh',
                'expires_at': (datetime.now(UTC) - timedelta(hours=1)).isoformat(),  # Expired
            },
        ]

        with creds_file.open('wb') as f:
            f.write(orjson.dumps(test_data))

        # Mock Dropbox client
        mock_dbx = Mock()
        mock_dbx._oauth2_access_token = 'new_token'
        mock_dbx._oauth2_refresh_token = 'refresh'
        mock_dbx._oauth2_access_token_expiration = datetime.now(UTC) + timedelta(hours=4)
        mock_dbx._scope = ['files']
        mock_dbx.check_and_refresh_access_token.return_value = None

        with patch('dropbox.Dropbox', return_value=mock_dbx):
            manager = CredentialManager(creds_file)

            # Get credential (should trigger refresh)
            cred = manager.get_credential('dropbox')

            # Assert refresh was called
            mock_dbx.check_and_refresh_access_token.assert_called_once()
            assert cred.access_token == 'new_token'

    def test_get_credential_no_refresh_when_valid(self, tempdir: Path):
        """Test that get_credential doesn't refresh valid tokens."""
        # Create credentials with future expiry (flat format)
        creds_file = tempdir / 'credentials.json'
        test_data = [
            {
                'type': 'dropbox',
                'account': 'test',
                'client_id': 'client',
                'client_secret': 'secret',
                'token_type': 'bearer',
                'scope': 'files',
                'access_token': 'valid_token',
                'refresh_token': 'refresh',
                'expires_at': (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            },
        ]

        with creds_file.open('wb') as f:
            f.write(orjson.dumps(test_data))

        manager = CredentialManager(creds_file)

        # Mock refresh handler
        with patch('automate.eserv.util.oauth_manager._refresh_dropbox') as mock_refresh:
            # Get credential (should NOT trigger refresh)
            cred = manager.get_credential('dropbox')

            # Assert refresh was NOT called
            assert not mock_refresh.called
            assert cred.access_token == 'valid_token'

    def test_persist_saves_flat_format(self, tempdir: Path):
        """Test that persist() saves credentials in flat format."""
        # Create initial credentials (flat format)
        creds_file = tempdir / 'credentials.json'
        test_data = [
            {
                'type': 'dropbox',
                'account': 'test',
                'client_id': 'client',
                'client_secret': 'secret',
                'token_type': 'bearer',
                'scope': 'files',
                'access_token': 'old_token',
                'refresh_token': 'refresh',
            },
        ]

        with creds_file.open('wb') as f:
            f.write(orjson.dumps(test_data))

        with patch('dropbox.Dropbox'):
            manager = CredentialManager(creds_file)

            # Simulate token refresh by manually updating credential
            cred = manager._credentials['dropbox']
            updated_cred = replace(cred, access_token='new_token')
            manager._credentials['dropbox'] = updated_cred

            # Persist changes
            manager.persist()

        # Reload and verify flat format
        with creds_file.open('rb') as f:
            saved_data = orjson.loads(f.read())

        # Assert flat structure
        assert saved_data[0]['access_token'] == 'new_token'
        assert saved_data[0]['type'] == 'dropbox'
        assert saved_data[0]['client_id'] == 'client'

        # Assert no nested dicts
        assert 'client' not in saved_data[0]
        assert 'data' not in saved_data[0]


class TestMSALIntegration:
    """Test MSAL integration for Microsoft Outlook authentication."""

    def test_msal_app_initialization(self, tempdir: Path):
        """Test MSAL app created for Outlook credentials on load."""
        # Create credentials with Outlook and Dropbox
        creds_file = tempdir / 'credentials.json'
        test_data = [
            {
                'type': 'microsoft-outlook',
                'account': 'eservice',
                'client_id': 'outlook_client',
                'client_secret': 'outlook_secret',
                'token_type': 'bearer',
                'scope': 'Mail.Read offline_access',
                'access_token': 'outlook_access',
                'refresh_token': 'outlook_refresh',
                'expires_at': (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            },
            {
                'type': 'dropbox',
                'account': 'business',
                'client_id': 'dbx_client',
                'client_secret': 'dbx_secret',
                'token_type': 'bearer',
                'scope': 'files.content.write',
                'access_token': 'dbx_access',
                'refresh_token': 'dbx_refresh',
            },
        ]

        with creds_file.open('wb') as f:
            f.write(orjson.dumps(test_data))

        # Load credentials
        with (
            patch('automate.eserv.util.msal_manager.ConfidentialClientApplication') as MockMSAL,
            patch('dropbox.Dropbox'),
        ):
            mock_app = Mock()
            MockMSAL.return_value = mock_app

            manager = CredentialManager(creds_file)

            outlook_cred = manager['microsoft-outlook']

            # Access manager.client to trigger lazy creation
            _ = outlook_cred.manager.client

            # Assert MSAL app created for Outlook
            MockMSAL.assert_called_once_with(
                client_id='outlook_client',
                client_credential='outlook_secret',
                authority='https://login.microsoftonline.com/common',
            )

            assert outlook_cred.manager.client is mock_app

            # Assert Dropbox credential has no MSAL app
            dropbox_cred = manager['dropbox']
            assert dropbox_cred.manager.client is not mock_app

    def test_msal_migration_first_refresh(self, tempdir: Path):
        """Test migration flag changes after first refresh."""
        # Create unmigrated Outlook credential
        creds_file = tempdir / 'credentials.json'
        test_data = [
            {
                'type': 'microsoft-outlook',
                'account': 'eservice',
                'client_id': 'client',
                'client_secret': 'secret',
                'token_type': 'bearer',
                'scope': 'Mail.Read offline_access',
                'access_token': 'old_token',
                'refresh_token': 'refresh',
                'expires_at': (datetime.now(UTC) - timedelta(hours=1)).isoformat(),  # Expired
                'msal_migrated': False,
            },
        ]

        with creds_file.open('wb') as f:
            f.write(orjson.dumps(test_data))

        # Mock MSAL
        mock_msal_result = {
            'access_token': 'new_token',
            'refresh_token': 'new_refresh',
            'token_type': 'bearer',
            'scope': ['Mail.Read', 'offline_access'],
            'expires_in': 3600,
        }

        with patch('automate.eserv.util.msal_manager.ConfidentialClientApplication') as MockMSAL:
            mock_app = Mock()
            mock_app.get_accounts.return_value = []
            mock_app.acquire_token_by_refresh_token.return_value = mock_msal_result
            MockMSAL.return_value = mock_app

            manager = CredentialManager(creds_file)

            # Get credential (triggers refresh)
            cred = manager.get_credential('microsoft-outlook')

            # Assert migration flag set to True
            assert cred['msal_migrated'] is True

            # Assert persisted with flag
            with creds_file.open('rb') as f:
                saved_data = orjson.loads(f.read())
            assert saved_data[0]['msal_migrated'] is True

    def test_msal_silent_refresh_after_migration(self, tempdir: Path):
        """Test silent refresh used after migration."""
        # Create migrated Outlook credential
        creds_file = tempdir / 'credentials.json'
        test_data = [
            {
                'type': 'microsoft-outlook',
                'account': 'eservice',
                'client_id': 'client',
                'client_secret': 'secret',
                'token_type': 'bearer',
                'scope': 'Mail.Read offline_access',
                'access_token': 'old_token',
                'refresh_token': 'refresh',
                'expires_at': (datetime.now(UTC) - timedelta(hours=1)).isoformat(),  # Expired
                'msal_migrated': True,
            },
        ]

        with creds_file.open('wb') as f:
            f.write(orjson.dumps(test_data))

        # Mock MSAL
        mock_account = {'username': 'user@example.com'}
        mock_msal_result = {
            'access_token': 'new_token',
            'token_type': 'bearer',
            'scope': ['Mail.Read', 'offline_access'],
            'expires_in': 3600,
        }

        with patch('automate.eserv.util.msal_manager.ConfidentialClientApplication') as MockMSAL:
            mock_app = Mock()
            mock_app.get_accounts.return_value = [mock_account]
            mock_app.acquire_token_silent.return_value = mock_msal_result
            MockMSAL.return_value = mock_app

            manager = CredentialManager(creds_file)

            # Manually set credential as expired to trigger refresh
            _ = manager._credentials['microsoft-outlook']
            _ = manager.get_credential('microsoft-outlook')

            # Assert silent refresh called (not by_refresh_token)
            mock_app.acquire_token_silent.assert_called_once()
            mock_app.acquire_token_by_refresh_token.assert_not_called()

    def test_msal_fallback_on_silent_failure(
        self,
        microsoft_credential: OAuthCredential[MicrosoftAuthManager],
    ):
        """Test fallback to refresh token when silent fails."""
        microsoft_credential.extra_properties['msal_migrated'] = True
        cred = microsoft_credential

        mock_account = {'username': 'user@example.com'}
        mock_msal_success = {
            'access_token': 'new_token',
            'token_type': 'bearer',
            'scope': ['Mail.Read', 'offline_access'],
            'expires_in': 3600,
        }

        with patch('automate.eserv.util.msal_manager.ConfidentialClientApplication') as MockMSAL:
            mock_app = Mock()
            mock_app.get_accounts.return_value = [mock_account]
            mock_app.acquire_token_silent.return_value = None  # Silent fails
            mock_app.acquire_token_by_refresh_token.return_value = mock_msal_success
            MockMSAL.return_value = mock_app

            result = _refresh_outlook_msal(cred)

            # Assert fallback to refresh token used
            mock_app.acquire_token_silent.assert_called_once()
            mock_app.acquire_token_by_refresh_token.assert_called_once()
            assert result['access_token'] == 'new_token'

    def test_msal_handles_account_cache_miss(
        self,
        microsoft_credential: OAuthCredential[MicrosoftAuthManager],
    ):
        """Test fallback when account cache is empty."""
        # Set msal_migrated to True so get_accounts is called
        cred = microsoft_credential
        cred.extra_properties['msal_migrated'] = True

        mock_msal_result = {
            'access_token': 'new_token',
            'token_type': 'bearer',
            'scope': ['Mail.Read', 'offline_access'],
            'expires_in': 3600,
        }

        # Mock MSAL app
        mock_app = Mock()
        mock_app.get_accounts.return_value = []  # Empty cache
        mock_app.acquire_token_by_refresh_token.return_value = mock_msal_result

        # Create mock manager with MSAL client
        mock_manager = Mock()
        mock_manager.client = mock_app

        # Patch the manager property
        with patch.object(type(cred), 'manager', property(lambda _: mock_manager)):
            result = _refresh_outlook_msal(cred)

            # Assert acquire_token_by_refresh_token used directly
            mock_app.get_accounts.assert_called_once()
            mock_app.acquire_token_by_refresh_token.assert_called_once()
            assert result['access_token'] == 'new_token'

    def test_msal_error_handling(
        self,
        microsoft_credential: OAuthCredential[MicrosoftAuthManager],
    ):
        """Test MSAL error handling."""
        cred = microsoft_credential

        mock_error_result = {'error': 'invalid_grant', 'error_description': 'Refresh token expired'}

        with patch('automate.eserv.util.msal_manager.ConfidentialClientApplication') as MockMSAL:
            mock_app = Mock()
            mock_app.acquire_token_by_refresh_token.return_value = mock_error_result
            MockMSAL.return_value = mock_app

            with pytest.raises(
                RuntimeError, match='MSAL token refresh failed: Refresh token expired'
            ):
                _refresh_outlook_msal(cred)

    def test_msal_token_normalization(
        self,
        microsoft_credential: OAuthCredential[MicrosoftAuthManager],
    ):
        """Test MSAL result converted to compatible format."""
        cred = microsoft_credential

        # MSAL returns scope as list, not string
        mock_msal_result = {
            'access_token': 'new_token',
            'refresh_token': 'new_refresh',
            'token_type': 'Bearer',
            'scope': ['Mail.Read', 'offline_access', 'Mail.Send'],
            'expires_in': 7200,
        }

        with patch('automate.eserv.util.msal_manager.ConfidentialClientApplication') as MockMSAL:
            mock_app = Mock()
            mock_app.acquire_token_by_refresh_token.return_value = mock_msal_result
            MockMSAL.return_value = mock_app

            result = _refresh_outlook_msal(cred)

            # Assert normalized to update_from_refresh() format
            assert result['access_token'] == 'new_token'
            assert result['refresh_token'] == 'new_refresh'
            assert result['token_type'] == 'Bearer'
            assert result['scope'] == 'Mail.Read offline_access Mail.Send'  # String, not list
            assert result['expires_in'] == 7200

    def test_msal_app_not_serialized(
        self,
        microsoft_credential: OAuthCredential[MicrosoftAuthManager],
    ):
        """Test msal_app excluded from export."""
        cred = microsoft_credential
        cred.extra_properties['msal_migrated'] = True

        exported = cred.export()

        # Assert msal_migrated included
        assert 'msal_migrated' in exported
        assert exported['msal_migrated'] is True

    def test_msal_app_recreated_on_load(self, tempdir: Path):
        """Test MSAL app recreated on each load."""
        creds_file = tempdir / 'credentials.json'
        test_data = [
            {
                'type': 'microsoft-outlook',
                'account': 'eservice',
                'client_id': 'client',
                'client_secret': 'secret',
                'token_type': 'bearer',
                'scope': 'Mail.Read offline_access',
                'access_token': 'token',
                'refresh_token': 'refresh',
                'msal_migrated': True,
            },
        ]

        with creds_file.open('wb') as f:
            f.write(orjson.dumps(test_data))

        with patch('automate.eserv.util.msal_manager.ConfidentialClientApplication') as MockMSAL:
            mock_app1 = Mock()
            mock_app2 = Mock()
            # Use side_effect to return different mocks for each call
            MockMSAL.side_effect = [mock_app1, mock_app2]

            # First load
            manager1 = CredentialManager(creds_file)
            cred1 = manager1._credentials['microsoft-outlook']

            # Access client to trigger creation
            client1 = cred1.manager.client

            # Persist (should not serialize msal_app)
            manager1.persist()

            # Second load
            manager2 = CredentialManager(creds_file)
            cred2 = manager2._credentials['microsoft-outlook']

            # Access client to trigger creation
            client2 = cred2.manager.client

            # Assert new MSAL app instance created for each load
            assert client1 is mock_app1
            assert client2 is mock_app2
            assert client1 is not client2

    def test_msal_migration_idempotent(self, tempdir: Path):
        """Test migration flag stays True after multiple refreshes."""
        creds_file = tempdir / 'credentials.json'
        test_data = [
            {
                'type': 'microsoft-outlook',
                'account': 'eservice',
                'client_id': 'client',
                'client_secret': 'secret',
                'token_type': 'bearer',
                'scope': 'Mail.Read offline_access',
                'access_token': 'token',
                'refresh_token': 'refresh',
                'expires_at': (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
                'msal_migrated': False,
            },
        ]

        with creds_file.open('wb') as f:
            f.write(orjson.dumps(test_data))

        mock_account = {'username': 'user@example.com'}
        mock_msal_result = {
            'access_token': 'new_token',
            'token_type': 'bearer',
            'scope': ['Mail.Read', 'offline_access'],
            'expires_in': 3600,
        }

        with patch('automate.eserv.util.msal_manager.ConfidentialClientApplication') as MockMSAL:
            mock_app = Mock()
            mock_app.acquire_token_by_refresh_token.return_value = mock_msal_result
            mock_app.get_accounts.return_value = [mock_account]
            mock_app.acquire_token_silent.return_value = mock_msal_result
            MockMSAL.return_value = mock_app

            manager = CredentialManager(creds_file)

            # First refresh (migration)
            cred1 = manager.get_credential('microsoft-outlook')
            assert cred1['msal_migrated'] is True

            # Force second refresh by manually updating the credential expiry
            cred1_dict = cred1.export()
            cred1_dict['expires_at'] = (datetime.now(UTC) - timedelta(hours=1)).isoformat()

            # Reload from JSON to get expired credential with same structure
            from automate.eserv.util.oauth_manager import _parse_credential_json

            with patch(
                'automate.eserv.util.msal_manager.ConfidentialClientApplication',
                return_value=mock_app,
            ):
                manager._credentials['microsoft-outlook'] = _parse_credential_json(cred1_dict)

            # Second refresh (normal mode)
            cred2 = manager.get_credential('microsoft-outlook')
            assert cred2['msal_migrated'] is True  # Still True

    def test_dual_mode_dropbox_unaffected(self, tempdir: Path):
        """Test Dropbox credentials unaffected by MSAL integration."""
        creds_file = tempdir / 'credentials.json'
        test_data = [
            {
                'type': 'dropbox',
                'account': 'business',
                'client_id': 'dbx_client',
                'client_secret': 'dbx_secret',
                'token_type': 'bearer',
                'scope': 'files.content.write',
                'access_token': 'old_token',
                'refresh_token': 'refresh',
                'expires_at': (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
            },
            {
                'type': 'microsoft-outlook',
                'account': 'eservice',
                'client_id': 'outlook_client',
                'client_secret': 'outlook_secret',
                'token_type': 'bearer',
                'scope': 'Mail.Read offline_access',
                'access_token': 'outlook_token',
                'refresh_token': 'outlook_refresh',
                'expires_at': (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
            },
        ]

        with creds_file.open('wb') as f:
            f.write(orjson.dumps(test_data))

        # Mock Dropbox client
        mock_dbx = Mock()
        mock_dbx._oauth2_access_token = 'new_dbx_token'
        mock_dbx._oauth2_refresh_token = 'refresh'
        mock_dbx._oauth2_access_token_expiration = datetime.now(UTC) + timedelta(hours=4)
        mock_dbx._scope = ['files.content.write']
        mock_dbx.check_and_refresh_access_token.return_value = None

        # Mock MSAL app
        mock_msal_app = Mock()
        msal_result = {
            'access_token': 'new_outlook_token',
            'token_type': 'bearer',
            'scope': ['Mail.Read', 'offline_access'],
            'expires_in': 3600,
        }
        mock_msal_app.get_accounts.return_value = []
        mock_msal_app.acquire_token_by_refresh_token.return_value = msal_result

        with (
            patch('dropbox.Dropbox', return_value=mock_dbx),
            patch(
                'automate.eserv.util.msal_manager.ConfidentialClientApplication',
                return_value=mock_msal_app,
            ),
        ):
            manager = CredentialManager(creds_file)

            # Refresh Dropbox credential
            dbx_cred = manager.get_credential('dropbox')

            # Assert Dropbox uses SDK refresh (not MSAL)
            mock_dbx.check_and_refresh_access_token.assert_called_once()
            assert dbx_cred['msal_migrated'] is None  # Default value
            assert dbx_cred.access_token == 'new_dbx_token'

            # Refresh Outlook credential
            outlook_cred = manager.get_credential('microsoft-outlook')

            # Assert Outlook uses MSAL
            mock_msal_app.acquire_token_by_refresh_token.assert_called_once()
            assert outlook_cred.manager.client is not None
            assert outlook_cred['msal_migrated'] is True
            assert outlook_cred.access_token == 'new_outlook_token'


class TestCertificateAuthentication:
    """Test certificate-based authentication fallback."""

    def test_certificate_auth_returns_token_data(self, microsoft_credential):
        """Certificate auth should return token data dict, not mutate credential."""
        manager = msauth_manager_factory(microsoft_credential)

        with patch.object(manager.client, 'acquire_token_for_client') as mock_acquire:
            mock_acquire.return_value = {
                'access_token': 'cert_token',
                'expires_in': 3600,
                'token_type': 'Bearer',
            }

            token_data = manager._authenticate_with_certificate()

            assert token_data['access_token'] == 'cert_token'
            assert token_data['expires_in'] == 3600
            # Credential should NOT be mutated
            assert manager.credential.access_token == 'old_outlook_token'

    def test_certificate_auth_fallback_on_refresh_failure(self, microsoft_credential):
        """Refresh token failure should trigger certificate auth."""
        manager = msauth_manager_factory(microsoft_credential)

        with (
            patch.object(manager.client, 'acquire_token_by_refresh_token') as mock_rt,
            patch.object(manager.client, 'acquire_token_for_client') as mock_cert,
        ):
            mock_rt.return_value = {'error': 'invalid_grant', 'error_description': 'Bad token'}
            mock_cert.return_value = {'access_token': 'cert_token', 'expires_in': 3600}

            token_data = manager._refresh_token()

            assert token_data['access_token'] == 'cert_token'
            mock_cert.assert_called_once()

    def test_certificate_auth_updates_via_refresh_chain(self, microsoft_credential):
        """Certificate auth token should flow through refresh() → update_from_refresh()."""
        manager = msauth_manager_factory(microsoft_credential)

        with (
            patch.object(manager.client, 'acquire_token_by_refresh_token') as mock_rt,
            patch.object(manager.client, 'acquire_token_for_client') as mock_cert,
            patch.object(manager, '_authenticate_with_certificate') as mock_cert_auth,
        ):
            mock_rt.return_value = {'error': 'invalid_grant', 'error_description': 'Bad token'}
            mock_cert_auth.return_value = {'access_token': 'cert_token', 'expires_in': 3600}

            refreshed_cred = microsoft_credential.refresh()

            assert refreshed_cred.access_token == 'cert_token'
            # Original credential unchanged (immutability)
            assert microsoft_credential.access_token == 'old_outlook_token'
            mock_cert_auth.assert_called_once()


class TestProtocolCompliance:
    """Test that managers implement TokenManager protocol."""

    def test_dropbox_manager_implements_token_manager(self, dropbox_credential):
        """DropboxManager should implement TokenManager protocol."""
        from automate.eserv.types.structs import TokenManager

        manager = dropbox_manager_factory(dropbox_credential)

        assert isinstance(manager, TokenManager)
        assert hasattr(manager, 'credential')
        assert hasattr(manager, '_client')
        assert hasattr(manager, '_refresh_token')
        assert hasattr(manager, 'client')

    def test_microsoft_auth_manager_implements_token_manager(self, microsoft_credential):
        """MicrosoftAuthManager should implement TokenManager protocol."""
        from automate.eserv.types.structs import TokenManager

        manager = msauth_manager_factory(microsoft_credential)

        assert isinstance(manager, TokenManager)
        assert hasattr(manager, 'credential')
        assert hasattr(manager, '_client')
        assert hasattr(manager, '_refresh_token')
        assert hasattr(manager, 'client')

    def test_token_manager_generic_constraint(self, dropbox_credential):
        """OAuthCredential should be parameterized by manager type."""
        manager = dropbox_manager_factory(dropbox_credential)

        # Manager should be bound to credential
        assert dropbox_credential.manager == manager
        assert type(manager).__name__ == 'DropboxManager'


class TestTokenProperty:
    """Test OAuthCredential.token property for Azure SDK compatibility."""

    def test_token_property_returns_access_token_object(self, microsoft_credential):
        """Token property should return AccessToken for Azure SDK."""
        from azure.core.credentials import AccessToken

        token = microsoft_credential.token

        assert isinstance(token, AccessToken)
        assert token.token == microsoft_credential.access_token
        assert token.expires_on == int(microsoft_credential.expires_at.timestamp())

    def test_token_property_with_dropbox_credential(self, dropbox_credential):
        """Token property should work with any credential type."""
        from azure.core.credentials import AccessToken

        token = dropbox_credential.token

        assert isinstance(token, AccessToken)
        assert token.token == dropbox_credential.access_token
        assert token.expires_on == int(dropbox_credential.expires_at.timestamp())


class TestEdgeCases:
    """Test edge cases and error paths."""

    def test_validate_token_data_with_non_dict(self, microsoft_credential):
        """_validate_token_data should raise TypeError for non-dict."""
        manager = msauth_manager_factory(microsoft_credential)

        with pytest.raises(TypeError, match='Expected dict, got str'):
            manager._validate_token_data('not a dict')

    def test_validate_token_data_with_error_response(self, microsoft_credential):
        """_validate_token_data should raise dynamic exception for errors."""
        manager = msauth_manager_factory(microsoft_credential)

        error_response = {
            'error': 'invalid_grant',
            'error_description': 'Token expired',
        }

        with pytest.raises(Exception, match='invalid_grant'):
            manager._validate_token_data(error_response)

    def test_scope_filtering_removes_reserved_scopes(self, microsoft_credential):
        """Scopes property should filter reserved MSAL scopes."""
        cred = replace(
            microsoft_credential,
            scope='Mail.Read offline_access openid profile User.Read',
        )
        manager = msauth_manager_factory(cred)

        # Should exclude offline_access, openid, profile
        assert manager.scopes == ['Mail.Read', 'User.Read']
        assert 'offline_access' not in manager.scopes
        assert 'openid' not in manager.scopes
        assert 'profile' not in manager.scopes

    def test_manager_creation_failure_propagates(self, dropbox_credential):
        """Factory failures should propagate exceptions."""
        with (
            patch(
                'automate.eserv.util.dbx_manager.DropboxManager.__init__',
                side_effect=ValueError('Bad config'),
            ),
            pytest.raises(ValueError, match='Bad config'),
        ):
            dropbox_manager_factory(dropbox_credential)

    def test_refresh_handler_binding(self, dropbox_credential):
        """Handler should be bound method of manager instance."""
        manager = dropbox_manager_factory(dropbox_credential)

        # Handler should be manager._refresh_token
        assert dropbox_credential.handler.__self__ == manager
        assert dropbox_credential.handler.__name__ == '_refresh_token'
