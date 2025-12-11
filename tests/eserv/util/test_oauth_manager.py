"""Test suite for util/oauth_manager.py OAuth credential management."""

from __future__ import annotations

import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import NoneType
from typing import TYPE_CHECKING, Any, Literal, TypedDict, Unpack
from unittest.mock import Mock, patch

import orjson
import pytest
from msal import ConfidentialClientApplication

from automate.eserv import *
from automate.eserv.types import *
from automate.eserv.util.msal_manager import _validate_token_data

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


def _refresh_outlook_msal(cred: OAuthCredential[MSALManager]) -> dict[str, Any]:
    return cred.manager._refresh_token()


@pytest.fixture
def dropbox_credential():
    return OAuthCredential(
        factory=DropboxManager,
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
    return make_ms_cred(
        account='test-account',
        client_id='outlook_client_id',
        client_secret='outlook_client_secret',
        token_type='bearer',
        scope='Mail.Read offline_access',
        access_token='old_outlook_token',
        refresh_token='outlook_refresh_token',
        expires_at=datetime.now(UTC) - timedelta(hours=1),  # Expired
        properties={'msal_migrated': False},
    )


class TokenManagerClientConfig(TypedDict, total=False):
    access_token: str
    refresh_token: str
    expires_at: datetime
    expires_in: int
    scopes: list[str]

    error_result: dict[str, str]

    side_effect: Any
    refresh: bool


type _MSALRefreshMethodDescriptor = Literal['silent', 'refresh_token', 'certificate']


def msal_refresh_test_case(
    cred: OAuthCredential[Any],
    accounts: Sequence[Any] = (),
    refresh_method: _MSALRefreshMethodDescriptor = 'silent',
    acquire_mocks: dict[
        Literal[
            'acquire_token_silent',
            'acquire_token_by_refresh_token',
            'acquire_token_for_client',
        ],
        Mock,
    ]
    | None = None,
    **config: Unpack[TokenManagerClientConfig],
) -> Mock:

    error_data = config.get('error_result')

    response_data = {
        'access_token': config.get('access_token', 'microsoft_token'),
        'refresh_token': config.get('access_token', 'refresh_token'),
        'token_type': 'bearer',
        'scope': config.get('scopes', ['.default']),
        'expires_in': config.get('expires_in', 3600),
    }

    def acquire_token():
        if se := config.get('side_effect'):
            raise se
        return error_data or response_data

    mock_acquire_token = Mock(wraps=acquire_token)

    mock_client = Mock(spec=ConfidentialClientApplication)
    mock_client.configure_mock(**{'get_accounts.return_value': accounts})

    match refresh_method:
        case 'silent':
            selected = 'acquire_token_silent'
        case 'refresh_token':
            selected = 'acquire_token_by_refresh_token'
        case 'certificate':
            selected = 'acquire_token_for_client'

    remaining: set[str] = {
        'acquire_token_silent',
        'acquire_token_by_refresh_token',
        'acquire_token_for_client',
    } - {selected}

    mock_client.configure_mock(
        **{selected: mock_acquire_token},
        **dict.fromkeys(remaining, Mock(return_value=None)),
    )

    expected_data = parse_credential_json(response_data)[1].export()

    with patch(
        target='automate.eserv.util.msal_manager.ConfidentialClientApplication',
        new=Mock(return_value=mock_client),
    ):
        if config.get('refresh') is False:
            mock_acquire_token.assert_not_called()

        elif error_data is not None:
            with pytest.raises(match=error_data.get('error_description', 'Token refresh was unsuccessful')):
                result = cred.refresh()

        else:
            started_at = time.time()
            result = cred.refresh()

            mock_acquire_token.assert_called_once()

            if 'error_result' not in config:
                for x in str(result), result.access_token:
                    assert x == expected_data['access_token']

                assert result.refresh_token == expected_data['refresh_token']
                assert result.scope == expected_data['scope']

                assert result.expires_at is not None

                if 'expires_in' in expected_data:
                    seconds = expected_data['expires_in'] - int(started_at - time.time())
                    expected_data['expires_at'] = datetime.now(UTC) + timedelta(seconds=seconds)

                    ms = expected_data['expires_at'].microsecond
                    result.expires_at = result._resolve_expiration().replace(microsecond=ms)

                if 'expires_at' in expected_data:
                    assert result.expires_at == expected_data['expires_at']

    return mock_client


def dbx_refresh_test_case(
    cred: OAuthCredential[Any],
    **config: Unpack[TokenManagerClientConfig],
) -> Mock:
    mock_client = Mock(
        spec=[
            '_oauth2_access_token',
            '_oauth2_refresh_token',
            '_oauth2_access_token_expiration',
            '_scope',
            'check_and_refresh_access_token',
        ]
    )

    mock_check_and_refresh = Mock(return_value=None, side_effect=config.get('side_effect'))

    mock_client.configure_mock(
        _oauth2_access_token=config.get('access_token', 'dropbox_token'),
        _oauth2_refresh_token=config.get('refresh_token', 'refresh_token'),
        _oauth2_access_token_expiration=config.get('expires_at', datetime.now(UTC) + timedelta(hours=4)),
        _scope=config.get('scopes', ['files.content.write', 'files.metadata.read']),
        check_and_refresh_access_token=mock_check_and_refresh,
    )

    with patch('dropbox.Dropbox', Mock(return_value=mock_client)):
        if not config.get('refresh', True):
            mock_check_and_refresh.assert_not_called()

        else:
            result = cred.refresh()

            mock_check_and_refresh.assert_called_once()

            # Assert returned data has correct structure
            assert result.access_token == mock_client._oauth2_access_token
            assert result.refresh_token == mock_client._oauth2_refresh_token
            assert result.expires_at == mock_client._oauth2_access_token_expiration
            assert result.scope.split() == mock_client._scope

    return mock_client


class TestTokenRefresh:
    """Test unified refresh mechanism for both Dropbox and Outlook."""

    def test_refresh_dropbox_success(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
    ):
        """Test successful Dropbox token refresh."""
        dbx_refresh_test_case(
            dropbox_credential,
            access_token='new_dropbox_token',
            refresh_token='new_refresh_token',
            scopes=['files.content.write', 'files.metadata.read'],
            expires_at=datetime.now(UTC) + timedelta(hours=4),
        )

    def test_refresh_outlook_msal_success(
        self,
        microsoft_credential: OAuthCredential[MSALManager],
    ):
        """Test successful Outlook token refresh using MSAL (migration mode)."""
        microsoft_credential['msal_migrated'] = False

        mock_client = msal_refresh_test_case(
            microsoft_credential,
            accounts=[],
            refresh_method='refresh_token',
            access_token='new_outlook_token',
            refresh_token='new_refresh_token',
            scopes=['Mail.Read', 'offline_access'],
            expires_in=3600,
        )

        mock_client.acquire_token_by_refresh_token.assert_called_once_with(
            refresh_token=microsoft_credential.refresh_token,
            scopes=['Mail.Read'],
        )

    def test_refresh_dropbox_connection_error(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
    ):
        """Test refresh handles network errors gracefully."""
        with pytest.raises(ConnectionError, match='Network unreachable'):
            dbx_refresh_test_case(
                cred=dropbox_credential,
                side_effect=ConnectionError('Network unreachable'),
            )

    def test_refresh_dropbox_auth_error(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
    ):
        from dropbox.exceptions import AuthError

        with pytest.raises(AuthError):
            dbx_refresh_test_case(
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

        with patch.object((cred := dropbox_credential).manager, '_refresh_token', mock_handler):
            refreshed = cred.refresh()

            # Assert new credential returned
            assert refreshed.access_token == 'new_token'
            assert refreshed.expiration() > datetime.now(UTC)

    def test_refresh_without_manager_factory_raises_error(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
    ):
        """Test that refresh without manager factory raises ValueError."""
        with pytest.raises(TypeError, match=f'expected {TokenManager}; received {NoneType}'):
            replace(dropbox_credential, manager_factory=Mock(return_value=None))


class TestCredentialUpdate:
    """Test credential update logic."""

    def test_reconstruct_with_expires_in(
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

        updated = original.reconstruct(token_data)

        # Assert new credential returned with correct values
        assert updated.access_token == 'new_token'
        assert updated.refresh_token == 'new_refresh'

        _ = updated.expiration()

        assert updated.expiration() > datetime.now(UTC)
        assert updated.expiration() < datetime.now(UTC) + timedelta(hours=2)

        # Assert original unchanged (immutable pattern)
        assert original.access_token == 'old_token'
        assert original.refresh_token == 'old_refresh'

    def test_reconstruct_with_expires_at(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
    ):
        """Test updating credential with expires_at timestamp."""
        future_time = datetime.now(UTC) + timedelta(hours=2)
        expected: dict[str, Any] = {
            'access_token': 'new_token',
            'expires_at': future_time.isoformat(),
        }

        updated = dropbox_credential.reconstruct(expected.copy())

        assert updated.access_token == expected['access_token']
        assert updated.expires_at is not None
        assert updated.expiration().isoformat() == expected['expires_at']

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

        updated = original.reconstruct(token_data)

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

        updated = original.reconstruct(token_data)

        assert updated.access_token == token_data['access_token']
        assert updated.scope == token_data['scope']
        assert updated.refresh_token == original.refresh_token

    def test_update_immutability(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
    ):
        """Test that reconstruct follows immutable pattern."""
        original = replace(dropbox_credential, access_token='token1')

        # Multiple updates should create new instances
        updated1 = original.reconstruct({'access_token': 'token2', 'expires_in': 3600})
        updated2 = updated1.reconstruct({'access_token': 'token3', 'expires_in': 3600})

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
        manager = DropboxManager(cred)

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

        manager = DropboxManager(cred)

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

        manager = DropboxManager(cred)

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

        assert cred.expires_at is not None
        assert exported['expires_at'] == cred.expiration().isoformat()

        # Assert no nested dicts
        assert 'client' not in exported
        assert 'data' not in exported

    def test_export_without_expires_at(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
    ):
        """Test export handles missing expires_at."""
        cred = replace(dropbox_credential, expires_at=None)

        exported = cred.export()

        assert 'expires_at' in exported
        assert exported['expires_at'] is None


class TestCredentialsConfig:
    """Test credential manager loading and expiry checking."""

    def test_load_credentials_flat_format(self, directory: Path):
        """Test loading credentials from flat JSON format."""
        # Create test credentials file with flat format
        creds_file = directory / 'credentials.json'
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
        manager = CredentialsConfig(creds_file)

        # Assert credential loaded correctly
        cred = manager.dropbox
        assert cred.type == 'dropbox'
        assert cred.account == 'business'
        assert cred.client_id == 'dbx_client'
        assert cred.client_secret == 'dbx_secret'
        assert cred.access_token == 'dbx_access'
        assert cred.refresh_token == 'dbx_refresh'
        assert cred.manager is not None

    def test_get_credential_refreshes_when_expired(
        self,
        directory: Path,
    ):
        """Test that get_credential auto-refreshes expired tokens."""
        # Create credentials with past expiry (flat format)
        creds_file = directory / 'credentials.json'
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

        manager = CredentialsConfig(creds_file)
        dbx_refresh_test_case(manager.dropbox, access_token='new_token')

    def test_get_credential_no_refresh_when_valid(self, directory: Path):
        """Test that get_credential doesn't refresh valid tokens."""
        creds_file = directory / 'credentials.json'

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

        manager = CredentialsConfig(creds_file)
        dbx_refresh_test_case(cred := manager.dropbox, refresh=False)
        assert cred.access_token == 'valid_token'

    def test_persist_saves_flat_format(self, directory: Path):
        """Test that persist() saves credentials in flat format."""
        # Create initial credentials (flat format)
        creds_file = directory / 'credentials.json'
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
            manager = CredentialsConfig(creds_file)

            # Simulate token refresh by manually updating credential
            cred = manager['dropbox']
            updated_cred = replace(cred, access_token='new_token')
            manager['dropbox'] = updated_cred

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

    def test_msal_app_initialization(
        self,
        dropbox_credential: OAuthCredential[DropboxManager],
        microsoft_credential: OAuthCredential[MSALManager],
        directory: Path,
    ):
        """Test MSAL app created for Outlook credentials on load."""
        creds_file = directory / 'credentials.json'

        test_data = [microsoft_credential.export(), dropbox_credential.export()]

        with creds_file.open('wb') as f:
            f.write(orjson.dumps(test_data))

        with (
            patch('os.environ', {}),
            patch('automate.eserv.util.msal_manager.ConfidentialClientApplication') as MockMSAL,
            patch('dropbox.Dropbox'),
        ):
            manager = CredentialsConfig(creds_file)

            ms_cred = manager.msal
            mock_ms_app = msal_refresh_test_case(ms_cred, refresh=False)
            MockMSAL.return_value = mock_ms_app

            _ = ms_cred.manager.client

            MockMSAL.assert_called_once_with(
                client_id=ms_cred.client_id,
                client_credential=ms_cred.client_secret,
                authority=ms_cred['authority'],
            )

            assert ms_cred.manager.client is mock_ms_app
            assert manager.dropbox.manager.client is not mock_ms_app

    def test_msal_migration_first_refresh(
        self,
        microsoft_credential: OAuthCredential[MSALManager],
        directory: Path,
    ):
        """Test migration flag changes after first refresh."""
        # Create unmigrated Outlook credential
        creds_file = directory / 'credentials.json'
        test_data = [microsoft_credential.export()]

        with creds_file.open('wb') as f:
            f.write(orjson.dumps(test_data))

        manager = CredentialsConfig(creds_file)

        msal_refresh_test_case(
            manager.msal,
            accounts=[],
            access_token='new_token',
            refresh_token='new_refresh',
            scopes=['Mail.Read', 'offline_access'],
            expires_in=3600,
            refresh=False,
        )

        # Get credential (triggers refresh)
        cred = manager.msal

        assert cred['msal_migrated'] is True

        with creds_file.open('rb') as f:
            saved_data = orjson.loads(f.read())

        assert saved_data[0]['msal_migrated'] is True

    def test_msal_silent_refresh_after_migration(
        self,
        microsoft_credential: OAuthCredential[MSALManager],
        directory: Path,
    ):
        """Test silent refresh used after migration."""
        # Create migrated Outlook credential
        creds_file = directory / 'credentials.json'

        microsoft_credential['msal_migrated'] = True

        mock_ms_app = msal_refresh_test_case(
            microsoft_credential,
            accounts=[acct := {'username': 'user@example.com'}],
            access_token='new_token',
            scopes=['Mail.Read', 'offline_access'],
            expires_in=-1,
        )  # refresh with outdated expiry

        test_data = [microsoft_credential.export()]

        with creds_file.open('wb') as f:
            f.write(orjson.dumps(test_data))

        manager = CredentialsConfig(creds_file)

        _ = manager['msal']
        _ = manager.msal

        mock_ms_app.acquire_token_silent.assert_called_once_with(scopes=['Mail.Read'], account=acct)
        mock_ms_app.acquire_token_by_refresh_token.assert_not_called()

    def test_msal_fallback_on_silent_failure(
        self,
        microsoft_credential: OAuthCredential[MSALManager],
    ):
        """Test fallback to refresh token when silent fails."""
        microsoft_credential.properties['msal_migrated'] = True
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
        microsoft_credential: OAuthCredential[MSALManager],
    ):
        """Test fallback when account cache is empty."""
        # Set msal_migrated to True so get_accounts is called
        microsoft_credential['msal_migrated'] = True

        mock_app = msal_refresh_test_case(
            microsoft_credential,
            accounts=[],
            refresh_method='refresh_token',
            access_token='new_token',
            scopes=['Mail.Read', 'offline_access'],
            expires_in=3600,
        )

        mock_app.get_accounts.assert_called_once()

    def test_msal_error_handling(
        self,
        microsoft_credential: OAuthCredential[MSALManager],
    ):
        """Test MSAL error handling."""
        with pytest.raises(Exception, match='Refresh token expired'):
            msal_refresh_test_case(
                microsoft_credential,
                error_result={
                    'error': 'invalid_grant',
                    'error_description': 'Refresh token expired',
                },
            )

    def test_msal_token_normalization(
        self,
        microsoft_credential: OAuthCredential[MSALManager],
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

            # Assert normalized to reconstruct() format
            assert result['access_token'] == 'new_token'
            assert result['refresh_token'] == 'new_refresh'
            assert result['token_type'] == 'Bearer'
            assert result['scope'] == 'Mail.Read offline_access Mail.Send'  # String, not list
            assert result['expires_in'] == 7200

    def test_msal_app_not_serialized(
        self,
        microsoft_credential: OAuthCredential[MSALManager],
    ):
        """Test msal_app excluded from export."""
        cred = microsoft_credential
        cred.properties['msal_migrated'] = True

        exported = cred.export()

        # Assert msal_migrated included
        assert 'msal_migrated' in exported
        assert exported['msal_migrated'] is True

    def test_msal_app_recreated_on_load(self, directory: Path):
        """Test MSAL app recreated on each load."""
        creds_file = directory / 'credentials.json'
        test_data = [
            {
                'type': 'msal',
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
            manager1 = CredentialsConfig(creds_file)
            cred1 = manager1['msal']

            # Access client to trigger creation
            client1 = cred1.manager.client

            # Persist (should not serialize msal_app)
            manager1.persist()

            # Second load
            manager2 = CredentialsConfig(creds_file)

            cred2 = manager2['msal']

            # Access client to trigger creation
            client2 = cred2.manager.client

            # Assert new MSAL app instance created for each load
            assert client1 is mock_app1
            assert client2 is mock_app2
            assert client1 is not client2

    def test_msal_migration_idempotent(self, directory: Path):
        """Test migration flag stays True after multiple refreshes."""
        creds_file = directory / 'credentials.json'
        test_data = [
            {
                'type': 'msal',
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

            manager = CredentialsConfig(creds_file)

            # First refresh (migration)
            cred1 = manager.msal
            assert cred1['msal_migrated'] is True

            # Force second refresh by manually updating the credential expiry
            cred1_dict = cred1.export()
            cred1_dict['expires_at'] = (datetime.now(UTC) - timedelta(hours=1)).isoformat()

            # Reload from JSON to get expired credential with same structure

            with patch(
                'automate.eserv.util.msal_manager.ConfidentialClientApplication',
                return_value=mock_app,
            ):
                manager['msal'] = parse_credential_json(cred1_dict)[1]

            # Second refresh (normal mode)
            cred2 = manager.msal
            assert cred2['msal_migrated'] is True  # Still True

    def test_dual_mode_dropbox_unaffected(self, directory: Path):
        """Test Dropbox credentials unaffected by MSAL integration."""
        creds_file = directory / 'credentials.json'
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
                'type': 'msal',
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
            manager = CredentialsConfig(creds_file)

            # Refresh Dropbox credential
            dbx_cred = manager['dropbox']

            # Assert Dropbox uses SDK refresh (not MSAL)
            mock_dbx.check_and_refresh_access_token.assert_called_once()
            assert dbx_cred['msal_migrated'] is None  # Default value
            assert dbx_cred.access_token == 'new_dbx_token'

            # Refresh Outlook credential
            outlook_cred = manager.msal

            # Assert Outlook uses MSAL
            mock_msal_app.acquire_token_by_refresh_token.assert_called_once()
            assert outlook_cred.manager.client is not None
            assert outlook_cred['msal_migrated'] is True
            assert outlook_cred.access_token == 'new_outlook_token'


class TestCertificateAuthentication:
    """Test certificate-based authentication fallback."""

    def test_certificate_auth_returns_token_data(self, microsoft_credential: MSALCredential):
        """Certificate auth should return token data dict, not mutate credential."""
        manager = microsoft_credential.manager

        with patch.object(manager.client, 'acquire_token_for_client') as mock_acquire:
            mock_acquire.return_value = {
                'access_token': 'cert_token',
                'expires_in': 3600,
                'token_type': 'Bearer',
            }

            token_data = manager._authenticate_with_certificate()

            assert isinstance(token_data, dict)
            assert token_data['access_token'] == 'cert_token'
            assert token_data['expires_in'] == 3600
            # Credential should NOT be mutated
            assert manager.credential.access_token == 'old_outlook_token'

    def test_certificate_auth_fallback_on_refresh_failure(self, microsoft_credential: MSALCredential):
        """Refresh token failure should trigger certificate auth."""
        manager = microsoft_credential.manager

        with (
            patch.object(manager.client, 'acquire_token_by_refresh_token') as mock_rt,
            patch.object(manager.client, 'acquire_token_for_client') as mock_cert,
        ):
            mock_rt.return_value = {'error': 'invalid_grant', 'error_description': 'Bad token'}
            mock_cert.return_value = {'access_token': 'cert_token', 'expires_in': 3600}

            token_data = manager._refresh_token()

            assert token_data['access_token'] == 'cert_token'
            mock_cert.assert_called_once()

    def test_certificate_auth_updates_via_refresh_chain(self, microsoft_credential: MSALCredential):
        """Certificate auth token should flow through refresh() → reconstruct()."""
        manager = microsoft_credential.manager

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

        manager = DropboxManager(dropbox_credential)

        assert isinstance(manager, TokenManager)
        assert hasattr(manager, 'credential')
        assert hasattr(manager, '_client')
        assert hasattr(manager, '_refresh_token')
        assert hasattr(manager, 'client')

    def test_microsoft_auth_manager_implements_token_manager(self, microsoft_credential: MSALCredential):
        """MSALManager should implement TokenManager protocol."""
        from automate.eserv.types.structs import TokenManager

        manager = microsoft_credential.manager

        assert isinstance(manager, TokenManager)
        assert hasattr(manager, 'credential')
        assert hasattr(manager, '_client')
        assert hasattr(manager, '_refresh_token')
        assert hasattr(manager, 'client')

    def test_token_manager_generic_constraint(self, dropbox_credential):
        """OAuthCredential should be parameterized by manager type."""
        manager = DropboxManager(dropbox_credential)

        # Manager should be bound to credential
        assert dropbox_credential.manager == manager
        assert type(manager).__name__ == 'DropboxManager'


class TestTokenProperty:
    """Test OAuthCredential.token property for Azure SDK compatibility."""

    def test_token_property_returns_access_token_object(self, microsoft_credential: MSALCredential):
        """Token property should return AccessToken for Azure SDK."""
        from azure.core.credentials import AccessToken

        token = microsoft_credential()

        assert isinstance(token, AccessToken)
        assert token.token == str(microsoft_credential)
        assert token.expires_on == int(microsoft_credential)

    def test_token_property_with_dropbox_credential(self, dropbox_credential):
        """Token property should work with any credential type."""
        from azure.core.credentials import AccessToken

        token = dropbox_credential.token

        assert isinstance(token, AccessToken)
        assert token.token == dropbox_credential.access_token
        assert token.expires_on == int(dropbox_credential.expires_at.timestamp())


class TestEdgeCases:
    """Test edge cases and error paths."""

    def test_validate_token_data_with_non_dict(self, microsoft_credential: MSALCredential):
        """_validate_token_data should raise TypeError for non-dict."""
        with pytest.raises(TypeError, match='Expected dict, got str'):
            _validate_token_data('not a dict', errors=True)

    def test_validate_token_data_with_error_response(self, microsoft_credential: MSALCredential):
        """_validate_token_data should raise dynamic exception for errors."""
        error_response = {
            'error': 'invalid_grant',
            'error_description': 'Token expired',
        }

        with pytest.raises(
            check=lambda exc: all([
                type(exc).__name__ == 'InvalidGrantError',
                'Token expired' in str(exc),
            ])
        ):
            _validate_token_data(error_response)

    def test_scope_filtering_removes_reserved_scopes(self, microsoft_credential: MSALCredential):
        """Scopes property should filter reserved MSAL scopes."""
        cred = replace(
            microsoft_credential,
            scope='Mail.Read offline_access openid profile User.Read',
        )
        manager = microsoft_credential.manager

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
            DropboxManager(dropbox_credential)
