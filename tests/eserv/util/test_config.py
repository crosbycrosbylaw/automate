"""Test suite for config/main.py configuration management."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final
from unittest.mock import patch

from automate.eserv.config.main import configure

if TYPE_CHECKING:
    from automate.eserv.types import Config
    from tests.eserv.conftest import MockDependencies, PatchedDependencies

MIN_TOKEN_LENGTH: Final[int] = 10


def test_config_from_env(mock_deps: MockDependencies, mock_core: PatchedDependencies):
    """Test Config.from_env() loads all configuration.

    This test validates:
    - SMTP configuration loading
    - Credential management (Dropbox and MSAL)
    - Path configuration
    - Cache settings
    - State tracking configuration
    """
    mock_env = mock_deps.fs['.env.test']

    # Mock the credential expired property to prevent refresh attempts
    with patch(
        'automate.eserv.util.oauth_credential.OAuthCredential.expired',
        new_callable=lambda: property(lambda self: False),
    ):
        config: Config = configure(dotenv_path=mock_env)

        # Verify SMTP config
        assert config.smtp_server == mock_deps.environment['SMTP_SERVER']
        assert config.smtp_port == int(mock_deps.environment['SMTP_PORT'])
        assert '@' in config.smtp_sender
        assert '@' in config.smtp_recipient

        # Verify Dropbox config
        dbx_cred = config.creds.dropbox
        assert dbx_cred is not None
        assert len(dbx_cred.access_token) > MIN_TOKEN_LENGTH

        # Verify Outlook config
        outlook_token = config.creds.msal
        assert outlook_token is not None
        assert len(outlook_token.access_token) > MIN_TOKEN_LENGTH

        # Verify paths config
        assert config.paths.service.exists()
        assert config.manual_review_folder

        # Verify cache config
        assert config.index_max_age > 0
        assert config.paths.index.parent == config.paths.service

        # Verify email state config
        assert config.paths.state.parent == config.paths.service
