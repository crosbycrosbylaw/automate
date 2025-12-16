"""Test suite for util/config.py configuration management."""

from __future__ import annotations

from typing import Final

from automate.eserv import *
from automate.eserv.types import *
from tests.eserv.conftest import *

MIN_TOKEN_LENGTH: Final[int] = 10


def test_config_from_env(mock_deps: MockDependencies):
    """Test Config.from_env() loads all configuration."""
    mock_env = mock_deps.fs['.env.test']
    config: Config = configure(dotenv_path=mock_env)

    smtp = config.smtp()

    # Verify SMTP config
    assert smtp['server'] == 'smtp.example.com'
    assert smtp['port'] == 587
    assert '@' in smtp['sender']
    assert '@' in smtp['recipient']

    # Verify Dropbox config
    assert (dbx_cred := config.creds.dropbox)
    assert len(dbx_cred.access_token) > MIN_TOKEN_LENGTH

    # Verify Outlook config
    assert (outlook_token := config.creds.msal)
    assert len(outlook_token.access_token) > MIN_TOKEN_LENGTH

    # Verify paths config
    assert config.paths.service.exists()
    assert config.manual_review_folder

    # Verify cache config
    assert config.index_max_age > 0
    assert config.paths.index.parent == config.paths.service

    # Verify email state config
    assert config.paths.state.parent == config.paths.service
