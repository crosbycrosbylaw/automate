"""Test suite for util/config.py configuration management."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest

from automate import eserv

if TYPE_CHECKING:
    from pathlib import Path

MIN_TOKEN_LENGTH: Final[int] = 10


@pytest.fixture
def test_env_file(tmp_path: Path):
    """Create test .env file with all required config."""
    creds_file = tmp_path / 'credentials.json'
    creds_file.write_text(
        """[
        {
            "type": "dropbox",
            "account": "test",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "token_type": "bearer",
            "scope": "files.content.write",
            "access_token": "test_dropbox_token_12345678901",
            "refresh_token": "refresh_token"
        },
        {
            "type": "msal",
            "account": "test",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "token_type": "bearer",
            "scope": "Mail.Read",
            "access_token": "test_outlook_token_12345678901",
            "refresh_token": "refresh_token"
        }
    ]""",
    )

    env_file = tmp_path / '.env'
    env_file.write_text(
        f"""CREDENTIALS_PATH={creds_file}
SMTP_SERVER=smtp.example.com
SMTP_PORT=587
SMTP_FROM_ADDR=from@example.com
SMTP_TO_ADDR=to@example.com
SMTP_USERNAME=user@example.com
SMTP_PASSWORD=password
SMTP_USE_TLS=true
MANUAL_REVIEW_FOLDER=/Manual Review
SERVICE_DIR={tmp_path}
INDEX_CACHE_TTL_HOURS=4
""",
    )
    return env_file


def test_config_from_env(test_env_file):
    """Test Config.from_env() loads all configuration."""
    config = eserv.configure(test_env_file)

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
