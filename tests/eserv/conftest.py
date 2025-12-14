from __future__ import annotations

import typing

import pytest
from pytest_fixture_classes import fixture_class
from rampy import test

from tests.eserv.lib import SAMPLE_EMAIL

if typing.TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path

    from automate.eserv.types import EmailRecord

from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import Mock

from automate.eserv import *
from automate.eserv.core import *
from automate.eserv.types import *

type Mocked[T] = Mock | T

directory = test.directory

MOCK_ENV = """
SERVICE_DIR=.service
CREDENTIALS_FILE=credentials.json
STATE_FILE=state.json
INDEX_FILE=index.json
MONITORING_LOOKBACK_DAYS=1
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_USE_TLS=true
INDEX_CACHE_TTL_HOURS=4
MANUAL_REVIEW_FOLDER=/MANUAL_REVIEW/
PROJECT_ROOT=./
SMTP_SERVER=smtp.example.com
SMTP_FROM_ADDR=test@example.com
SMTP_TO_ADDR=test@example.com
MONITORING_FOLDER_PATH=Inbox,File Handling - All,Filing Accepted / Notification of Service / Courtesy Copy
CERT_PRIVATE_KEY_PATH=
"""


def _make_mock_credentials() -> str:
    from datetime import UTC, datetime, timedelta

    future_time = (datetime.now(UTC) + timedelta(hours=4)).isoformat()

    return f"""[
    {{
        "type": "dropbox",
        "account": "test@example.com",
        "client_id": "test-dropbox-client-id",
        "client_secret": "test-dropbox-client-secret",
        "access_token": "test-dropbox-access-token",
        "token_type": "bearer",
        "expires_at": "{future_time}",
        "refresh_token": "test-dropbox-refresh-token",
        "scope": "account_info.read files.content.read files.content.write files.metadata.read"
    }},
    {{
        "type": "msal",
        "account": "test@example.com",
        "client_id": "test-msal-client-id",
        "client_secret": "test-msal-client-secret",
        "token_type": "Bearer",
        "scope": "Mail.ReadWrite openid profile email",
        "expires_at": "{future_time}",
        "access_token": "test-msal-access-token",
        "refresh_token": "test-msal-refresh-token"
    }}
]
"""


MOCK_CREDENTIALS = _make_mock_credentials()


@pytest.fixture
def mock_dotenv_path(directory) -> Path:
    """Create mock .env file path."""
    env_path = directory / '.env'
    env_path.write_text(MOCK_ENV)
    return env_path


@pytest.fixture
def mock_paths(directory: Path, mock_dotenv_path: Path) -> Mocked[PathsConfig]:
    mock_paths = Mock(spec=PathsConfig)

    @property
    def private_key(self) -> Path:
        raise MissingVariableError('CERT_PRIVATE_KEY_PATH')

    mock_paths.configure_mock(
        _env_path=mock_dotenv_path,
        _env_status=EnvStatus.SUCCESS,
        env_path=Mock(return_value=mock_dotenv_path),
        root=directory,
        service=(svc := directory / '.service'),
        credentials=(creds := directory / 'credentials.json'),
        state=(state := svc / 'state.json'),
        error_log=(error := svc / 'error_log.json'),
        private_key=private_key,
    )

    svc.mkdir(parents=True, exist_ok=True)

    creds.touch(exist_ok=True)
    creds.write_text(_make_mock_credentials())

    state.touch(exist_ok=True)
    error.touch(exist_ok=True)

    return mock_paths


@pytest.fixture
def mock_creds(mock_paths: Mocked[PathsConfig]) -> Mocked[CredentialsConfig]:
    mock_creds = Mock(spec=CredentialsConfig)

    import orjson

    mapping = {
        item[0]: item[1]
        for x in orjson.loads(mock_paths.credentials.read_bytes())
        if (item := parse_credential_json(x))
    }

    def _refresh(cred: OAuthCredential[Any]) -> OAuthCredential[Any]:
        return replace(cred, expires_at=datetime.now(UTC) + timedelta(hours=4))

    def __getattr__(name: str):
        cred = mapping[name]
        return cred if not cred.outdated else _refresh(cred)

    mock_creds.configure_mock(
        path=mock_paths.credentials,
        _mapping=mapping,
        __getitem__=Mock(wraps=mapping.__getitem__),
        __setitem__=Mock(wraps=mapping.__setitem__),
        dropbox=mapping['dropbox'],
        msal=mapping['msal'],
        _refresh=Mock(wraps=_refresh),
        persist=Mock(return_value=None),
    )

    return mock_creds


@pytest.fixture
def mock_config(
    mock_dotenv_path: Path,
    mock_paths: PathsConfig,
    mock_creds: CredentialsConfig,
) -> Mocked[Config]:
    import dotenv

    dotenv.load_dotenv(mock_dotenv_path)

    from automate.eserv.config.main import BaseFields, MonitoringFields, SMTPFields

    base_fields = BaseFields()
    monitoring_fields = MonitoringFields()
    smtp_fields = SMTPFields()

    configuration = {
        'paths': mock_paths,
        'creds': mock_creds,
    }

    for obj in base_fields, monitoring_fields, smtp_fields:
        configuration.update(asdict(obj))

    mock_config = Mock(spec=Config)
    mock_config.configure_mock(**configuration)

    return mock_config


@pytest.fixture
def record() -> EmailRecord:
    from automate.eserv.util.email_record import make_email_record

    return make_email_record(SAMPLE_EMAIL)


@fixture_class(name='setup_files')
class SetupFilesFixture:
    directory: Path

    def __call__(self, registry: Mapping[str, bytes]) -> Sequence[Path]:
        out: list[Path] = []

        for name, content in registry.items():
            path = self.directory / name
            path.write_bytes(content)

            out.append(path)

        return out
