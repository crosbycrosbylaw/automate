from __future__ import annotations

from contextlib import contextmanager
from dataclasses import field
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, TypedDict, Unpack
from unittest.mock import (
    PropertyMock,
    patch,
)

import orjson
import pytest
from pytest_fixture_classes import fixture_class

from automate.eserv import *
from automate.eserv.core import *
from automate.eserv.types import *
from tests import *

if TYPE_CHECKING:
    from collections.abc import Generator


_MockCertFiles = TypedDict(
    '_MockCertFiles',
    {'.': Path, 'private.key': Path},
)
_MockServiceFiles = TypedDict(
    '_MockServiceFiles',
    {'.': Path, 'state.json': Path, 'index.json': Path, 'errors.json': Path},
)
MockFiles = TypedDict(
    'MockFiles',
    {
        '.': Path,
        '.env.test': Path,
        'credentials.json': Path,
        'cert': _MockCertFiles,
        'service': _MockServiceFiles,
    },
)


def _mock_expiration() -> str:
    return (datetime.now(UTC) + timedelta(hours=4)).isoformat()


class PartialPatches(TypedDict, total=False):
    configure: Mocked[Config]
    get_state_tracker: Mocked[EmailState]
    get_error_tracker: Mocked[ErrorTracker]


class PatchedDependencies(TypedDict):
    configure: Mocked[Config]
    get_state_tracker: Mocked[EmailState]
    get_error_tracker: Mocked[ErrorTracker]


@fixture_class(name='mock_deps')
class MockDependencies:
    """Centralized mock fixture for eserv tests.

    Provides:
        - files: MockFiles with temporary file structure
        - config: Config factory mock (call .return_value for instance)
        - state_tracker: EmailState factory mock
        - error_tracker: ErrorTracker factory mock
        - as_mock(): Navigate mock attributes
    """

    directory: Path

    # File structure
    root: Path = field(init=False)
    cert: Path = field(init=False)
    service: Path = field(init=False)

    environment: dict[str, str] = field(
        init=False,
        default_factory=lambda: {
            'INDEX_CACHE_TTL_HOURS': '4',
            'MONITORING_LOOKBACK_DAYS': '1',
            'MANUAL_REVIEW_FOLDER': '/MANUAL_REVIEW/',
            'MONITORING_FOLDER_PATH': 'Inbox,Test',
            'SMTP_PORT': '587',
            'SMTP_USERNAME': '',
            'SMTP_PASSWORD': '',
            'SMTP_USE_TLS': 'true',
            'SMTP_SERVER': 'smtp.example.com',
            'SMTP_FROM_ADDR': 'test@example.com',
            'SMTP_TO_ADDR': 'test@example.com',
        },
    )

    credentials: list[CredentialsJSON] = field(
        init=False,
        default_factory=lambda: [
            {
                'type': 'dropbox',
                'account': 'test@example.com',
                'client_id': 'test-dropbox-client-id',
                'client_secret': 'test-dropbox-client-secret',
                'access_token': 'test-dropbox-access-token',
                'token_type': 'bearer',
                'expires_at': f'{_mock_expiration}',
                'refresh_token': 'test-dropbox-refresh-token',
                'scope': 'account_info.read files.content.read files.content.write files.metadata.read',
            },
            {
                'type': 'msal',
                'account': 'test@example.com',
                'client_id': 'test-msal-client-id',
                'client_secret': 'test-msal-client-secret',
                'token_type': 'Bearer',
                'scope': 'Mail.ReadWrite openid profile email',
                'expires_at': f'{_mock_expiration}',
                'access_token': 'test-msal-access-token',
                'refresh_token': 'test-msal-refresh-token',
            },
        ],
    )

    # Cached mock instances
    _files: MockFiles = field(init=False)
    _creds: Mocked[CredentialsConfig] = field(init=False)
    _paths: Mocked[PathsConfig] = field(init=False)
    _configure: Mocked[Config] = field(init=False)
    _get_state_tracker: Mocked[EmailState] = field(init=False)
    _get_error_tracker: Mocked[ErrorTracker] = field(init=False)

    def __post_init__(self) -> None:
        """Initialize mock file structure and environment."""
        object.__setattr__(self, 'root', self.directory.resolve(strict=True))
        object.__setattr__(self, 'service', self.root / 'service')
        object.__setattr__(self, 'cert', self.root / 'cert')

        for d in self.root, self.service, self.cert:
            d.mkdir(parents=True, exist_ok=True)

        for f in [
            credentials_json := self.root / 'credentials.json',
            state_json := self.service / 'state.json',
            index_json := self.service / 'index.json',
            errors_json := self.service / 'errors.json',
            dotenv_test := self.root / '.env.test',
            private_key := self.cert / 'private.key',
        ]:
            f.touch(exist_ok=True)

        self.environment['PROJECT_ROOT'] = str(self.root)
        self.environment['SERVICE_DIR'] = str(self.service)
        self.environment['CREDENTIALS_FILE'] = str(credentials_json)
        self.environment['CERT_PRIVATE_KEY_FILE'] = str(private_key)

        credentials_json.write_bytes(orjson.dumps(self.credentials, option=orjson.OPT_APPEND_NEWLINE))
        dotenv_test.write_text('\n' + '\n'.join(f'{k}={v}' for k, v in self.environment.items()) + '\n')

        # Cache files structure
        object.__setattr__(
            self,
            '_files',
            {
                '.': self.root,
                '.env.test': dotenv_test,
                'credentials.json': credentials_json,
                'cert': {
                    '.': self.cert,
                    'private.key': private_key,
                },
                'service': {
                    '.': self.service,
                    'state.json': state_json,
                    'index.json': index_json,
                    'errors.json': errors_json,
                },
            },
        )

        # Load environment for test
        import dotenv

        dotenv.load_dotenv(dotenv_test)

    @property
    def fs(self) -> MockFiles:
        """Get the mock file structure."""
        return self._files

    @property
    def paths(self) -> Mocked[PathsConfig]:
        if not hasattr(self, '_paths'):
            namespace: dict[str, Path] = {
                'root': self.fs['.'],
                'credentials': self.fs['credentials.json'],
                'private_key': self.fs['cert']['private.key'],
                'service': self.fs['service']['.'],
                'index': self.fs['service']['index.json'],
                'state': self.fs['service']['state.json'],
                'errors': self.fs['service']['errors.json'],
            }
            object.__setattr__(self, '_paths', mock(PathsConfig, namespace))

        return self._paths

    def convert_creds(self) -> dict[str, PropertyMock]:
        dbx_json, msal_json = self.credentials
        return {
            'dropbox': PropertyMock(return_value=parse_credential_json(dbx_json)),
            'msal': PropertyMock(return_value=parse_credential_json(msal_json)),
        }

    @property
    def creds(self) -> Mocked[CredentialsConfig]:
        if not hasattr(self, '_creds'):
            namespace: dict[str, Any] = {'_path': self.fs['credentials.json'], **self.convert_creds()}
            object.__setattr__(self, '_creds', mock(CredentialsConfig, namespace))

        return self._creds

    @property
    def configure(self) -> Mocked[Config]:
        """Return the Config factory (callable mock that returns the config instance)."""
        if not hasattr(self, '_configure'):
            namespace = {'paths': self.paths(), 'creds': self.creds()}
            object.__setattr__(self, '_configure', mock(Config, namespace))

        return self._configure

    @property
    def get_state_tracker(self) -> Mocked[EmailState]:
        """Return the EmailState factory (callable mock that returns the state tracker instance)."""
        if not hasattr(self, '_get_state_tracker'):
            namespace = {
                'path': self.fs['service']['state.json'],
                'is_processed.return_value': False,
                'processed': set[str](),
            }
            object.__setattr__(self, '_get_state_tracker', mock(EmailState, namespace))

        return self._get_state_tracker

    @property
    def get_error_tracker(self) -> Mocked[ErrorTracker]:
        """Return the ErrorTracker factory (callable mock that returns the error tracker instance)."""
        if not hasattr(self, '_get_error_tracker'):
            errors: list[ErrorDict] = []

            def mock_error(event: str | None = None, **kwds: Any) -> IntermediaryResult:

                stage = kwds.get('stage')
                exception = kwds.get('exception')
                result = kwds.get('result')
                context = kwds.get('context')

                if exception and hasattr(exception, 'entry'):
                    error_entry = exception.entry()

                else:
                    error_entry: ErrorDict = {
                        'uid': kwds.get('uid', 'test-uid'),
                        'category': getattr(stage, 'value', 'unknown'),
                        'message': f'{event or exception or "Something went wrong"}',
                        'timestamp': datetime.now(UTC).isoformat(),
                    }

                    if context := kwds.get('context'):
                        error_entry['context'] = context

                errors.append(error_entry)

                if result:
                    raise PipelineError.from_stage(stage, message=event, context=context)

                return IntermediaryResult(status=status.ERROR)

            def mock_prev() -> ErrorDict | None:
                try:
                    value = errors[-1]
                except IndexError:
                    value = None
                else:
                    return value

            # Based on ErrorTracker API: has .path attribute (not .file)

            @contextmanager
            def mock_track(uid: str | None = None) -> Generator[ErrorTracker]:

                def mock_prev() -> ErrorDict | None:
                    return next((e for e in reversed(errors) if e.get('uid') == uid), None)

                subtracker = self.get_error_tracker.new(**{
                    'path': self.fs['service']['errors.json'],
                    'uid': uid,
                    'error.side_effect': partial(mock_error, uid=uid),
                    'prev_error': PropertyMock(side_effect=mock_prev),
                })

                try:
                    yield subtracker
                finally:
                    pass

            namespace = {
                'path': self.fs['service']['errors.json'],
                'prev_error': PropertyMock(side_effect=mock_prev),
                'warning.return_value': None,
                'error.side_effect': mock_error,
                'clear_old_errors.return_value': None,
                'track.side_effect': mock_track,
            }
            object.__setattr__(self, '_get_error_tracker', mock(ErrorTracker, namespace))

        return self._get_error_tracker

    @contextmanager
    def __call__(
        self,
        target: str = 'automate.eserv.core',
        **kwds: Unpack[PartialPatches],
    ) -> Generator[PatchedDependencies]:
        patches: PatchedDependencies = {
            'configure': kwds.pop('configure', self.configure),
            'get_state_tracker': kwds.pop('get_state_tracker', self.get_state_tracker),
            'get_error_tracker': kwds.pop('get_error_tracker', self.get_error_tracker),
        }
        with patch.multiple(target=target, **patches):
            yield patches


@pytest.fixture(name='mock_core')
def mock_core_fixture(mock_deps: MockDependencies) -> Generator[PatchedDependencies]:
    """Fixture that applies core module patches.

    This fixture:
    1. Applies patches to automate.eserv.core module
    2. Returns the patched dependencies for assertions
    3. Cleans up patches after test

    Note: Environment is already loaded by MockDependencies.__post_init__
    """
    with mock_deps() as patches:
        yield patches
