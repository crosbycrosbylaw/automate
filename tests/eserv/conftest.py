from __future__ import annotations

from contextlib import contextmanager
from dataclasses import field
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, TypedDict
from unittest.mock import MagicMock, Mock, PropertyMock, create_autospec, patch

import orjson
import pytest
from pytest_fixture_classes import fixture_class
from rampy import test

from automate.eserv import *
from automate.eserv.core import *
from automate.eserv.types import *

if TYPE_CHECKING:
    from collections.abc import Callable, Generator


class _Mocked[T](MagicMock):
    return_value: T

    __call__: Callable[..., T]


type MockType[T] = _Mocked[T]


directory = test.directory


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


class PatchedDependencies(TypedDict):
    configure: MockType[Config]
    get_state_tracker: MockType[EmailState]
    get_error_tracker: MockType[ErrorTracker]


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
                'expires_at': f'{_mock_expiration()}',
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
                'expires_at': f'{_mock_expiration()}',
                'access_token': 'test-msal-access-token',
                'refresh_token': 'test-msal-refresh-token',
            },
        ],
    )

    # Cached mock instances
    _files: MockFiles = field(init=False)
    _configure: MockType[Config] = field(init=False)
    _get_state_tracker: MockType[EmailState] = field(init=False)
    _get_error_tracker: MockType[ErrorTracker] = field(init=False)

    def __post_init__(self) -> None:
        """Initialize mock file structure and environment."""
        object.__setattr__(self, 'root', self.directory.resolve(strict=True))
        object.__setattr__(self, 'service', self.root / 'service')
        object.__setattr__(self, 'cert', self.root / 'cert')

        for d in self.root, self.service, self.cert:
            d.mkdir(parents=True, exist_ok=True)

        creds_json = self.root / 'credentials.json'
        env_test = self.root / '.env.test'

        for f in [creds_json, env_test]:
            f.touch(exist_ok=True)

        self.environment['PROJECT_ROOT'] = str(self.root)
        self.environment['SERVICE_DIR'] = str(self.service)
        self.environment['CREDENTIALS_FILE'] = str(creds_json)

        creds_json.write_bytes(orjson.dumps(self.credentials, option=orjson.OPT_APPEND_NEWLINE))
        env_test.write_text('\n' + '\n'.join(f'{k}={v}' for k, v in self.environment.items()) + '\n')

        # Setup certificate files
        private_key = self.cert / 'private.key'
        private_key.touch(exist_ok=True)
        self.environment['CERT_PRIVATE_KEY_FILE'] = str(private_key)

        # Setup service files
        state_json = self.service / 'state.json'
        index_json = self.service / 'index.json'
        errors_json = self.service / 'errors.json'

        for f in [state_json, index_json, errors_json]:
            f.touch(exist_ok=True)

        self.environment['STATE_FILE'] = str(state_json)
        self.environment['INDEX_FILE'] = str(index_json)

        # Cache files structure
        object.__setattr__(
            self,
            '_files',
            {
                '.': self.root,
                '.env.test': env_test,
                'credentials.json': creds_json,
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

        dotenv.load_dotenv(env_test)

    @property
    def fs(self) -> MockFiles:
        """Get the mock file structure."""
        return self._files

    @property
    def configure(self) -> MockType[Config]:
        """Return the Config factory (callable mock that returns the config instance)."""
        if not hasattr(self, '_configure'):
            mock_config = create_autospec(spec=Config, instance=True)

            # Setup paths mock with all required attributes (based on PathsConfig)
            mock_paths = create_autospec(spec=PathsConfig, instance=True)
            mock_paths.root = self.fs['.']
            mock_paths.credentials = self.fs['credentials.json']
            mock_paths.private_key = self.fs['cert']['private.key']
            mock_paths.service = self.fs['service']['.']
            mock_paths.state = self.fs['service']['state.json']
            mock_paths.index = self.fs['service']['index.json']
            mock_paths.errors = self.fs['service']['errors.json']
            mock_config.paths = mock_paths

            # Setup creds mock
            mock_config.creds = create_autospec(
                spec=CredentialsConfig,
                instance=True,
            )

            # Cache both the factory and the instance
            mock_factory = MagicMock(spec=Config, return_value=mock_config)
            # Allow attribute access on factory to passthrough to instance
            mock_factory.paths = mock_paths
            object.__setattr__(self, '_configure', mock_factory)
        return self._configure

    @property
    def get_state_tracker(self) -> MockType[EmailState]:
        """Return the EmailState factory (callable mock that returns the state tracker instance)."""
        if not hasattr(self, '_get_state_tracker'):
            mock_state_tracker = create_autospec(spec=EmailState, instance=True)
            # Based on EmailState API: only has .path attribute
            mock_state_tracker.path = self.fs['service']['state.json']
            mock_state_tracker.is_processed = Mock(return_value=False)
            mock_state_tracker.processed = set[str]()
            # Cache both the factory and the instance
            mock_factory = MagicMock(spec=EmailState, return_value=mock_state_tracker)
            object.__setattr__(self, '_get_state_tracker', mock_factory)
        return self._get_state_tracker

    @property
    def get_error_tracker(self) -> MockType[ErrorTracker]:
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

            errors_json = self.fs['service']['errors.json']

            # Based on ErrorTracker API: has .path attribute (not .file)
            mock_error_tracker = create_autospec(spec=ErrorTracker, instance=True, path=errors_json)
            mock_error_tracker.path = errors_json
            mock_error_tracker.warning = Mock(return_value=None)
            mock_error_tracker.error = Mock(side_effect=mock_error)
            mock_error_tracker.prev_error = PropertyMock(side_effect=mock_prev)
            mock_error_tracker.clear_old_errors = Mock(return_value=None)

            per_uid = create_autospec(ErrorTracker, instance=True, path=errors_json)
            per_uid.warning = mock_error_tracker.warning

            @contextmanager
            def mock_track(uid: str | None = None) -> Generator[ErrorTracker]:
                per_uid.uid = uid
                per_uid.error = Mock(side_effect=partial(mock_error, uid=uid))

                def mock_prev() -> ErrorDict | None:
                    return next((e for e in reversed(errors) if e.get('uid') == per_uid.uid), None)

                per_uid.prev_error = PropertyMock(side_effect=mock_prev)

                try:
                    yield per_uid
                finally:
                    per_uid.uid = None
                    per_uid.error = mock_error_tracker.error
                    per_uid.prev_error = mock_error_tracker.prev_error

            mock_error_tracker.track = Mock(side_effect=mock_track)

            # Cache both the factory and the instance
            mock_factory = MagicMock(spec=ErrorTracker, return_value=mock_error_tracker)
            object.__setattr__(self, '_get_error_tracker', mock_factory)

        return self._get_error_tracker

    def as_mock(self, string: str) -> Mock:
        """Navigate through mock object attributes.

        For factory properties (config, state_tracker, error_tracker), automatically
        accesses .return_value to get the instance mock.
        """
        obj: Any = self
        for attr in string.split('.'):
            value = getattr(obj, attr, obj)

            # If we're accessing a factory property, get the return_value (the instance)
            if attr in ('config', 'state_tracker', 'error_tracker') and hasattr(value, 'return_value'):
                obj = value.return_value
            elif isinstance(value, Mock | MagicMock | PropertyMock):
                obj = value
            else:
                raise TypeError(attr, value)

        return obj


@pytest.fixture(name='mock_core')
def mock_core_fixture(mock_deps: MockDependencies) -> Generator[PatchedDependencies]:
    """Fixture that applies core module patches.

    This fixture:
    1. Applies patches to automate.eserv.core module
    2. Returns the patched dependencies for assertions
    3. Cleans up patches after test

    Note: Environment is already loaded by MockDependencies.__post_init__
    """
    # Get the patches
    patches: PatchedDependencies = {
        'configure': mock_deps.configure,
        'get_state_tracker': mock_deps.get_state_tracker,
        'get_error_tracker': mock_deps.get_error_tracker,
    }

    # Apply patches and yield
    with patch.multiple('automate.eserv.core', **patches):
        yield patches
