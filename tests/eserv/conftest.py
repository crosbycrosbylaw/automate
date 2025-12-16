from __future__ import annotations

from contextlib import contextmanager
from dataclasses import field
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import TypedDict
from unittest.mock import MagicMock, Mock, PropertyMock, create_autospec, patch

import orjson
from pytest_fixture_classes import fixture_class
from rampy import test

from automate.eserv import *
from automate.eserv.core import *
from automate.eserv.types import *

if TYPE_CHECKING:
    from collections.abc import Generator

type MockType[T] = type[T] | MagicMock

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


@fixture_class(name='mock_files')
class MockFilesFixture:
    directory: Path

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

    value: MockFiles = field(init=False)

    def _format_environment(self) -> str:
        return '\n' + '\n'.join(f'{k}={v}' for k, v in self.environment.items()) + '\n'

    def _encode_credentials(self) -> bytes:
        return orjson.dumps(self.credentials, option=orjson.OPT_APPEND_NEWLINE)

    def __post_init__(self) -> None:
        object.__setattr__(self, 'root', self.directory.resolve(strict=True))
        object.__setattr__(self, 'service', self.root / 'service')
        object.__setattr__(self, 'cert', self.root / 'cert')

        for d in self.root, self.service, self.cert:
            d.mkdir(parents=True, exist_ok=True)

        for f in [creds_json := self.root / 'credentials.json', env_test := self.root / '.env.test']:
            f.touch(exist_ok=True)

        self.environment['PROJECT_ROOT'] = str(self.root)
        self.environment['SERVICE_DIR'] = str(self.service)
        self.environment['CREDENTIALS_FILE'] = str(creds_json)

        creds_json.write_bytes(self._encode_credentials())
        env_test.write_text(self._format_environment())

        object.__setattr__(
            self,
            'value',
            {
                '.': self.root,
                '.env.test': env_test,
                'credentials.json': creds_json,
                'cert': self._scaffold_cert_files(),
                'service': self._scaffold_service_files(),
            },
        )

    def _scaffold_cert_files(self) -> _MockCertFiles:
        private_key = self.cert / 'private.key'
        private_key.touch(exist_ok=True)

        self.environment['CERT_PRIVATE_KEY_FILE'] = str(private_key)

        return {
            '.': self.cert,
            'private.key': private_key,
        }

    def _scaffold_service_files(self) -> _MockServiceFiles:
        for f in [
            state_json := self.service / 'state.json',
            index_json := self.service / 'index.json',
            errors_json := self.service / 'errors.json',
        ]:
            f.touch(exist_ok=True)

        self.environment['STATE_FILE'] = str(state_json)
        self.environment['INDEX_FILE'] = str(index_json)

        return {
            '.': self.service,
            'state.json': state_json,
            'index.json': index_json,
            'errors.json': errors_json,
        }

    def __call__(self) -> MockFiles:
        import dotenv

        dotenv.load_dotenv(self.value['.env.test'])
        return self.value


class PatchedDependencies(TypedDict):
    configure: MockType[Config]
    get_state_tracker: MockType[EmailState]
    get_error_tracker: MockType[ErrorTracker]


@fixture_class(name='mock_dependencies')
class MockDependencies:
    mock_files: MockFilesFixture

    _f: MockFiles = field(init=False)

    @property
    def f(self) -> MockFiles:
        if not hasattr(self, '_f'):
            object.__setattr__(self, '_f', self.mock_files())
        return self._f

    @property
    def config(self) -> MockType[Config]:
        mock_config = create_autospec(spec=Config, instance=True)
        mock_config.paths = create_autospec(
            spec=PathsConfig,
            instance=True,
            path=self.f['.env.test'],
        )
        mock_config.creds = create_autospec(
            spec=CredentialsConfig,
            instance=True,
            path=self.f['credentials.json'],
        )
        return MagicMock(spec=Config, return_value=mock_config)

    @property
    def state_tracker(self) -> MockType[EmailState]:
        mock_state_tracker = create_autospec(spec=EmailState, instance=True)
        mock_state_tracker.path = self.f['service']['state.json']
        mock_state_tracker.is_processed = Mock(return_value=False)
        mock_state_tracker.processed = set[str]()
        return MagicMock(spec=EmailState, return_value=mock_state_tracker)

    @property
    def error_tracker(self) -> MockType[ErrorTracker]:
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

        errors_json = self.f['service']['errors.json']

        mock_error_tracker = create_autospec(spec=ErrorTracker, instance=True, path=errors_json)
        mock_error_tracker.warning = Mock(return_value=None)
        mock_error_tracker.error = Mock(side_effect=mock_error)
        mock_error_tracker.prev_error = PropertyMock(side_effect=mock_prev)

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

        return MagicMock(spec=ErrorTracker, return_value=mock_error_tracker)

    def __call__(self, patch_target: str = 'automate.eserv.core') -> PatchedDependencies:
        patches: PatchedDependencies = {
            'configure': self.config,
            'get_state_tracker': self.state_tracker,
            'get_error_tracker': self.error_tracker,
        }
        with patch.multiple(patch_target, **patches):
            return patches

    def as_mock(self, string: str) -> Mock:
        obj: Any = self
        for attr in string.split('.'):
            if isinstance(value := getattr(obj, attr, obj), Mock | MagicMock | PropertyMock):
                obj = value
            else:
                raise TypeError(attr, value)

        return obj
