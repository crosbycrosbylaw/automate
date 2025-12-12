"""Unit tests for core Pipeline orchestration.

Tests cover:
- Pipeline initialization with config, state, and error tracker
- Complete processing workflow through all 6 stages
- Stage transition error handling
- Duplicate detection via state tracking
- Upload result status routing (SUCCESS, MANUAL_REVIEW, ERROR, NO_WORK)
- Monitor workflow and error cleanup
- Execute wrapper with exception handling
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal
from unittest.mock import Mock, patch

import pytest

from automate.eserv import *
from automate.eserv.core import *
from automate.eserv.types import *

if TYPE_CHECKING:
    from collections.abc import Generator, Mapping
    from contextlib import _GeneratorContextManager
    from pathlib import Path


@pytest.fixture
def mock_dotenv_path(directory) -> Path:
    """Create mock .env file path."""
    env_path = directory / '.env'
    env_path.write_text('TEST_VAR=test_value\n')
    return env_path


def new_mock_processor(
    batch_result_config: Mapping[str, int] | None = None,
    summarize_returns: Any | None = None,
) -> Mock:
    mock_batch_result = Mock(spec=BatchResult)
    mock_batch_result.configure_mock(
        **{'summarize.return_value': summarize_returns or {}},
        **(batch_result_config or {}),
    )

    mock_processor = Mock(spec=EmailProcessor)
    mock_processor.configure_mock(**{
        'process_batch.return_value': mock_batch_result,
    })

    return mock_processor


def _resolve_dependency_name(key: CoreDependency) -> str:
    match key:
        case 'config':
            return 'config_factory'
        case 'state':
            return 'get_state_tracker'
        case 'tracker':
            return 'get_error_tracker'
        case _:
            raise ValueError(key)


@pytest.fixture
def mock_dependencies(directory) -> dict[str, Mock]:
    """Mock all Pipeline dependencies."""
    service_dir = directory / 'svc'
    service_dir.mkdir(exist_ok=True, parents=True)

    mock_config = Mock()
    mock_config.state = Mock(state_file=service_dir / 'state.json')
    mock_config.paths = Mock(service_dir=service_dir)
    mock_state = Mock(spec=['is_processed', 'processed'])
    mock_state.is_processed.return_value = False
    mock_state.processed = set()

    # Configure error() to return IntermediaryResult with ERROR status and store error entry
    errors_list = []

    def mock_error(
        event=None,
        *,
        stage=None,
        exception=None,
        result=None,
        context=None,
    ) -> IntermediaryResult:
        # Create and store error entry
        if exception and hasattr(exception, 'entry'):
            error_entry = exception.entry()
        else:
            # Create error entry dict matching ErrorDict structure
            error_entry = {
                'uid': 'email-123',
                'category': stage.value if stage and hasattr(stage, 'value') else 'unknown',
                'message': event or (str(exception) if exception else 'Error occurred'),
                'timestamp': datetime.now(UTC).isoformat(),
            }
            if context:
                error_entry['context'] = context

        errors_list.append(error_entry)

        if result:
            raise PipelineError.from_stage(stage, message=event, context=context)
        return IntermediaryResult(status=status.ERROR)

    mock_tracker = Mock(spec=['track', 'clear_old_errors', 'prev_error'])
    mock_track_cm = Mock()
    mock_track_cm.__enter__ = Mock(return_value=mock_track_cm)
    mock_track_cm.__exit__ = Mock(return_value=None)
    mock_track_cm.error = Mock(side_effect=mock_error)
    mock_track_cm.warning = Mock()
    mock_tracker.track.return_value = mock_track_cm

    # Configure prev_error to return the most recent error
    type(mock_tracker).prev_error = property(lambda self: errors_list[-1] if errors_list else None)

    return {
        'config': mock_config,
        'state': mock_state,
        'tracker': mock_tracker,
        'track_cm': mock_track_cm,
    }


@pytest.fixture
def sample_email_record():
    """Create sample EmailRecord for testing."""
    from automate.eserv import make_email_record

    return make_email_record(
        uid='email-123',
        sender='court@example.com',
        subject='Smith v. Jones - Filing Accepted',
        received_at=datetime(2025, 1, 1, 12, 0, tzinfo=UTC),
        body='<html><body><a href="http://example.com/doc.pdf">Download</a></body></html>',
    )


type CoreDependency = Literal['config', 'state', 'tracker', 'track_cm']
type MockCoreFactory = Callable[
    [*tuple[CoreDependency, ...]],
    _GeneratorContextManager[dict[CoreDependency, Mock]],
]


@pytest.fixture
def mock_core_factory(
    mock_dependencies,
) -> MockCoreFactory:

    @contextmanager
    def _mock_core(*deps: CoreDependency) -> Generator[Any]:
        include = set[str](deps) - {'track_cm'}

        out: dict[CoreDependency, Mock] = {
            name: Mock(return_value=mock_dependencies[name]) for name in deps if name in include
        }
        try:
            with patch.multiple(
                target='automate.eserv.core',
                **{_resolve_dependency_name(name): out[name] for name in out},
            ):
                yield out
        finally:
            pass

    return _mock_core


class TestPipelineInit:
    """Test Pipeline initialization."""

    def test_config_loading_from_dotenv_path(
        self,
        mock_dotenv_path: Path,
        mock_core_factory: MockCoreFactory,
        mock_dependencies: dict[str, Mock],
    ) -> None:
        """Test config loaded from .env path."""
        with mock_core_factory('config', 'state', 'tracker') as mock_core:
            pipeline = Pipeline(dotenv_path=mock_dotenv_path)

            mock_core['config'].assert_called_once_with(mock_dotenv_path)
            assert pipeline.config is mock_dependencies['config']

    def test_state_tracker_initialization(
        self,
        directory,
        mock_dependencies: dict,
        mock_core_factory: MockCoreFactory,
    ) -> None:
        """Test state tracker initialized from config."""
        with mock_core_factory('config', 'state', 'tracker') as mock_core:
            # Initialize pipeline
            pipeline = Pipeline()

            # Verify state_tracker called with state file path
            mock_core['state'].assert_called_once_with(directory / 'svc' / 'state.json')

            # Verify pipeline.state set
            assert pipeline.state is mock_dependencies['state']

    def test_error_tracker_initialization(
        self,
        directory: Path,
        mock_dependencies: dict,
        mock_core_factory: MockCoreFactory,
    ) -> None:
        """Test error tracker initialized from config."""
        with mock_core_factory('config', 'state', 'tracker') as mock_core:
            # Initialize pipeline
            pipeline = Pipeline()

            # Verify error_tracker called with error log path
            expected_path = directory / 'svc' / 'error_log.json'
            mock_core['tracker'].assert_called_once_with(expected_path)

            # Verify pipeline.tracker set
            assert pipeline.tracker is mock_dependencies['tracker']


def _mock_download_info(
    store_path: Path,
    *,
    lead_name: str = 'Motion',
    source: str = 'http://example.com/doc.pdf',
) -> Mock:
    mock = Mock()
    asdict = {}
    mock.source = asdict['source'] = source
    mock.lead_name = asdict['lead_name'] = lead_name
    mock.store_path = store_path
    mock.unpack = Mock(return_value=(*asdict.values(), store_path))
    asdict['store_path'] = store_path.as_posix()
    mock.asdict = Mock(return_value=asdict)
    return mock


def _mock_upload_info() -> Mock:
    asdict = {
        'case_name': 'Smith v. Jones',
        'doc_count': 1,
    }
    mock = Mock()
    mock.case_name = asdict['case_name']
    mock.doc_count = asdict['doc_count']
    mock.asdict = Mock(return_value=asdict)
    mock.unpack = Mock(return_value=asdict.values())

    return mock


class TestPipelineProcess:
    """Test Pipeline.process() complete workflow."""

    mock_download_info = staticmethod(_mock_download_info)
    mock_upload_info = staticmethod(_mock_upload_info)

    def test_successful_complete_workflow(
        self,
        mock_core_factory: MockCoreFactory,
        sample_email_record,
        directory,
    ) -> None:
        """Test successful processing through all 6 stages."""
        # Setup temp store path
        store_path = directory / 'docs'
        store_path.mkdir(exist_ok=True)
        pdf_path = store_path / 'Motion.pdf'
        pdf_path.write_bytes(b'%PDF-1.4\nTest PDF')

        # Create mock download info
        mock_download_info = self.mock_download_info(store_path)

        # Mock all stage functions
        with (
            mock_core_factory('config', 'state', 'tracker'),
            patch('automate.eserv.core.BeautifulSoup') as mock_soup_class,
            patch('automate.eserv.core.download_documents', return_value=mock_download_info),
            patch('automate.eserv.core.extract_upload_info') as mock_extract,
            patch('automate.eserv.core.upload_documents') as mock_upload,
        ):
            # Setup mocks
            mock_soup = Mock()
            mock_soup_class.return_value = mock_soup

            mock_extract.return_value = self.mock_upload_info()

            mock_upload.return_value = IntermediaryResult(
                status=status.SUCCESS,
                folder_path='/Clio/Smith v. Jones',
                uploaded_files=['Motion.pdf'],
            )

            # Initialize pipeline and process
            pipeline = Pipeline()
            result = pipeline.process(sample_email_record)

            # Verify result
            assert result.status == status.SUCCESS
            assert result.folder_path == '/Clio/Smith v. Jones'

            # Verify all stages called
            mock_soup_class.assert_called_once()
            mock_extract.assert_called_once()
            mock_upload.assert_called_once()

    def test_html_parsing_failure(
        self,
        mock_dependencies: dict,
        mock_core_factory: MockCoreFactory,
        sample_email_record,
    ) -> None:
        """Test HTML parsing failure returns error result."""
        with (
            mock_core_factory('config', 'state', 'tracker'),
            patch('automate.eserv.core.BeautifulSoup', side_effect=Exception('Parse error')),
        ):
            # Initialize pipeline
            pipeline = Pipeline()

            # Process should return error result
            result = pipeline.process(sample_email_record)

            # Verify error logged and returned error status
            mock_dependencies['track_cm'].error.assert_called_once()
            assert result.status == status.ERROR

    def test_download_failure(
        self,
        mock_dependencies: dict,
        mock_core_factory: MockCoreFactory,
        sample_email_record,
    ) -> None:
        """Test document download failure returns error result."""
        with (
            mock_core_factory('config', 'state', 'tracker'),
            patch('automate.eserv.core.BeautifulSoup'),
            patch(
                'automate.eserv.core.download_documents',
                side_effect=Exception('Download error'),
            ),
        ):
            # Initialize pipeline
            pipeline = Pipeline()

            # Process should return error result
            result = pipeline.process(sample_email_record)

            # Verify error logged and returned error status
            mock_dependencies['track_cm'].error.assert_called_once()
            assert result.status == status.ERROR

    def test_upload_info_extraction_failure(
        self,
        mock_dependencies: dict,
        mock_core_factory: MockCoreFactory,
        sample_email_record,
        directory,
    ) -> None:
        """Test upload info extraction failure returns error result."""
        store_path = directory / 'docs'
        store_path.mkdir(exist_ok=True)

        # Create mock download info
        mock_download_info = self.mock_download_info(store_path)

        with (
            mock_core_factory('config', 'state', 'tracker'),
            patch('automate.eserv.core.BeautifulSoup'),
            patch('automate.eserv.core.download_documents', return_value=mock_download_info),
            patch(
                'automate.eserv.core.extract_upload_info',
                side_effect=Exception('Extraction error'),
            ),
        ):
            # Initialize pipeline
            pipeline = Pipeline()

            # Process should return error result
            result = pipeline.process(sample_email_record)

            # Verify error logged and returned error status
            mock_dependencies['track_cm'].error.assert_called_once()
            assert result.status == status.ERROR

    def test_duplicate_detection_uid_already_processed(
        self,
        mock_dependencies: dict,
        mock_core_factory: MockCoreFactory,
        sample_email_record,
        directory,
    ) -> None:
        """Test duplicate email detection via state tracker."""
        store_path = directory / 'docs'
        store_path.mkdir(exist_ok=True)

        # Mock state to return True for is_processed
        mock_dependencies['state'].is_processed.return_value = True

        # Create mock download info
        mock_download_info = self.mock_download_info(store_path)

        with (
            mock_core_factory('config', 'state', 'tracker'),
            patch('automate.eserv.core.BeautifulSoup'),
            patch('automate.eserv.core.download_documents', return_value=mock_download_info),
            patch('automate.eserv.core.extract_upload_info') as mock_extract,
        ):
            mock_extract.return_value = self.mock_upload_info()

            # Initialize pipeline
            pipeline = Pipeline()
            result = pipeline.process(sample_email_record)

            # Verify NO_WORK returned
            assert result.status == status.NO_WORK

            # Verify is_processed checked
            mock_dependencies['state'].is_processed.assert_called_once_with('email-123')

    def test_no_pdfs_after_download(
        self,
        mock_core_factory: MockCoreFactory,
        sample_email_record,
        directory,
    ) -> None:
        """Test NO_WORK when no PDF files after download."""
        # Empty store directory (no PDFs)
        store_path = directory / 'docs'
        store_path.mkdir(exist_ok=True)

        # Create mock download info
        mock_download_info = self.mock_download_info(store_path)

        with (
            mock_core_factory('config', 'state', 'tracker'),
            patch('automate.eserv.core.BeautifulSoup'),
            patch('automate.eserv.core.download_documents', return_value=mock_download_info),
            patch('automate.eserv.core.extract_upload_info') as mock_extract,
            patch('automate.eserv.core.upload_documents') as mock_upload,
        ):
            mock_extract.return_value = self.mock_upload_info()
            mock_upload.return_value = IntermediaryResult(status=status.NO_WORK)

            # Initialize pipeline
            pipeline = Pipeline()
            result = pipeline.process(sample_email_record)

            # Verify NO_WORK status
            assert result.status == status.NO_WORK

    def test_upload_success_status(
        self,
        mock_core_factory: MockCoreFactory,
        sample_email_record,
        directory,
    ) -> None:
        """Test SUCCESS status from successful upload."""
        store_path = directory / 'docs'
        store_path.mkdir(exist_ok=True)
        pdf_path = store_path / 'Motion.pdf'
        pdf_path.write_bytes(b'%PDF-1.4\nTest')

        # Create mock download info
        mock_download_info = self.mock_download_info(store_path)

        with (
            mock_core_factory('config', 'state', 'tracker'),
            patch('automate.eserv.core.BeautifulSoup'),
            patch('automate.eserv.core.download_documents', return_value=mock_download_info),
            patch('automate.eserv.core.extract_upload_info') as mock_extract,
            patch('automate.eserv.core.upload_documents') as mock_upload,
        ):
            mock_extract.return_value = self.mock_upload_info()
            mock_upload.return_value = IntermediaryResult(
                status=status.SUCCESS,
                folder_path='/Clio/Smith v. Jones',
                uploaded_files=['Motion.pdf'],
            )

            # Initialize pipeline
            pipeline = Pipeline()
            result = pipeline.process(sample_email_record)

            # Verify SUCCESS status
            assert result.status == status.SUCCESS

    def test_upload_manual_review_status(
        self,
        mock_dependencies: dict,
        mock_core_factory: MockCoreFactory,
        sample_email_record,
        directory,
    ) -> None:
        """Test MANUAL_REVIEW status when no folder match."""
        store_path = directory / 'docs'
        store_path.mkdir(exist_ok=True)
        pdf_path = store_path / 'Motion.pdf'
        pdf_path.write_bytes(b'%PDF-1.4\nTest')

        # Create mock download info
        mock_download_info = self.mock_download_info(store_path)

        with (
            mock_core_factory('config', 'state', 'tracker'),
            patch('automate.eserv.core.BeautifulSoup'),
            patch('automate.eserv.core.download_documents', return_value=mock_download_info),
            patch('automate.eserv.core.extract_upload_info') as mock_extract,
            patch('automate.eserv.core.upload_documents') as mock_upload,
        ):
            mock_extract.return_value = self.mock_upload_info()
            mock_upload.return_value = IntermediaryResult(
                status=status.MANUAL_REVIEW,
                folder_path='/Clio/Manual Review/',
                uploaded_files=['Motion.pdf'],
            )

            # Initialize pipeline
            pipeline = Pipeline()
            result = pipeline.process(sample_email_record)

            # Verify MANUAL_REVIEW status
            assert result.status == status.MANUAL_REVIEW

            # Verify warning logged
            mock_dependencies['track_cm'].warning.assert_called_once()

    def test_upload_error_status(
        self,
        mock_dependencies: dict[str, Mock],
        mock_core_factory: MockCoreFactory,
        sample_email_record,
        directory,
    ) -> None:
        """Test ERROR status from upload failure."""
        store_path = directory / 'docs'
        store_path.mkdir(exist_ok=True)

        pdf_path = store_path / 'Motion.pdf'
        pdf_path.write_bytes(b'%PDF-1.4\nTest')

        # Create mock download info
        mock_download_info = self.mock_download_info(store_path)
        with (
            mock_core_factory('config', 'state', 'tracker'),
            patch('automate.eserv.core.BeautifulSoup'),
            patch('automate.eserv.core.download_documents', return_value=mock_download_info),
            patch('automate.eserv.core.extract_upload_info') as mock_extract,
            patch('automate.eserv.core.upload_documents') as mock_upload,
        ):
            mock_extract.return_value = self.mock_upload_info()
            mock_upload.return_value = IntermediaryResult(status=status.ERROR, error='Dropbox API error')

            # Initialize pipeline
            pipeline = Pipeline()

            # Process should raise DocumentUploadError
            with pytest.raises(DocumentUploadError):
                pipeline.process(sample_email_record)

            # Verify error logged
            mock_dependencies['track_cm'].error.assert_called_once()


class TestPipelineMonitor:
    """Test Pipeline.monitor() workflow."""

    @pytest.mark.asyncio
    async def test_batch_processing_via_email_processor(
        self,
        mock_core_factory: MockCoreFactory,
    ) -> None:
        """Test monitor delegates to EmailProcessor."""
        with (
            mock_core_factory('config', 'state', 'tracker'),
            patch('automate.eserv.core.get_record_processor') as mock_get_record_processor,
        ):
            # Mock EmailProcessor.process_batch
            mock_processor = new_mock_processor(batch_result := {'total': 5, 'succeeded': 4, 'failed': 1})

            mock_get_record_processor.return_value = mock_processor

            # Initialize pipeline and monitor
            result = await (pipeline := Pipeline()).monitor(num_days=1)

            # Verify EmailProcessor created with pipeline
            mock_get_record_processor.assert_called_once_with(pipeline)

            # Verify process_batch called
            mock_processor.process_batch.assert_called_once_with(1)

            for key, expected in batch_result.items():
                actual = getattr(result, key)
                assert actual == expected, f'{key.capitalize()} mismatch: {actual} != {expected}'

    @pytest.mark.asyncio
    async def test_error_log_cleanup_before_processing(
        self,
        mock_dependencies: dict,
        mock_core_factory: MockCoreFactory,
    ) -> None:
        """Test error log cleanup called before monitoring."""
        with (
            mock_core_factory('config', 'state', 'tracker'),
            patch('automate.eserv.core.get_record_processor') as mock_get_record_processor,
        ):
            mock_processor = new_mock_processor()
            mock_get_record_processor.return_value = mock_processor

            # Initialize pipeline and monitor
            pipeline = Pipeline()
            await pipeline.monitor(num_days=1)

            # Verify error cleanup called
            mock_dependencies['tracker'].clear_old_errors.assert_called_once_with(days=30)


class TestPipelineExecute:
    """Test Pipeline.execute() wrapper."""

    mock_download_info = staticmethod(_mock_download_info)
    mock_upload_info = staticmethod(_mock_upload_info)

    def test_successful_execution_wrapper(
        self,
        mock_core_factory: MockCoreFactory,
        sample_email_record,
        directory,
    ) -> None:
        """Test execute wraps process() successfully."""
        store_path = directory / 'docs'
        store_path.mkdir(exist_ok=True)
        pdf_path = store_path / 'Motion.pdf'
        pdf_path.write_bytes(b'%PDF-1.4\nTest')

        # Create mock download info
        mock_download_info = self.mock_download_info(store_path)

        with (
            mock_core_factory('config', 'state', 'tracker'),
            patch('automate.eserv.core.BeautifulSoup'),
            patch('automate.eserv.core.download_documents', return_value=mock_download_info),
            patch('automate.eserv.core.extract_upload_info') as mock_extract,
            patch('automate.eserv.core.upload_documents') as mock_upload,
        ):
            mock_extract.return_value = self.mock_upload_info()
            mock_upload.return_value = IntermediaryResult(status=status.SUCCESS)

            # Initialize pipeline and execute
            pipeline = Pipeline()
            result = pipeline.execute(sample_email_record)

            # Verify ProcessedResult returned
            assert result.error is None
            assert result.status == 'success'

    def test_pipeline_error_converted_to_processed_result(
        self,
        mock_core_factory: MockCoreFactory,
        sample_email_record,
    ) -> None:
        """Test PipelineError converted to ProcessedResult with error."""
        with (
            mock_core_factory('config', 'state', 'tracker'),
            patch('automate.eserv.core.BeautifulSoup', side_effect=Exception('Parse error')),
        ):
            # Initialize pipeline
            pipeline = Pipeline()
            result = pipeline.execute(sample_email_record)

            # Verify ProcessedResult with error returned
            assert result.error is not None
            assert result.status == 'error'

    def test_generic_exception_converted_to_processed_result(
        self,
        mock_core_factory: MockCoreFactory,
        sample_email_record,
    ) -> None:
        """Test generic exception converted to ProcessedResult with stage info."""
        with (
            mock_core_factory('config', 'state', 'tracker'),
            patch('automate.eserv.core.BeautifulSoup', side_effect=RuntimeError('Unexpected error')),
        ):
            # Initialize pipeline
            pipeline = Pipeline()
            result = pipeline.execute(sample_email_record)

            # Verify ProcessedResult with error
            # Error is wrapped in PipelineError with stage 'parsing'
            assert result.error is not None
            assert result.error['category'] == EmailParseError.stage.value
            assert 'message' in result.error
            message = result.error['message']
            assert isinstance(message, str)
            assert message == 'BeautifulSoup initialization'
