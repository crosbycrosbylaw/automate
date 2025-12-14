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

# pyright: reportAttributeAccessIssue=information

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, TypedDict
from unittest.mock import Mock, patch

import pytest

from automate.eserv import *
from automate.eserv.core import *
from automate.eserv.types import *

if TYPE_CHECKING:
    from collections.abc import Generator, Mapping
    from contextlib import _GeneratorContextManager
    from pathlib import Path

    from tests.eserv.monitor.test_client import Mocked


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


class MockDependencies(TypedDict):
    config: Mocked[Config]
    state: Mocked[EmailState]
    tracker: Mocked[ErrorTracker]
    track_cm: Mocked[_GeneratorContextManager[ErrorTracker]]


@pytest.fixture
def mock_dependencies(mock_config: Mocked[Config]) -> MockDependencies:
    """Mock all Pipeline dependencies."""
    mock_state = Mock(spec=['json_path', 'is_processed', 'processed'])
    mock_state.json_path = mock_config.paths.state
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

    mock_track_cm = Mock()
    mock_track_cm.__enter__ = Mock(return_value=mock_track_cm)
    mock_track_cm.__exit__ = Mock(return_value=None)
    mock_track_cm.error = Mock(side_effect=mock_error)
    mock_track_cm.warning = Mock()

    mock_tracker = Mock(spec=['file', 'uid', 'track', 'clear_old_errors', 'prev_error'])
    mock_tracker.file = mock_config.paths.error_log
    mock_tracker.uid = 'n/a'
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


type PatchedCore = dict[Literal['configure', 'get_state_tracker', 'get_error_tracker'], Mock]


@pytest.fixture
def patched_core(
    mock_dependencies,
) -> Generator[PatchedCore]:

    patches: PatchedCore = {
        'configure': Mock(return_value=mock_dependencies['config']),
        'get_state_tracker': Mock(return_value=mock_dependencies['state']),
        'get_error_tracker': Mock(return_value=mock_dependencies['tracker']),
    }

    try:
        with patch.multiple('automate.eserv.core', **patches):
            yield patches
    finally:
        pass


class TestPipelineInit:
    """Test Pipeline initialization."""

    def test_config_loading_from_dotenv_path(
        self,
        mock_dotenv_path: Path,
        patched_core: PatchedCore,
        mock_dependencies: MockDependencies,
    ) -> None:
        """Test config loaded from .env path."""
        pipeline = Pipeline(mock_dotenv_path)
        patched_core['configure'].assert_called_once_with(dotenv_path=mock_dotenv_path)
        assert pipeline.config is mock_dependencies['config']

    def test_state_tracker_initialization(
        self,
        patched_core: PatchedCore,
        mock_dependencies: MockDependencies,
    ) -> None:
        """Test state tracker initialized from config."""
        pipeline = Pipeline()

        patched_core['get_state_tracker'].assert_called_once_with(mock_dependencies['config'].paths.state)
        assert pipeline.state.json_path == mock_dependencies['config'].paths.state
        assert pipeline.state is mock_dependencies['state']

    def test_error_tracker_initialization(
        self,
        patched_core: PatchedCore,
        mock_dependencies: MockDependencies,
    ) -> None:
        """Test error tracker initialized from config."""
        pipeline = Pipeline()

        expected_path = mock_dependencies['config'].paths.error_log
        patched_core['get_error_tracker'].assert_called_once_with(expected_path)
        assert pipeline.tracker is mock_dependencies['tracker']
        assert pipeline.tracker.file == expected_path


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
        patched_core: PatchedCore,
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
        patched_core: PatchedCore,
        mock_dependencies: MockDependencies,
        sample_email_record,
    ) -> None:
        """Test HTML parsing failure returns error result."""
        with patch('automate.eserv.core.BeautifulSoup', side_effect=Exception('Parse error')):
            # Initialize pipeline
            pipeline = Pipeline()

            # Process should return error result
            result = pipeline.process(sample_email_record)

            # Verify error logged and returned error status
            mock_dependencies['track_cm'].error.assert_called_once()
            assert result.status == status.ERROR

    def test_download_failure(
        self,
        patched_core: PatchedCore,
        mock_dependencies: MockDependencies,
        sample_email_record,
    ) -> None:
        """Test document download failure returns error result."""
        with (
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
        patched_core: PatchedCore,
        mock_dependencies: MockDependencies,
        sample_email_record,
        directory,
    ) -> None:
        """Test upload info extraction failure returns error result."""
        store_path = directory / 'docs'
        store_path.mkdir(exist_ok=True)

        # Create mock download info
        mock_download_info = self.mock_download_info(store_path)

        with (
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
        patched_core: PatchedCore,
        mock_dependencies: MockDependencies,
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
        patched_core: PatchedCore,
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
        patched_core: PatchedCore,
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
        patched_core: PatchedCore,
        mock_dependencies: MockDependencies,
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
        patched_core: PatchedCore,
        mock_dependencies: MockDependencies,
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
        patched_core: PatchedCore,
    ) -> None:
        """Test monitor delegates to EmailProcessor."""
        with patch('automate.eserv.core.get_record_processor') as mock_get_record_processor:
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
        patched_core: PatchedCore,
        mock_dependencies: MockDependencies,
    ) -> None:
        """Test error log cleanup called before monitoring."""
        with patch('automate.eserv.core.get_record_processor') as mock_get_record_processor:
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
        patched_core: PatchedCore,
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
        patched_core: PatchedCore,
        sample_email_record,
    ) -> None:
        """Test PipelineError converted to ProcessedResult with error."""
        with patch('automate.eserv.core.BeautifulSoup', side_effect=Exception('Parse error')):
            # Initialize pipeline
            pipeline = Pipeline()
            result = pipeline.execute(sample_email_record)

            # Verify ProcessedResult with error returned
            assert result.error is not None
            assert result.status == 'error'

    def test_generic_exception_converted_to_processed_result(
        self,
        patched_core: PatchedCore,
        sample_email_record,
    ) -> None:
        """Test generic exception converted to ProcessedResult with stage info."""
        with patch('automate.eserv.core.BeautifulSoup', side_effect=RuntimeError('Unexpected error')):
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
