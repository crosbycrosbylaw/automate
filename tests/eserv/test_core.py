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

# pyright: reportAttributeAccessIssue=false

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock, patch

import pytest

from automate.eserv import *
from automate.eserv.core import *
from automate.eserv.types import *

from .conftest import *

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


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


@pytest.fixture
def mock_core(mock_dependencies: MockDependencies) -> PatchedDependencies:
    return mock_dependencies('automate.eserv.core')


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


class TestPipelineInit:
    """Test Pipeline initialization."""

    def test_config_loading_from_dotenv_path(
        self,
        mock_dependencies: MockDependencies,
        mock_core: PatchedDependencies,
    ) -> None:
        """Test config loaded from .env path."""
        mock_dotenv = mock_dependencies.files['.env.test']
        pipeline = Pipeline(mock_dotenv)

        mock_core['configure'].assert_called_once_with(dotenv_path=mock_dotenv)
        assert pipeline.config is mock_dependencies.config()

    def test_state_tracker_initialization(
        self,
        mock_dependencies: MockDependencies,
        mock_core: PatchedDependencies,
    ) -> None:
        """Test state tracker initialized from config."""
        mock_state_json = mock_dependencies.files['service']['state.json']
        pipeline = Pipeline()

        mock_core['get_state_tracker'].assert_called_once_with(mock_state_json)
        assert pipeline.state.json_path == mock_dependencies.config.paths.state
        assert pipeline.state is mock_dependencies.state_tracker

    def test_error_tracker_initialization(
        self,
        mock_dependencies: MockDependencies,
        mock_core: PatchedDependencies,
    ) -> None:
        """Test error tracker initialized from config."""
        mock_errors_json = mock_dependencies.files['service']['errors.json']
        pipeline = Pipeline()

        mock_core['get_error_tracker'].assert_called_once_with(mock_errors_json)
        assert pipeline.tracker is mock_dependencies.error_tracker
        assert pipeline.tracker.file == mock_errors_json


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
        mock_core: PatchedDependencies,
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
        mock_core: PatchedDependencies,
        mock_dependencies: MockDependencies,
        sample_email_record,
    ) -> None:
        """Test HTML parsing failure returns error result."""
        with patch('automate.eserv.core.BeautifulSoup', side_effect=Exception('Parse error')):
            # Initialize pipeline
            pipeline = Pipeline()

            # Process should return error result
            result = pipeline.process(sample_email_record)
            mock_dependencies.as_mock('error_tracker.track').assert_called_once()
            assert result.status == status.ERROR

    def test_download_failure(
        self,
        mock_core: PatchedDependencies,
        mock_dependencies: MockDependencies,
        sample_email_record,
    ) -> None:
        """Test document download failure returns error result."""
        with (
            patch('automate.eserv.core.BeautifulSoup'),
            patch('automate.eserv.core.download_documents', side_effect=Exception('Download error')),
        ):
            # Initialize pipeline
            pipeline = Pipeline()

            # Process should return error result
            result = pipeline.process(sample_email_record)

            mock_dependencies.as_mock('error_tracker.track').return_value.error.assert_called_once()
            assert result.status == status.ERROR

    def test_upload_info_extraction_failure(
        self,
        mock_core: PatchedDependencies,
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
            mock_dependencies.as_mock('error_tracker.track').return_value.error.assert_called_once()
            assert result.status == status.ERROR

    def test_duplicate_detection_uid_already_processed(
        self,
        mock_core: PatchedDependencies,
        mock_dependencies: MockDependencies,
        sample_email_record: EmailRecord,
        directory,
    ) -> None:
        """Test duplicate email detection via state tracker."""
        store_path = directory / 'docs'
        store_path.mkdir(exist_ok=True)

        # Mock state to return True for is_processed
        mock_dependencies.as_mock('state_tracker.is_processed').return_value = True
        sample_email_record.uid = 'test-uid'

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

            mock_dependencies.as_mock('state_tracker.is_processed').assert_called_once_with('test-uid')

    def test_no_pdfs_after_download(
        self,
        mock_core: PatchedDependencies,
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
        mock_core: PatchedDependencies,
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
        mock_core: PatchedDependencies,
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
            mock_dependencies.as_mock('error_tracker.track.return_value').warning.assert_called_once()

    def test_upload_error_status(
        self,
        mock_core: PatchedDependencies,
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
            mock_dependencies.as_mock('error_tracker.track.return_value').error.assert_called_once()


class TestPipelineMonitor:
    """Test Pipeline.monitor() workflow."""

    @pytest.mark.asyncio
    async def test_batch_processing_via_email_processor(
        self,
        mock_core: PatchedDependencies,
    ) -> None:
        """Test monitor delegates to EmailProcessor."""
        with patch('automate.eserv.core.get_record_processor') as mock_get_record_processor:
            # Mock EmailProcessor.process_batch
            mock_processor = new_mock_processor(batch_result := {'total': 5, 'succeeded': 4, 'failed': 1})

            mock_get_record_processor.return_value = mock_processor

            # Initialize pipeline and monitor
            result = await (pipeline := Pipeline()).monitor()

            # Verify EmailProcessor created with pipeline
            mock_get_record_processor.assert_called_once_with(pipeline)

            # Verify process_batch called
            mock_processor.process_batch.assert_called_once_with(1)

            for key, expected in batch_result.items():
                actual = getattr(result, key)
                assert actual == expected, f'{key.capitalize()} mismatch: {actual} != {expected}'

    @pytest.mark.asyncio
    async def test_errors_cleanup_before_processing(
        self,
        mock_dependencies: MockDependencies,
    ) -> None:
        """Test error log cleanup called before monitoring."""
        with patch('automate.eserv.core.get_record_processor') as mock_get_record_processor:
            mock_processor = new_mock_processor()
            mock_get_record_processor.return_value = mock_processor

            # Initialize pipeline and monitor
            await Pipeline().monitor()

            # Verify error cleanup called
            mock_dependencies.as_mock('error_tracker').clear_old_errors.assert_called_once_with(days=30)


class TestPipelineExecute:
    """Test Pipeline.execute() wrapper."""

    mock_download_info = staticmethod(_mock_download_info)
    mock_upload_info = staticmethod(_mock_upload_info)

    def test_successful_execution_wrapper(
        self,
        mock_core: PatchedDependencies,
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
        mock_core: PatchedDependencies,
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
        mock_core: PatchedDependencies,
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
