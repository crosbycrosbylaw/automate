"""Unit tests for upload module.

Tests cover:
- DropboxManager lazy client initialization
- Folder index fetching with pagination
- File upload orchestration
- upload_documents workflow
- Folder matching vs manual review routing
- Multi-file naming logic
- Notification dispatch
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

from automate.eserv import *
from automate.eserv.types import *

if TYPE_CHECKING:
    from pathlib import Path

    from tests.eserv.conftest import SetupFilesFixture
    from tests.eserv.stages.conftest import UploadDocumentSubtestFixture


class TestDropboxManagerClient:
    """Test DropboxManager lazy client initialization."""

    def test_lazy_client_initialization_on_first_access(self, mock_credential: Mock) -> None:
        """Test client is created lazily on first access."""
        manager = dropbox_manager_factory(credential=mock_credential)

        # Verify client not created yet
        assert manager._client is None

        with patch('dropbox.Dropbox') as mock_dropbox_class:
            mock_client = Mock()
            mock_dropbox_class.return_value = mock_client

            # Access client property
            client = manager.client

            # Verify Dropbox SDK constructor called with credentials
            mock_dropbox_class.assert_called_once_with(
                oauth2_access_token='test_access_token',
                oauth2_refresh_token='test_refresh_token',
                app_key='test_client_id',
                app_secret='test_client_secret',
            )

            # Verify client returned
            assert client is mock_client

    def test_client_caching(self, mock_credential: Mock) -> None:
        """Test client is cached after first creation."""
        manager = dropbox_manager_factory(credential=mock_credential)

        with patch('dropbox.Dropbox') as mock_dropbox_class:
            mock_client = Mock()
            mock_dropbox_class.return_value = mock_client

            # Access client twice
            client1 = manager.client
            client2 = manager.client

            # Verify Dropbox SDK constructor called only once
            assert mock_dropbox_class.call_count == 1

            # Verify same client returned
            assert client1 is client2


class TestDropboxManagerIndex:
    """Test folder index fetching."""

    def test_successful_folder_index_fetch(self, mock_credential: Mock) -> None:
        """Test successful folder index fetch without pagination."""
        manager = dropbox_manager_factory(credential=mock_credential)

        # Mock Dropbox client and files_list_folder response
        mock_client = Mock()
        mock_result = Mock()
        mock_result.has_more = False

        # Create mock entries with proper attributes (avoid Mock's special 'name' attribute)
        from dropbox.files import FolderMetadata

        entry1 = Mock(spec=FolderMetadata)
        entry1.path_display = '/Clio/Smith v. Jones'
        entry1.name = 'Smith v. Jones'
        entry1.id = 'folder_id_1'

        entry2 = Mock(spec=FolderMetadata)
        entry2.path_display = '/Clio/Doe v. Roe'
        entry2.name = 'Doe v. Roe'
        entry2.id = 'folder_id_2'

        mock_result.entries = [entry1, entry2]

        mock_client.files_list_folder.return_value = mock_result

        # Set _client directly since client is a read-only property
        manager._client = mock_client

        # Fetch index
        index = manager.index()

        # Verify files_list_folder called
        mock_client.files_list_folder.assert_called_once_with('/Clio/', recursive=True)

        # Verify index structure
        assert '/Clio/Smith v. Jones' in index
        assert index['/Clio/Smith v. Jones']['name'] == 'Smith v. Jones'
        assert index['/Clio/Smith v. Jones']['id'] == 'folder_id_1'
        assert '/Clio/Doe v. Roe' in index

    def test_pagination_handling(self, mock_credential: Mock) -> None:
        """Test pagination with has_more=True."""
        manager = dropbox_manager_factory(credential=mock_credential)

        # Create mock entries with proper attributes
        from dropbox.files import FolderMetadata

        entry1 = Mock(spec=FolderMetadata)
        entry1.path_display = '/Clio/Case1'
        entry1.name = 'Case1'
        entry1.id = 'id1'

        entry2 = Mock(spec=FolderMetadata)
        entry2.path_display = '/Clio/Case2'
        entry2.name = 'Case2'
        entry2.id = 'id2'

        # Mock first page
        mock_result_page1 = Mock()
        mock_result_page1.has_more = True
        mock_result_page1.cursor = 'cursor_123'
        mock_result_page1.entries = [entry1]

        # Mock second page
        mock_result_page2 = Mock()
        mock_result_page2.has_more = False
        mock_result_page2.entries = [entry2]

        mock_client = Mock()
        mock_client.files_list_folder.return_value = mock_result_page1
        mock_client.files_list_folder_continue.return_value = mock_result_page2

        # Set _client directly since client is a read-only property
        manager._client = mock_client

        # Fetch index
        index = manager.index()

        # Verify pagination calls
        mock_client.files_list_folder.assert_called_once()
        mock_client.files_list_folder_continue.assert_called_once_with('cursor_123')

        # Verify both pages in index
        assert '/Clio/Case1' in index
        assert '/Clio/Case2' in index


class TestDropboxManagerUpload:
    """Test file upload functionality."""

    def test_successful_file_upload(
        self,
        mock_credential: Mock,
        mock_document: Path,
    ) -> None:
        """Test successful file upload to Dropbox."""
        manager = dropbox_manager_factory(credential=mock_credential)

        # Mock Dropbox client
        mock_client = Mock()
        mock_metadata = Mock(path_display='/Clio/Smith v. Jones/Motion.pdf')
        mock_client.files_upload.return_value = mock_metadata

        # Set _client directly since client is a read-only property
        manager._client = mock_client

        # Upload file
        manager.upload(mock_document, '/Clio/Smith v. Jones/Motion.pdf')

        # Verify files_upload called
        mock_client.files_upload.assert_called_once()
        call_args = mock_client.files_upload.call_args
        assert call_args[0][1] == '/Clio/Smith v. Jones/Motion.pdf'

        # Verify file added to uploaded list
        assert len(manager.uploaded) == 1
        assert manager.uploaded[0] == '/Clio/Smith v. Jones/Motion.pdf'

    def test_uploaded_list_tracking(
        self,
        mock_credential: Mock,
        mock_document: Path,
    ) -> None:
        """Test uploaded files are tracked in list."""
        manager = dropbox_manager_factory(credential=mock_credential)

        mock_client = Mock()
        mock_client.files_upload.return_value = Mock()

        # Set _client directly since client is a read-only property
        manager._client = mock_client

        # Upload multiple files
        manager.upload(mock_document, '/Clio/Case1/Doc1.pdf')
        manager.upload(mock_document, '/Clio/Case1/Doc2.pdf')
        manager.upload(mock_document, '/Clio/Case2/Doc3.pdf')

        # Verify all tracked
        assert len(manager.uploaded) == 3
        assert '/Clio/Case1/Doc1.pdf' in manager.uploaded
        assert '/Clio/Case1/Doc2.pdf' in manager.uploaded
        assert '/Clio/Case2/Doc3.pdf' in manager.uploaded


def test_document_upload_orchestration(
    mock_document: Path,
    setup_files: SetupFilesFixture,
    run_upload_subtest: UploadDocumentSubtestFixture,
) -> None:
    """Test various behaviors related to document uploading."""
    run_upload_subtest(
        'match found triggers successful upload',
        documents=[mock_document],
        cached_paths=[
            '/Clio/Smith v. Jones',
            '/Clio/Doe v. Roe',
        ],
        uploaded=['/Clio/Smith v. Jones/Motion.pdf'],
        case_name='Smith v. Jones',
        assertions=lambda res: {
            'statuses should be success': res.status == status.SUCCESS,
            'path should be expected': res.folder_path == '/Clio/Smith v. Jones',
        },
        extensions=lambda self: [
            self.mock_dbx.upload.assert_called_once(),
            self.mock_notifier.notify_upload_success.assert_called_once(),
        ],
    )

    run_upload_subtest(
        'no match triggers manual review routing',
        documents=[mock_document],
        cached_paths=['/Clio/Smith v. Jones'],
        uploaded=['/Clio/Manual Review/Motion.pdf'],
        case_name='Unknown Case',
        assertions=lambda res: {
            'status should be review': res.status == status.MANUAL_REVIEW,
            'path should be review': res.folder_path == '/Manual Review/',
        },
        extensions=lambda self: [
            self.mock_dbx.upload.assert_called_once(),
            self.mock_notifier.notify_manual_review.assert_called_once(),
        ],
    )

    run_upload_subtest(
        'empty document triggers no work early return',
        documents=[],
        assertions=lambda res: {
            'status should be no work': res.status == status.NO_WORK,
        },
    )

    run_upload_subtest(
        'multi-file naming conventions are consistent',
        documents=setup_files({
            'doc1.pdf': b'%PDF-1.4\nDoc1',
            'doc2.pdf': b'%PDF-1.4\nDoc2',
            'doc3.pdf': b'%PDF-1.4\nDoc3',
        }),
        cached_paths=['/Clio/Smith v. Jones'],
        case_name='Smith v. Jones',
        uploaded=[],
        extensions=lambda self: {
            'upload should be called per file': self.mock_dbx.upload.call_count == 3,
        },
    )

    run_upload_subtest(
        'cache refreshes when stale',
        documents=[mock_document],
        stale_cache=True,
        case_name='Smith v. Jones',
        cached_paths=['/Clio/Smith v. Jones'],
        uploaded=[],
        extensions=lambda self: [
            self.mock_dbx.index.assert_called_once(),
            self.mock_cache.refresh.assert_called_once(),
        ],
    )


def test_notification_sent_for_each_outcome(
    run_upload_subtest: UploadDocumentSubtestFixture,
    mock_document: Path,
) -> None:
    """Test notifications are sent for success and manual review."""
    run_upload_subtest(
        'success notifications sent for successful result',
        documents=[mock_document],
        cached_paths=['/Clio/Smith v. Jones'],
        uploaded=[],
        case_name='Smith v. Jones',
        extensions=lambda self: [
            self.mock_notifier.notify_upload_success.assert_called_once(),
        ],
    )

    run_upload_subtest(
        'manual review notification sent for partially successful results',
        documents=[mock_document],
        case_name='Unknown Case',
        extensions=lambda self: [
            self.mock_notifier.notify_manual_review.assert_called_once(),
        ],
    )
