"""Unit tests for download module.

Tests cover:
- Document download orchestration
- Response processing for PDF, HTML, ASP.NET forms
- ASP.NET form bypass logic
- Filename extraction and sanitization
- Recursion depth limits
- Multi-file pagination
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

from automate.eserv.download import (
    _bypass_aspnet_form,
    _process_accepted_response,
    _process_response,
    download_documents,
)
from automate.eserv.errors.types import DocumentDownloadError

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def mock_response() -> Mock:
    """Create mock HTTP response."""
    response = Mock()
    response.status_code = 200
    response.content = b'%PDF-1.4\nMock PDF content'
    response.text = '<html><body>Test</body></html>'
    response.url = 'http://example.com/document'
    response.headers = Mock()
    response.headers.lower_items = Mock(
        return_value=[
            ('content-type', 'application/pdf'),
            ('content-disposition', 'attachment; filename="document.pdf"'),
        ],
    )
    response.raise_for_status = Mock()
    return response


@pytest.fixture
def mock_session() -> Mock:
    """Create mock requests.Session."""
    session = Mock()
    session.get = Mock()
    session.post = Mock()
    return session


@pytest.fixture
def mock_soup() -> Mock:
    """Create mock BeautifulSoup object."""
    return Mock()


class TestDownloadDocuments:
    """Test download_documents orchestration."""

    def test_successful_single_pdf_download(self, mock_soup: Mock, directory: Path) -> None:
        """Test successful download of single PDF document."""
        # Create temp directory for document store
        temp_path = directory / 'downloads'
        temp_path.mkdir(exist_ok=True)

        # Mock extract_download_info
        mock_info = Mock()
        mock_info.lead_name = 'Motion'
        mock_info.source = 'http://example.com/document.pdf'
        mock_info.store_path = temp_path
        mock_info.unpack.return_value = mock_info.source, mock_info.lead_name, mock_info.store_path

        with (
            patch('automate.eserv.download.extract_download_info', return_value=mock_info),
            patch('requests.sessions.Session') as mock_session_class,
        ):
            # Setup mock session
            mock_session = Mock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.content = b'%PDF-1.4\nTest PDF content'
            mock_response.text = ''
            mock_response.url = 'http://example.com/document.pdf'
            mock_response.headers = Mock()
            mock_response.headers.lower_items = Mock(
                return_value=[
                    ('content-type', 'application/pdf'),
                    ('content-disposition', 'attachment; filename="Motion.pdf"'),
                ],
            )
            mock_response.raise_for_status = Mock()
            mock_session.get.return_value = mock_response
            mock_session.__enter__ = Mock(return_value=mock_session)
            mock_session.__exit__ = Mock(return_value=None)
            mock_session_class.return_value = mock_session

            # Execute download
            result = download_documents(mock_soup)

            # Verify return values
            assert result.lead_name == 'Motion'
            assert result.store_path == temp_path

            # Verify session.get called
            mock_session.get.assert_called_once()

            # Verify file was saved
            assert (temp_path / 'Motion.pdf').exists()

    def test_multi_file_download(self, mock_soup: Mock, directory) -> None:
        """Test download of multiple documents from HTML with links."""
        temp_path = directory / 'downloads'
        temp_path.mkdir(exist_ok=True)

        mock_info = Mock()
        mock_info.lead_name = 'Motion'
        mock_info.source = 'http://example.com/index.html'
        mock_info.store_path = temp_path
        mock_info.unpack.return_value = mock_info.source, mock_info.lead_name, mock_info.store_path
        # Mock extract_links_from_response_html to return 3 links
        mock_links = [
            Mock(source='http://example.com/doc1.pdf'),
            Mock(source='http://example.com/doc2.pdf'),
            Mock(source='http://example.com/doc3.pdf'),
        ]

        with (
            patch('automate.eserv.download.extract_download_info', return_value=mock_info),
            patch('requests.sessions.Session') as mock_session_class,
            patch(
                'automate.eserv.download.extract_links_from_response_html',
                return_value=mock_links,
            ),
        ):
            mock_session = Mock()

            # First call returns HTML with links
            html_response = Mock()
            html_response.status_code = 200
            html_response.content = b'<html>Links</html>'
            html_response.text = '<html><a href="doc1.pdf">Link1</a></html>'
            html_response.url = 'http://example.com/index.html'
            html_response.headers = Mock()
            html_response.headers.lower_items = Mock(return_value=[('content-type', 'text/html')])
            html_response.raise_for_status = Mock()

            # Subsequent calls return PDFs
            def mock_get(url, **_: ...) -> ...:
                if 'index.html' in url:
                    return html_response
                # Return PDF responses
                pdf_response = Mock()
                pdf_response.status_code = 200
                pdf_response.content = b'%PDF-1.4\nTest PDF'
                pdf_response.text = ''
                pdf_response.url = url
                pdf_response.headers = Mock()
                pdf_response.headers.lower_items = Mock(
                    return_value=[
                        ('content-type', 'application/pdf'),
                        (
                            'content-disposition',
                            f'attachment; filename="{url.split("/")[-1]}"',
                        ),
                    ],
                )
                pdf_response.raise_for_status = Mock()
                return pdf_response

            mock_session.get.side_effect = mock_get
            mock_session.__enter__ = Mock(return_value=mock_session)
            mock_session.__exit__ = Mock(return_value=None)
            mock_session_class.return_value = mock_session

            # Execute download
            result = download_documents(mock_soup)

            # Verify return values
            assert result.lead_name == 'Motion'
            assert result.store_path == temp_path

            # Verify session.get called 4 times (1 HTML + 3 PDFs)
            assert mock_session.get.call_count == 4

    def test_missing_download_info_raises_error(self, mock_soup: Mock) -> None:
        """Test that missing download info raises an error."""
        with (
            patch(
                'automate.eserv.download.extract_download_info',
                side_effect=ValueError('No download info'),
            ),
            pytest.raises(ValueError, match='No download info'),
        ):
            download_documents(mock_soup)


class TestProcessResponse:
    """Test response processing logic."""

    def test_pdf_content_type_handling(self, mock_session: Mock, mock_response: Mock) -> None:
        """Test direct PDF response is processed correctly."""
        # Setup PDF response
        mock_response.headers.lower_items = Mock(
            return_value=[
                ('content-type', 'application/pdf'),
                ('content-disposition', 'attachment; filename="document.pdf"'),
            ],
        )

        # Process response
        result = _process_response(mock_session, mock_response)

        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], tuple)
        assert result[0][0] == 'document.pdf'

    def test_html_with_aspnet_form_delegates_to_bypass(
        self,
        mock_session: Mock,
        mock_response: Mock,
    ) -> None:
        """Test HTML with __VIEWSTATE triggers ASP.NET form bypass."""
        # Setup HTML response with ASP.NET form
        mock_response.text = '<html><input id="__VIEWSTATE" value="test" /></html>'
        mock_response.headers.lower_items = Mock(
            return_value=[
                ('content-type', 'text/html'),
            ],
        )

        # Mock POST response after bypass
        post_response = Mock()
        post_response.status_code = 200
        post_response.content = b'%PDF-1.4\nPDF after bypass'
        post_response.text = ''
        post_response.url = 'http://example.com/document'
        post_response.headers = Mock()
        post_response.headers.lower_items = Mock(
            return_value=[
                ('content-type', 'application/pdf'),
                ('content-disposition', 'attachment; filename="document.pdf"'),
            ],
        )
        post_response.raise_for_status = Mock()

        with (
            patch('automate.eserv.download.extract_aspnet_form_data', return_value={}),
            patch(
                'automate.eserv.download.extract_post_request_url',
                return_value='http://example.com/post',
            ),
        ):
            mock_session.post.return_value = post_response

            # Process response
            result = _process_response(mock_session, mock_response)

            # Verify POST was called
            mock_session.post.assert_called_once()

            # Verify result contains PDF
            assert len(result) == 1

    def test_html_with_document_links_recursion(
        self,
        mock_session: Mock,
        mock_response: Mock,
    ) -> None:
        """Test HTML with document links triggers recursive downloads."""
        # Setup HTML response
        mock_response.text = '<html><a href="doc.pdf">Document</a></html>'
        mock_response.headers.lower_items = Mock(
            return_value=[
                ('content-type', 'text/html'),
            ],
        )

        # Mock extracted links
        mock_link = Mock(source='http://example.com/doc.pdf')

        # Mock PDF response
        pdf_response = Mock()
        pdf_response.status_code = 200
        pdf_response.content = b'%PDF-1.4\nTest PDF'
        pdf_response.text = ''
        pdf_response.url = 'http://example.com/doc.pdf'
        pdf_response.headers = Mock()
        pdf_response.headers.lower_items = Mock(
            return_value=[
                ('content-type', 'application/pdf'),
                ('content-disposition', 'attachment; filename="doc.pdf"'),
            ],
        )
        pdf_response.raise_for_status = Mock()

        with patch(
            'automate.eserv.download.extract_links_from_response_html',
            return_value=[mock_link],
        ):
            mock_session.get.return_value = pdf_response

            # Process response
            result = _process_response(mock_session, mock_response)

            # Verify recursive get called
            mock_session.get.assert_called_once_with(
                'http://example.com/doc.pdf',
                allow_redirects=True,
                timeout=30,
            )

            # Verify result
            assert len(result) == 1

    def test_recursion_depth_limit(self, mock_session: Mock, mock_response: Mock) -> None:
        """Test recursion depth limit of 2 is enforced."""
        # Setup HTML response
        mock_response.text = '<html>Test</html>'
        mock_response.headers.lower_items = Mock(
            return_value=[
                ('content-type', 'text/html'),
            ],
        )

        # Process with depth=2 should raise
        with pytest.raises(RuntimeError, match='exceeded maximum recursion depth'):
            _process_response(mock_session, mock_response, depth=2)

    def test_unknown_content_type_raises_error(
        self,
        mock_session: Mock,
        mock_response: Mock,
    ) -> None:
        """Test unknown content-type raises ValueError."""
        # Setup response with unknown content type
        mock_response.headers.lower_items = Mock(
            return_value=[
                ('content-type', 'application/unknown'),
            ],
        )

        # Process response should raise
        with pytest.raises(
            DocumentDownloadError, match="unknown content-type: 'application/unknown'"
        ):
            _process_response(mock_session, mock_response)


class TestBypassAspnetForm:
    """Test ASP.NET form bypass logic."""

    def test_successful_form_bypass_and_post(self, mock_session: Mock) -> None:
        """Test successful ASP.NET form bypass with POST."""
        base_text = '<html><form><input id="__VIEWSTATE" value="test" /></form></html>'
        base_link = 'http://example.com/form'

        # Mock form data extraction
        mock_form_data = {'__VIEWSTATE': 'test', 'email': 'test@example.com'}

        # Mock POST response
        post_response = Mock()
        post_response.status_code = 200
        post_response.content = b'%PDF-1.4\nPDF content'
        post_response.raise_for_status = Mock()

        with (
            patch('automate.eserv.download.extract_aspnet_form_data', return_value=mock_form_data),
            patch(
                'automate.eserv.download.extract_post_request_url',
                return_value='http://example.com/post',
            ),
        ):
            mock_session.post.return_value = post_response

            # Execute bypass
            result = _bypass_aspnet_form(mock_session, base_text, base_link)

            # Verify POST called with correct parameters
            mock_session.post.assert_called_once()
            call_args = mock_session.post.call_args
            assert call_args[0][0] == 'http://example.com/post'
            assert call_args[1]['data'] == mock_form_data

            # Verify response returned
            assert result == post_response

    def test_missing_form_data_raises_error(self, mock_session: Mock) -> None:
        """Test missing form data raises error."""
        base_text = '<html><form></form></html>'
        base_link = 'http://example.com/form'

        # Mock extract_aspnet_form_data to raise error
        with (
            patch(
                'automate.eserv.download.extract_aspnet_form_data',
                side_effect=ValueError('Missing form data'),
            ),
            pytest.raises(ValueError, match='Missing form data'),
        ):
            _bypass_aspnet_form(mock_session, base_text, base_link)

    def test_missing_post_url_raises_error(self, mock_session: Mock) -> None:
        """Test missing POST URL raises error."""
        base_text = '<html><form></form></html>'
        base_link = 'http://example.com/form'

        # Mock extract_post_request_url to raise error
        with (
            patch('automate.eserv.download.extract_aspnet_form_data', return_value={}),
            patch(
                'automate.eserv.download.extract_post_request_url',
                side_effect=ValueError('Missing POST URL'),
            ),
            pytest.raises(ValueError, match='Missing POST URL'),
        ):
            _bypass_aspnet_form(mock_session, base_text, base_link)


class TestProcessAcceptedResponse:
    """Test filename extraction and fallback logic."""

    def test_filename_extraction_from_content_disposition(self) -> None:
        """Test filename extracted from Content-Disposition header."""
        content = b'%PDF-1.4\nTest PDF'
        content_disposition = 'attachment; filename="Motion to Dismiss.pdf"'

        with patch(
            'automate.eserv.download.extract_filename_from_disposition',
            return_value='Motion to Dismiss.pdf',
        ):
            result = _process_accepted_response(content, None, content_disposition)

            # Verify returns tuple with filename
            assert isinstance(result, tuple)
            assert result[0] == 'Motion to Dismiss.pdf'
            assert result[1] == content

    def test_fallback_filename_generation(self) -> None:
        """Test fallback filename generation when no Content-Disposition."""
        content = b'%PDF-1.4\nTest PDF'
        content_disposition = ''

        with patch(
            'automate.eserv.download.extract_filename_from_disposition',
            return_value=None,
        ):
            result = _process_accepted_response(content, 1, content_disposition)

            # Verify returns tuple with fallback filename
            assert isinstance(result, tuple)
            assert result[0] == 'untitled_1'
            assert result[1] == content

    def test_returns_raw_bytes_when_no_filename_or_file_no(self) -> None:
        """Test returns raw bytes when no filename or file_no available."""
        content = b'%PDF-1.4\nTest PDF'
        content_disposition = ''

        with patch(
            'automate.eserv.download.extract_filename_from_disposition',
            return_value=None,
        ):
            result = _process_accepted_response(content, None, content_disposition)

            # Verify returns raw bytes
            assert isinstance(result, bytes)
            assert result == content
