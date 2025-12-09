"""Unit tests for GraphClient.

Tests cover:
- Filter expression correctness
- Pagination logic with @odata.nextLink
- Folder resolution edge cases
- Network error handling and retry logic
- MAPI flag application
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest
from requests.exceptions import HTTPError

from automate.eserv.monitor.client import graph_client_factory
from automate.eserv.monitor.flags import status_flag_factory
from automate.eserv.types import *

if TYPE_CHECKING:
    from automate.eserv.types import GraphClient


@pytest.fixture
def mock_credential() -> Mock:
    """Create mock OAuth credential."""
    cred = Mock(spec=['access_token', 'manager', 'token_type', 'service'])
    cred.access_token = 'test_token_12345'
    cred.token_type = 'Bearer'
    cred.manager = Mock()
    cred.service = Mock()
    return cred


@pytest.fixture
def mock_config() -> Mock:
    """Create mock monitoring config."""
    config = Mock(spec=['graph_api_base_url', 'folder_path'])
    config.graph_api_base_url = 'https://graph.microsoft.com/v1.0'
    config.folder_path = 'Inbox/Test Folder'
    return config


@pytest.fixture
def graph_client(mock_credential: Mock, mock_config: Mock) -> GraphClient:
    """Create GraphClient instance for testing."""
    return graph_client_factory(config=mock_config)


class TestFilterExpression:
    """Test Graph API OData filter expression generation."""

    @patch('automate.eserv.monitor.client.requests.request')
    def test_filter_syntax_uses_odata_operators(
        self,
        mock_request: Mock,
        graph_client: GraphClient,
    ) -> None:
        """Test that filter uses correct OData syntax (eq, not :)."""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{}'
        mock_response.json.return_value = {'value': []}
        mock_request.return_value = mock_response

        # Mock folder resolution to avoid actual API call
        graph_client._folder_id_cache['monitoring'] = 'test_folder_id'

        # Call fetch_unprocessed_emails
        graph_client.fetch_unprocessed_emails(num_days=1, processed_uids=set())

        # Verify request was made with correct filter
        call_args = mock_request.call_args
        params = call_args[1].get('params', {})
        filter_expr = params.get('$filter', '')

        # Check filter uses 'eq true' not ':false'
        assert 'hasAttachments eq true' in filter_expr
        assert 'hasAttachments:false' not in filter_expr
        assert 'NOT hasAttachments:false' not in filter_expr

    @patch('automate.eserv.monitor.client.requests.request')
    def test_filter_includes_date_range(
        self,
        mock_request: Mock,
        graph_client: GraphClient,
    ) -> None:
        """Test that filter includes receivedDateTime constraint."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{}'
        mock_response.json.return_value = {'value': []}
        mock_request.return_value = mock_response

        graph_client._folder_id_cache['monitoring'] = 'test_folder_id'

        # Call with 7 days lookback
        graph_client.fetch_unprocessed_emails(num_days=7, processed_uids=set())

        call_args = mock_request.call_args
        params = call_args[1].get('params', {})
        filter_expr = params.get('$filter', '')

        # Check filter includes receivedDateTime with ge (greater or equal)
        assert 'receivedDateTime ge' in filter_expr


class TestPagination:
    """Test pagination handling with @odata.nextLink."""

    @patch('automate.eserv.monitor.client.requests.request')
    @patch('automate.eserv.monitor.client.requests.get')
    def test_pagination_fetches_all_pages(
        self,
        mock_get: Mock,
        mock_request: Mock,
        graph_client: GraphClient,
    ) -> None:
        """Test that pagination loop fetches all pages."""
        # Mock folder resolution
        graph_client._folder_id_cache['monitoring'] = 'test_folder_id'

        # Mock first page response with nextLink
        page1_response = Mock()
        page1_response.status_code = 200
        page1_response.text = (
            '{"value": [{"id": "msg1"}], "@odata.nextLink": "https://next-page-url"}'
        )
        page1_response.json.return_value = {
            'value': [
                {
                    'id': 'msg1',
                    'from': {'emailAddress': {'address': 'test@example.com'}},
                    'subject': 'Test 1',
                    'receivedDateTime': datetime.now(UTC).isoformat(),
                },
            ],
            '@odata.nextLink': 'https://next-page-url',
        }

        # Mock second page response (no nextLink)
        page2_response = Mock()
        page2_response.status_code = 200
        page2_response.text = '{"value": [{"id": "msg2"}]}'
        page2_response.json.return_value = {
            'value': [
                {
                    'id': 'msg2',
                    'from': {'emailAddress': {'address': 'test@example.com'}},
                    'subject': 'Test 2',
                    'receivedDateTime': datetime.now(UTC).isoformat(),
                },
            ],
        }

        # Mock body fetch responses for both messages
        body1_response = Mock()
        body1_response.status_code = 200
        body1_response.text = '{}'
        body1_response.json.return_value = {'body': {'content': '<html>Test body 1</html>'}}

        body2_response = Mock()
        body2_response.status_code = 200
        body2_response.text = '{}'
        body2_response.json.return_value = {'body': {'content': '<html>Test body 2</html>'}}

        # Set up mock responses in sequence
        mock_request.side_effect = [page1_response, body1_response, body2_response]
        mock_get.return_value = page2_response

        # Fetch emails
        records = graph_client.fetch_unprocessed_emails(num_days=1, processed_uids=set())

        # Should have fetched both pages
        assert len(records) == 2
        assert records[0].uid == 'msg1'
        assert records[1].uid == 'msg2'

        # Verify nextLink was used
        mock_get.assert_called_once_with(
            'https://next-page-url',
            headers={
                'Authorization': 'Bearer test_token_12345',
                'Content-Type': 'application/json',
            },
            timeout=30,
        )

    @patch('automate.eserv.monitor.client.requests.request')
    def test_pagination_stops_when_no_nextlink(
        self,
        mock_request: Mock,
        graph_client: GraphClient,
    ) -> None:
        """Test that pagination stops when @odata.nextLink is absent."""
        graph_client._folder_id_cache['monitoring'] = 'test_folder_id'

        # Mock single page response without nextLink
        response = Mock()
        response.status_code = 200
        response.text = '{}'
        response.json.return_value = {'value': []}
        mock_request.return_value = response

        records = graph_client.fetch_unprocessed_emails(num_days=1, processed_uids=set())

        # Should only make one request (no pagination)
        assert mock_request.call_count == 1
        assert len(records) == 0


class TestFolderResolution:
    """Test folder path resolution to folder ID."""

    @patch('automate.eserv.monitor.client.requests.request')
    def test_resolve_nested_folder_path(
        self,
        mock_request: Mock,
        graph_client: GraphClient,
    ) -> None:
        """Test resolving deeply nested folder paths."""
        # Mock responses for each level of folder hierarchy
        # Level 1: Inbox
        level1_response = Mock()
        level1_response.status_code = 200
        level1_response.json.return_value = {'value': [{'id': 'inbox_id', 'displayName': 'Inbox'}]}

        # Level 2: Test Folder
        level2_response = Mock()
        level2_response.status_code = 200
        level2_response.json.return_value = {
            'value': [{'id': 'test_folder_id', 'displayName': 'Test Folder'}],
        }

        mock_request.side_effect = [level1_response, level2_response]

        folder_id = graph_client.resolve_monitoring_folder_id()

        assert folder_id == 'test_folder_id'
        assert mock_request.call_count == 2

    @patch('automate.eserv.monitor.client.requests.request')
    def test_resolve_folder_raises_on_missing_folder(
        self,
        mock_request: Mock,
        graph_client: GraphClient,
    ) -> None:
        """Test that missing folder raises FileNotFoundError."""
        # Mock empty response (folder not found)
        response = Mock()
        response.status_code = 200
        response.json.return_value = {'value': []}
        mock_request.return_value = response

        with pytest.raises(FileNotFoundError):
            graph_client.resolve_monitoring_folder_id()

    @patch('automate.eserv.monitor.client.requests.request')
    def test_folder_id_caching(
        self,
        mock_request: Mock,
        graph_client: GraphClient,
    ) -> None:
        """Test that folder ID is cached after first resolution."""
        response = Mock()
        response.status_code = 200
        response.json.return_value = {'value': [{'id': 'cached_id', 'displayName': 'Inbox'}]}
        mock_request.return_value = response

        # First call should hit API
        folder_id1 = graph_client.resolve_monitoring_folder_id()

        # Second call should use cache
        folder_id2 = graph_client.resolve_monitoring_folder_id()

        assert folder_id1 == folder_id2 == 'cached_id'
        # Should only make API calls for first resolution (2 levels in path)
        assert mock_request.call_count == 2


class TestErrorHandling:
    """Test network error categorization and retry logic."""

    @patch('automate.eserv.monitor.client.requests.request')
    def test_retries_on_429_rate_limit(
        self,
        mock_request: Mock,
        graph_client: GraphClient,
    ) -> None:
        """Test that 429 errors trigger retry with exponential backoff."""
        # First attempt: 429 error
        error_response = Mock()
        error_response.status_code = 429
        error1 = HTTPError(response=error_response)

        # Second attempt: success
        success_response = Mock()
        success_response.status_code = 200
        success_response.text = '{}'
        success_response.json.return_value = {'value': 'success'}

        mock_request.side_effect = [error1, success_response]

        result = graph_client._request('GET', '/test')

        assert result == {'value': 'success'}
        assert mock_request.call_count == 2

    @patch('automate.eserv.monitor.client.requests.request')
    def test_retries_on_500_server_error(
        self,
        mock_request: Mock,
        graph_client: GraphClient,
    ) -> None:
        """Test that 5xx errors trigger retry."""
        error_response = Mock()
        error_response.status_code = 503
        error = HTTPError(response=error_response)

        success_response = Mock()
        success_response.status_code = 200
        success_response.text = '{}'
        success_response.json.return_value = {'data': 'ok'}

        mock_request.side_effect = [error, success_response]

        result = graph_client._request('GET', '/test')

        assert result == {'data': 'ok'}
        assert mock_request.call_count == 2

    @patch('automate.eserv.monitor.client.requests.request')
    def test_no_retry_on_400_bad_request(
        self,
        mock_request: Mock,
        graph_client: GraphClient,
    ) -> None:
        """Test that 4xx errors do not trigger retry."""
        error_response = Mock()
        error_response.status_code = 400
        error = HTTPError(response=error_response)

        mock_request.side_effect = error

        with pytest.raises(HTTPError):
            graph_client._request('GET', '/test')

        # Should only attempt once (no retries)
        assert mock_request.call_count == 1

    @patch('automate.eserv.monitor.client.requests.request')
    def test_no_retry_on_401_unauthorized(
        self,
        mock_request: Mock,
        graph_client: GraphClient,
    ) -> None:
        """Test that 401 errors do not trigger retry."""
        error_response = Mock()
        error_response.status_code = 401
        error = HTTPError(response=error_response)

        mock_request.side_effect = error

        with pytest.raises(HTTPError):
            graph_client._request('GET', '/test')

        assert mock_request.call_count == 1

    @patch('automate.eserv.monitor.client.requests.request')
    @patch('automate.eserv.monitor.client.time.sleep')
    def test_exponential_backoff_delays(
        self,
        mock_sleep: Mock,
        mock_request: Mock,
        graph_client: GraphClient,
    ) -> None:
        """Test that retry delays follow exponential backoff."""
        error_response = Mock()
        error_response.status_code = 429
        error = HTTPError(response=error_response)

        # All attempts fail
        mock_request.side_effect = [error, error, error]

        with pytest.raises(HTTPError):
            graph_client._request('GET', '/test')

        # Should have called sleep with exponential delays
        # 1st retry: 1.0 * 2^0 = 1.0
        # 2nd retry: 1.0 * 2^1 = 2.0
        assert mock_sleep.call_count == 2
        delays = [call[0][0] for call in mock_sleep.call_args_list]
        assert delays == [1.0, 2.0]


class TestMAPIFlags:
    """Test MAPI flag application."""

    @patch('automate.eserv.monitor.client.requests.request')
    def test_apply_flag_uses_correct_format(
        self,
        mock_request: Mock,
        graph_client: GraphClient,
    ) -> None:
        """Test that apply_flag sends correct JSON structure."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{}'
        mock_response.json.return_value = {}
        mock_request.return_value = mock_response

        # Create a test flag (success flag)
        test_flag = status_flag_factory(success=True)

        graph_client.apply_flag('test_email_id', test_flag)

        # Verify request structure
        call_args = mock_request.call_args
        assert call_args[0][0] == 'PATCH'
        assert '/me/messages/test_email_id' in call_args[0][1]

        json_data = call_args[1]['json']
        assert 'singleValueExtendedProperties' in json_data
        assert isinstance(json_data['singleValueExtendedProperties'], list)
        assert len(json_data['singleValueExtendedProperties']) == 1


class TestHTMLBodyValidation:
    """Test HTML body validation."""

    @patch('automate.eserv.monitor.client.requests.request')
    def test_raises_on_empty_html_body(
        self,
        mock_request: Mock,
        graph_client: GraphClient,
    ) -> None:
        """Test that empty HTML body raises ValueError."""
        graph_client._folder_id_cache['monitoring'] = 'test_folder_id'

        # Mock message list response
        list_response = Mock()
        list_response.status_code = 200
        list_response.json.return_value = {
            'value': [
                {
                    'id': 'msg1',
                    'from': {'emailAddress': {'address': 'test@example.com'}},
                    'subject': 'Test',
                    'receivedDateTime': datetime.now(UTC).isoformat(),
                },
            ],
        }

        # Mock body fetch with empty content
        body_response = Mock()
        body_response.status_code = 200
        body_response.json.return_value = {'body': {'content': ''}}

        mock_request.side_effect = [list_response, body_response]

        with pytest.raises(ValueError, match='has no HTML body'):
            graph_client.fetch_unprocessed_emails(num_days=1, processed_uids=set())
