"""Unit tests for GraphClient.

Tests cover:
- GraphClient initialization with Config
- Async folder resolution
- Async email fetching with filtering
- MAPI flag application
- Request builder pattern with pagination
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, Mock, patch

import pytest

from automate.eserv.monitor.client import GraphClient, make_graph_client
from automate.eserv.monitor.flags import status_flag_factory
from automate.eserv.types import *


@pytest.fixture
def graph_client(mock_config: Config) -> GraphClient:
    """Create GraphClient instance for testing."""
    return make_graph_client(mock_config)


class TestGraphClientInit:
    """Test GraphClient initialization."""

    def test_client_initialization(self, graph_client: GraphClient) -> None:
        """Test GraphClient initializes with config."""
        assert graph_client.config is not None
        assert graph_client.path_segments == ['Inbox', 'Test']
        assert graph_client._folder_id_cache == {}

    def test_cutoff_date_calculated(self, mock_config: Config) -> None:
        """Test cutoff date is calculated from monitor_num_days."""
        client = GraphClient(mock_config)

        now = datetime.now(UTC)
        expected_days = mock_config.monitor_num_days

        # Cutoff should be approximately N days ago
        delta = now - client.cutoff
        assert delta.days == expected_days

    def test_client_property_creates_graph_service_client(
        self,
        graph_client: GraphClient,
    ) -> None:
        """Test client property creates GraphServiceClient."""
        with patch('automate.eserv.monitor.client.GraphServiceClient') as mock_gsc:
            _ = graph_client.client
            mock_gsc.assert_called_once_with(graph_client.config.creds.msal)


class TestFolderResolution:
    """Test async folder resolution."""

    @pytest.mark.asyncio
    async def test_resolve_monitoring_folder_caches_result(
        self,
        graph_client: GraphClient,
    ) -> None:
        """Test folder ID is cached after first resolution."""
        mock_resolve = Mock(return_value='cached-folder-id')

        with patch('automate.eserv.monitor.utils.resolve_mail_folders', mock_resolve):
            # Mock the request.get() to return empty folder list
            mock_request = Mock()
            mock_request.get = AsyncMock(
                return_value=[
                    Mock(
                        display_name='Inbox',
                        id='test-inbox-id',
                        child_folder_count=1,
                        child_folders=[Mock(display_name='Test', id='cached-folder-id')],
                    )
                ]
            )

            with patch.object(graph_client, 'request', return_value=mock_request):
                # First call
                folder_id1 = await graph_client._resolve_monitoring_folder_id()

                # Second call should use cache
                folder_id2 = await graph_client._resolve_monitoring_folder_id()

                assert folder_id1 == folder_id2 == 'cached-folder-id'
                # Should only resolve once
                mock_resolve.assert_called_once()

    @pytest.mark.asyncio
    async def test_resolve_folder_raises_on_failure(
        self,
        graph_client: GraphClient,
    ) -> None:
        """Test FileNotFoundError raised when folder cannot be resolved."""
        with patch(
            'automate.eserv.monitor.utils.resolve_mail_folders',
            side_effect=ValueError('Folder not found'),
        ):
            mock_request = Mock()
            mock_request.get = AsyncMock(return_value=[])

            with (
                patch.object(graph_client, 'request', return_value=mock_request),
                pytest.raises(FileNotFoundError),
            ):
                await graph_client._resolve_monitoring_folder_id()


class TestFetchUnprocessedEmails:
    """Test async email fetching."""

    @pytest.mark.asyncio
    async def test_fetch_emails_with_filter(
        self,
        graph_client: GraphClient,
    ) -> None:
        """Test emails are fetched with date filter."""
        # Mock folder resolution
        graph_client._folder_id_cache['monitoring'] = 'test-folder-id'

        # Create mock message
        mock_message = Mock()
        mock_message.id = 'msg-123'
        mock_message.sender = Mock()
        mock_message.sender.email_address = Mock()
        mock_message.sender.email_address.address = 'test@example.com'
        mock_message.subject = 'Test Subject'
        mock_message.body = Mock()
        mock_message.body.content = '<html><body>Test</body></html>'
        mock_message.received_date_time = datetime.now(UTC)

        # Mock request.collect()
        mock_request = Mock()
        mock_request.collect = AsyncMock(return_value=[mock_message])

        with patch.object(graph_client, 'request', return_value=mock_request):
            records = await graph_client.fetch_unprocessed_emails(processed_uids=set())

            assert len(records) == 1
            assert records[0].uid == 'msg-123'
            assert records[0].sender == 'test@example.com'
            assert records[0].subject == 'Test Subject'

    @pytest.mark.asyncio
    async def test_fetch_excludes_processed_uids(
        self,
        graph_client: GraphClient,
    ) -> None:
        """Test processed UIDs are filtered out."""
        graph_client._folder_id_cache['monitoring'] = 'test-folder-id'

        # Create two messages, one already processed
        msg1 = Mock()
        msg1.id = 'msg-processed'
        msg1.sender = Mock()
        msg1.sender.email_address = Mock()
        msg1.sender.email_address.address = 'test@example.com'
        msg1.subject = 'Processed'
        msg1.body = Mock()
        msg1.body.content = '<html>Test</html>'
        msg1.received_date_time = datetime.now(UTC)

        msg2 = Mock()
        msg2.id = 'msg-new'
        msg2.sender = Mock()
        msg2.sender.email_address = Mock()
        msg2.sender.email_address.address = 'test@example.com'
        msg2.subject = 'New'
        msg2.body = Mock()
        msg2.body.content = '<html>Test</html>'
        msg2.received_date_time = datetime.now(UTC)

        mock_request = Mock()
        mock_request.collect = AsyncMock(return_value=[msg1, msg2])

        with patch.object(graph_client, 'request', return_value=mock_request):
            records = await graph_client.fetch_unprocessed_emails(processed_uids={'msg-processed'})

            # Should only return the new message
            assert len(records) == 1
            assert records[0].uid == 'msg-new'

    @pytest.mark.asyncio
    async def test_fetch_raises_on_missing_html_body(
        self,
        graph_client: GraphClient,
    ) -> None:
        """Test ValueError raised when message has no HTML body."""
        graph_client._folder_id_cache['monitoring'] = 'test-folder-id'

        # Message with no body content
        msg = Mock()
        msg.id = 'msg-123'
        msg.body = Mock()
        msg.body.content = None  # Missing body

        mock_request = Mock()
        mock_request.collect = AsyncMock(return_value=[msg])

        with (
            patch.object(graph_client, 'request', return_value=mock_request),
            pytest.raises(ValueError, match='Missing HTML body'),
        ):
            await graph_client.fetch_unprocessed_emails(processed_uids=set())


class TestApplyFlag:
    """Test MAPI flag application."""

    @pytest.mark.asyncio
    async def test_apply_flag_success(
        self,
        graph_client: GraphClient,
    ) -> None:
        """Test flag is applied to email."""
        flag = status_flag_factory(success=True)

        # Mock the Graph SDK client
        mock_patch = AsyncMock()
        graph_client.client = Mock()
        graph_client.client.me = Mock()
        graph_client.client.me.messages = Mock()
        graph_client.client.me.messages.by_message_id = Mock(return_value=Mock())
        graph_client.client.me.messages.by_message_id.return_value.patch = mock_patch

        await graph_client.apply_flag('msg-123', flag)

        # Verify patch was called
        mock_patch.assert_called_once()


class TestRequestBuilder:
    """Test request builder pattern."""

    def test_request_builder_creation(
        self,
        graph_client: GraphClient,
    ) -> None:
        """Test request builder is created with proper parameters."""
        mock_builder = Mock()

        request = graph_client.request(
            mock_builder,
            filter='test filter',
            top=50,
            select=['id', 'subject'],
        )

        assert request.builder == mock_builder
        assert request.filter == 'test filter'
        assert request.top == 50
        assert request.select == ['id', 'subject']

    @pytest.mark.asyncio
    async def test_request_collect_handles_pagination(
        self,
        graph_client: GraphClient,
    ) -> None:
        """Test collect() follows pagination links."""
        mock_builder = Mock()

        # First response with nextLink
        mock_response1 = Mock()
        mock_response1.odata_next_link = 'https://next-page'
        mock_response1.value = [Mock(id='item1')]

        # Second response without nextLink
        mock_response2 = Mock()
        mock_response2.odata_next_link = None
        mock_response2.value = [Mock(id='item2')]

        mock_get = AsyncMock()

        async def mock_get_side_effect(*_args, **_kwds):
            await asyncio.sleep(1)
            mock_get.call_count = getattr(mock_get, 'call_count', 0) + 1
            return mock_response1 if mock_get.call_count == 1 else mock_response2

        mock_get.side_effect = mock_get_side_effect
        mock_builder.get = mock_get

        mock_builder.with_url = Mock(return_value=mock_builder)

        request = graph_client.request(mock_builder)
        results = await request.collect()

        # Should have collected both pages
        assert len(results) == 2
        assert results[0].id == 'item1'
        assert results[1].id == 'item2'

        # Verify with_url was called with nextLink
        mock_builder.with_url.assert_called_once_with('https://next-page')
