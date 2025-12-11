"""Unit tests for get_record_processor.

Tests cover:
- Processor initialization with GraphClient and state
- Batch processing workflow
- Flag application logic
- Result-to-flag conversion
- Batch result calculations
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rampy import test

from automate.eserv import (
    get_record_processor,
    make_email_record,
    process_pipeline_result,
    status_flag_factory,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from typing import Any

    from automate.eserv.types import *


@pytest.fixture
def mock_pipeline() -> Mock:
    """Create mock Pipeline with config and state."""
    pipeline = Mock(spec=['config', 'state', 'execute'])

    # Mock config with credentials and monitoring
    pipeline.config = Mock()
    pipeline.config.credentials = {
        'msal': Mock(access_token='test_outlook_token'),
    }
    pipeline.config.monitoring = Mock()

    # Mock state tracker
    pipeline.state = Mock(spec=['processed', 'record'])
    pipeline.state.processed = set()

    return pipeline


@pytest.fixture
def mock_graph_client() -> Mock:
    """Create mock GraphClient."""
    return Mock(spec=['fetch_unprocessed_emails', 'apply_flag'])


@pytest.fixture
def sample_email_record() -> EmailRecord:
    """Create sample EmailRecord for testing."""
    return make_email_record(
        uid='email-123',
        sender='court@example.com',
        subject='Test Case Filing',
        received_at=datetime(2025, 1, 1, 12, 0, tzinfo=UTC),
        body='<html><body>Test email</body></html>',
    )


@test.paramdef('evaluator').values(
    (lambda p, mock: p.state is mock.state,),
    (lambda p, mock: p.client is not None,),
)
class TestEmailProcessorInit:
    """Test EmailProcessor initialization."""

    def test_dynamic(
        self,
        evaluator: Callable[[EmailProcessor, Mock], bool],
        mock_pipeline: Mock,
    ) -> None:
        """Test GraphClient created from pipeline config credentials."""
        processor = get_record_processor(pipeline=mock_pipeline)

        assert evaluator(processor, mock_pipeline)


def process_batch_scenario(
    *,
    records: Sequence[EmailRecord],
    expect_succeeded: int,
    expect_total: int | None = None,
    expect_called: int | None = None,
    mock_execute: Callable[[EmailRecord], ProcessedResult] | None = None,
    insert_sample: bool = False,
    verify_flags_applied: bool = False,
    verify_state_recorded: bool = False,
) -> dict[str, Any]:
    """Create test scenario for batch processing."""
    return {
        'params': [records],
        'expect_succeeded': expect_succeeded,
        'expect_total': expect_total,
        'expect_called': expect_called,
        'mock_execute': mock_execute,
        'insert_sample': insert_sample,
        'verify_flags_applied': verify_flags_applied,
        'verify_state_recorded': verify_state_recorded,
    }


@test.scenarios(**{
    'successful batch': process_batch_scenario(
        records=[
            make_email_record(
                uid='email-456',
                sender='court@example.com',
                subject='Another Case',
                received_at=datetime(2025, 1, 2, 12, 0, tzinfo=UTC),
                body='<html><body>Email 2</body></html>',
            ),
            make_email_record(
                uid='email-789',
                sender='court@example.com',
                subject='Third Case',
                received_at=datetime(2025, 1, 3, 12, 0, tzinfo=UTC),
                body='<html><body>Email 3</body></html>',
            ),
        ],
        expect_succeeded=3,
        insert_sample=True,
        verify_flags_applied=True,
        verify_state_recorded=True,
    ),
    'empty batch': process_batch_scenario(
        records=[],
        expect_succeeded=0,
    ),
    'partial failures': process_batch_scenario(
        records=[
            make_email_record(
                uid='email-456',
                sender='court@example.com',
                subject='Another Case',
                received_at=datetime(2025, 1, 2, 12, 0, tzinfo=UTC),
                body='<html><body>Email 2</body></html>',
            ),
            make_email_record(
                uid='email-789',
                sender='court@example.com',
                subject='Third Case',
                received_at=datetime(2025, 1, 3, 12, 0, tzinfo=UTC),
                body='<html><body>Email 3</body></html>',
            ),
        ],
        mock_execute=lambda rec: process_pipeline_result(
            record=make_email_record(uid=rec.uid, sender=rec.sender, subject=rec.subject),
            error={
                'category': 'download',
                'message': 'Network error',
                'uid': rec.uid,
                'timestamp': datetime.now(UTC).isoformat(),
            }
            if rec.uid == 'email-456'
            else None,
        ),
        expect_succeeded=2,
        insert_sample=True,
    ),
})
class TestProcessBatch:
    """Test batch processing workflow."""

    @pytest.mark.asyncio
    async def test(
        self,
        /,
        params: list[Any],
        expect_succeeded: int,
        expect_total: int | None,
        expect_called: int | None,
        mock_execute: Callable[...] | None,
        insert_sample: bool,
        verify_flags_applied: bool,
        verify_state_recorded: bool,
        mock_pipeline: Mock,
        sample_email_record: EmailRecord,
    ) -> None:
        """Test batch processing with various scenarios."""
        records = params[0].copy()

        if insert_sample:
            records.insert(0, sample_email_record)

        # Convert dict records back to EmailRecord objects (rampy serialization workaround)
        email_records = []
        for rec in records:
            if isinstance(rec, dict):
                email_records.append(EmailRecord(**rec))
            else:
                email_records.append(rec)

        mock_client = Mock(spec=['fetch_unprocessed_emails', 'apply_flag'])

        async def mock_fetch_unprocessed(*_: ...):
            await asyncio.sleep(1)
            return email_records

        mock_client.fetch_unprocessed_emails = mock_fetch_unprocessed

        processor = get_record_processor(pipeline=mock_pipeline)
        processor.client = mock_client

        # Configure execute to return ProcessedResult objects
        if mock_execute is not None:
            # Wrap the mock_execute to handle both dict and EmailRecord
            def wrapped_execute(rec):
                # Handle dict serialization from rampy
                if isinstance(rec, dict):
                    rec_obj = make_email_record(**rec)
                    return mock_execute(rec_obj)
                return mock_execute(rec)

            mock_pipeline.execute.side_effect = wrapped_execute
        else:
            # Default: return success ProcessedResult for all records
            def default_execute(rec):
                # Handle dict serialization from rampy
                if isinstance(rec, dict):
                    uid = rec['uid']
                    sender = rec['sender']
                    subject = rec['subject']
                else:
                    uid = rec.uid
                    sender = rec.sender
                    subject = rec.subject

                return process_pipeline_result(
                    record=make_email_record(uid=uid, sender=sender, subject=subject),
                    error=None,
                )

            mock_pipeline.execute.side_effect = default_execute

        expect_total = expect_total or len(records)
        expect_called = expect_called or expect_total

        batch_result = await processor.process_batch(num_days=1)

        assert batch_result.total == expect_total
        assert batch_result.succeeded == expect_succeeded
        assert batch_result.failed == expect_total - expect_succeeded

        assert mock_pipeline.execute.call_count == expect_called

        if verify_flags_applied:
            assert mock_client.apply_flag.call_count == expect_called

        if verify_state_recorded:
            assert mock_pipeline.state.record.call_count == expect_called


@pytest.mark.asyncio
async def test_flag_application_failure_continues_processing(
    mock_pipeline: Mock,
    sample_email_record: EmailRecord,
) -> None:
    """Test that flag application failures don't crash processing."""
    processor = get_record_processor(pipeline=mock_pipeline)
    mock_client = Mock(spec=['fetch_unprocessed_emails', 'apply_flag'])

    async def mock_fetch_unprocessed(*_: ...):
        await asyncio.sleep(1)
        return [sample_email_record]

    # Mock fetch returns 1 email
    mock_client.fetch_unprocessed_emails = mock_fetch_unprocessed

    # Mock execute returns success
    mock_pipeline.execute.return_value = process_pipeline_result(
        record=make_email_record(
            uid=sample_email_record.uid,
            sender=sample_email_record.sender,
            subject=sample_email_record.subject,
        ),
        error=None,
    )

    # Mock flag application raises exception
    mock_client.apply_flag.side_effect = Exception('Flag API error')
    processor.client = mock_client

    # Execute batch processing - should NOT raise
    result = await processor.process_batch(num_days=1)

    # Verify processing completed despite flag failure
    assert result.total == 1
    assert result.succeeded == 1

    # Verify state still recorded
    assert mock_pipeline.state.record.call_count == 1


@test.paramdef('error').values(
    (None,),
    ({'category': 'download', 'message': 'Network timeout'},),  # pyright: ignore[reportArgumentType]
)
class TestResultFlagConversion:
    """Test result to flag conversion logic."""

    def test_dynamic(
        self,
        error: ErrorDict | None,
        mock_pipeline: Mock,
    ) -> None:
        """Test successful result converts to success flag."""
        if error is not None:
            expect_flag = status_flag_factory(error)
        else:
            expect_flag = status_flag_factory()

        result = process_pipeline_result(
            record=make_email_record(
                uid='email-123',
                sender='test@example.com',
                subject='Test',
            ),
            error=error,
        )

        processor = get_record_processor(pipeline=mock_pipeline)
        assert processor._result_to_flag(result) == expect_flag


def batch_result_scenario(
    *,
    count: int,
    error: ErrorDict | None,
    expect_succeeded: int,
) -> dict[str, Any]:
    """Create test scenario for batch result calculations."""
    return {
        'params': [count, error],
        'expect_succeeded': expect_succeeded,
    }


@test.scenarios(**{
    'all successes': batch_result_scenario(count=5, error=None, expect_succeeded=5),
    'all failures': batch_result_scenario(
        count=5,
        error={
            'category': 'download',
            'message': 'Error',
            'timestamp': datetime.now(UTC).isoformat(),
        },
        expect_succeeded=0,
    ),
    'mixed results': batch_result_scenario(count=3, error=None, expect_succeeded=2),
})
class TestBatchResultSummary:
    """Test batch result count calculations."""

    def test(
        self,
        /,
        params: list[Any],
        expect_succeeded: int,
    ) -> None:
        """Test batch result calculations."""
        count: int
        error: ErrorDict | None

        count, error = params

        from automate.eserv.types import BatchResult

        # Create results based on scenario
        if error is None and count == expect_succeeded:
            # All successes
            results: list[ProcessedResult] = [
                process_pipeline_result(
                    record=make_email_record(
                        uid=f'email-{i}',
                        sender='test@example.com',
                        subject='Test',
                    ),
                )
                for i in range(count)
            ]
        elif error and expect_succeeded == 0:
            results: list[ProcessedResult] = []

            for i in range(count):
                record = make_email_record(
                    uid=f'email-{i}',
                    sender='test@example.com',
                    subject='Test',
                )
                error['uid'] = record.uid
                results.append(process_pipeline_result(record=record, error=error))

        else:
            results: list[ProcessedResult] = []

            for i in range(count):
                record = make_email_record(
                    uid=f'email-{i}',
                    sender='test@example.com',
                    subject='Test',
                )

                if i < expect_succeeded:
                    error = None
                else:
                    error = {
                        'uid': record.uid,
                        'category': 'download',
                        'message': 'Error',
                        'timestamp': datetime.now(UTC).isoformat(),
                    }

                results.append(process_pipeline_result(record=record, error=error))

        batch_result = BatchResult(results)

        assert batch_result.total == (batch_size := len(results))
        assert batch_result.succeeded == expect_succeeded
        assert batch_result.failed == batch_size - expect_succeeded
