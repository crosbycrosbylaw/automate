"""Test suite for util/email_state.py email processing state tracking."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from automate.eserv.record import record_factory
from automate.eserv.util import state_tracker_factory

if TYPE_CHECKING:
    from pathlib import Path

    from automate.eserv.types import EmailRecord


def create_test_record(uid: str, subject: str) -> EmailRecord:
    """Create test EmailRecord."""
    return record_factory(
        uid=uid,
        sender='court@example.com',
        subject=subject,
        received_at=datetime.now(UTC),
        body='<html>test</html>',
    )


class TestEmailStateBasic:
    """Test basic email state tracking operations."""

    def test_unprocessed_uid_returns_false(self, directory: Path) -> None:
        """Test is_processed returns False for unprocessed UID."""
        state_file = directory / 'email_state.json'
        state = state_tracker_factory(state_file)

        assert not state.is_processed('basic-test-789')

    def test_mark_and_check_processed(self, directory: Path) -> None:
        """Test marking UID as processed and checking status."""
        state_file = directory / 'email_state.json'
        state = state_tracker_factory(state_file)

        record = create_test_record('basic-test-789', 'Test Case')
        state.record(record)

        assert state.is_processed('basic-test-789')
        assert 'basic-test-789' in state.processed


class TestEmailStateDuplicates:
    """Test duplicate email detection."""

    def test_duplicate_recording_idempotent(self, directory: Path) -> None:
        """Test recording same UID twice is idempotent."""
        state_file = directory / 'email_state.json'
        state = state_tracker_factory(state_file)

        record = create_test_record('duplicate-test-456', 'Duplicate Test')

        # Record twice
        state.record(record)
        state.record(record)

        # Should still only be processed once
        assert state.is_processed('duplicate-test-456')
        assert len(state.processed) == 1


class TestEmailStatePersistence:
    """Test state persistence across instances."""

    def test_state_persists_across_instances(self, directory: Path) -> None:
        """Test state persists when creating new tracker instance."""
        state_file = directory / 'email_state.json'

        # Create first instance and record email
        state1 = state_tracker_factory(state_file)
        record = create_test_record('test-uid-123', 'Persist Test')
        state1.record(record)

        # Create new instance and verify persistence
        state2 = state_tracker_factory(state_file)
        assert state2.is_processed('test-uid-123')
        assert 'test-uid-123' in state2.processed


class TestEmailStateClearFlags:
    """Test clear_flags functionality for manual reprocessing."""

    def test_clear_flags_removes_uid(self, directory: Path) -> None:
        """Test clear_flags removes UID from processed set."""
        state_file = directory / 'email_state.json'
        state = state_tracker_factory(state_file)

        # Record email
        record = create_test_record('clear-test-123', 'Test Case')
        state.record(record)
        assert state.is_processed('clear-test-123')

        # Clear flags
        state.clear_flags('clear-test-123')
        assert not state.is_processed('clear-test-123')
        assert 'clear-test-123' not in state.processed

    def test_clear_flags_persists_removal(self, directory: Path) -> None:
        """Test clear_flags persists removal across instances."""
        state_file = directory / 'email_state.json'

        # Record and clear in first instance
        state1 = state_tracker_factory(state_file)
        record = create_test_record('persist-clear-456', 'Test Case')
        state1.record(record)
        state1.clear_flags('persist-clear-456')

        # Verify removal persists in new instance
        state2 = state_tracker_factory(state_file)
        assert not state2.is_processed('persist-clear-456')

    def test_clear_flags_nonexistent_uid_is_noop(self, directory: Path) -> None:
        """Test clear_flags with nonexistent UID does not raise error."""
        state_file = directory / 'email_state.json'
        state = state_tracker_factory(state_file)

        # Should not raise exception
        state.clear_flags('nonexistent-uid-789')
        assert not state.is_processed('nonexistent-uid-789')
