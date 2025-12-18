"""Test suite for util/email_record.py factory function.

Tests cover:
- EmailInfo creation (without body)
- EmailRecord creation (with body)
- Default value handling
- UID generation
- Timestamp handling
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from automate.eserv.util.email_record import make_email_record

if TYPE_CHECKING:
    from automate.eserv.types import EmailInfo, EmailRecord


class TestEmailInfoCreation:
    """Test EmailInfo creation without body."""

    def test_creates_email_info_without_body(self) -> None:
        """Test factory creates EmailInfo when body not provided."""
        info = make_email_record()

        assert hasattr(info, 'uid')
        assert hasattr(info, 'sender')
        assert hasattr(info, 'subject')
        # Should NOT have html_body attribute (EmailInfo, not EmailRecord)
        assert not hasattr(info, 'html_body')

    def test_uses_provided_uid(self) -> None:
        """Test factory uses provided UID."""
        info = make_email_record(uid='test-uid-123')

        assert info.uid == 'test-uid-123'

    def test_generates_uid_when_not_provided(self) -> None:
        """Test factory generates UUID when UID not provided."""
        info = make_email_record()

        assert info.uid is not None
        assert len(info.uid) > 0
        assert '-' in info.uid  # UUID format

    def test_uses_provided_sender(self) -> None:
        """Test factory uses provided sender."""
        info = make_email_record(sender='test@example.com')

        assert info.sender == 'test@example.com'

    def test_defaults_sender_to_unknown(self) -> None:
        """Test factory defaults sender to 'unknown'."""
        info = make_email_record()

        assert info.sender == 'unknown'

    def test_uses_provided_subject(self) -> None:
        """Test factory uses provided subject."""
        info = make_email_record(subject='Test Subject')

        assert info.subject == 'Test Subject'

    def test_defaults_subject_to_empty_string(self) -> None:
        """Test factory defaults subject to empty string."""
        info = make_email_record()

        assert info.subject == ''

    def test_handles_none_values(self) -> None:
        """Test factory converts None values to defaults."""
        info = make_email_record(sender=None, subject=None)

        assert info.sender == 'unknown'
        assert info.subject == ''


class TestEmailRecordCreation:
    """Test EmailRecord creation with body."""

    def test_creates_email_record_with_body(self) -> None:
        """Test factory creates EmailRecord when body provided."""
        record = make_email_record(body='<html><body>Test</body></html>')

        assert hasattr(record, 'uid')
        assert hasattr(record, 'sender')
        assert hasattr(record, 'subject')
        assert hasattr(record, 'received_at')
        assert hasattr(record, 'html_body')

    def test_stores_body_content(self) -> None:
        """Test factory stores body content."""
        body = '<html><body>Test email content</body></html>'
        record = make_email_record(body=body)

        assert record.html_body == body

    def test_uses_provided_received_at(self) -> None:
        """Test factory uses provided received_at timestamp."""
        timestamp = datetime(2025, 1, 1, 12, 0, tzinfo=UTC)
        record = make_email_record(body='<html>Test</html>', received_at=timestamp)

        assert record.received_at == timestamp

    def test_generates_received_at_when_not_provided(self) -> None:
        """Test factory generates current timestamp when not provided."""
        before = datetime.now(UTC)
        record = make_email_record(body='<html>Test</html>')
        after = datetime.now(UTC)

        assert before <= record.received_at <= after

    def test_combines_all_parameters(self) -> None:
        """Test factory handles all parameters together."""
        timestamp = datetime(2025, 1, 1, 12, 0, tzinfo=UTC)
        record = make_email_record(
            body='<html>Test</html>',
            uid='test-123',
            sender='court@example.com',
            subject='Case Filing',
            received_at=timestamp,
        )

        assert record.uid == 'test-123'
        assert record.sender == 'court@example.com'
        assert record.subject == 'Case Filing'
        assert record.received_at == timestamp
        assert record.html_body == '<html>Test</html>'

    def test_generates_uid_for_record_when_not_provided(self) -> None:
        """Test factory generates UUID for EmailRecord when UID not provided."""
        record = make_email_record(body='<html>Test</html>')

        assert record.uid is not None
        assert len(record.uid) > 0
        assert '-' in record.uid  # UUID format

    def test_handles_none_values_for_record(self) -> None:
        """Test factory converts None values to defaults for EmailRecord."""
        record = make_email_record(
            body='<html>Test</html>',
            sender=None,
            subject=None,
        )

        assert record.sender == 'unknown'
        assert record.subject == ''


class TestOverloadBehavior:
    """Test type overload behavior based on parameters."""

    def test_returns_different_types_based_on_body(self) -> None:
        """Test factory returns EmailInfo without body, EmailRecord with body."""
        info = make_email_record()
        record = make_email_record(body='<html>Test</html>')

        # EmailInfo should not have html_body attribute
        assert not hasattr(info, 'html_body')

        # EmailRecord should have html_body attribute
        assert hasattr(record, 'html_body')

    def test_generated_uids_are_unique(self) -> None:
        """Test factory generates unique UIDs for each call."""
        info1 = make_email_record()
        info2 = make_email_record()

        assert info1.uid != info2.uid

    def test_record_uid_matches_when_explicitly_provided(self) -> None:
        """Test both Info and Record use same UID when provided."""
        uid = 'test-uid-123'

        info = make_email_record(uid=uid)
        record = make_email_record(body='<html>Test</html>', uid=uid)

        assert info.uid == uid
        assert record.uid == uid
