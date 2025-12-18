"""Test suite for util/notifications.py email notification system.

Tests cover:
- Notifier initialization with SMTP config
- Email sending (success and failure paths)
- Success notification formatting
- Manual review notification formatting
- Error notification formatting
- SMTP connection handling (TLS and non-TLS)
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import Mock, call, patch

import pytest

from automate.eserv.util.notifications import Notifier

if TYPE_CHECKING:
    from automate.eserv.types import SMTPConfig


@pytest.fixture
def smtp_config() -> SMTPConfig:
    """Create mock SMTP configuration."""
    return {
        'server': 'smtp.example.com',
        'port': 587,
        'sender': 'notify@example.com',
        'recipient': 'user@example.com',
        'username': 'notify@example.com',
        'password': 'password123',
        'use_tls': True,
    }


@pytest.fixture
def smtp_config_no_auth() -> SMTPConfig:
    """Create SMTP configuration without authentication."""
    return {
        'server': 'smtp.example.com',
        'port': 25,
        'sender': 'notify@example.com',
        'recipient': 'user@example.com',
        'username': None,
        'password': None,
        'use_tls': False,
    }


class TestNotifierInitialization:
    """Test Notifier initialization."""

    def test_initialization_with_smtp_config(self, smtp_config: SMTPConfig) -> None:
        """Test Notifier initializes with SMTP config."""
        notifier = Notifier(smtp=smtp_config)

        assert notifier.smtp is smtp_config
        assert notifier.prefix == '[automate.eserv]'
        assert notifier.verbose is True

    def test_initialization_with_custom_prefix(self, smtp_config: SMTPConfig) -> None:
        """Test Notifier accepts custom prefix."""
        notifier = Notifier(smtp=smtp_config, prefix='[TEST]')

        assert notifier.prefix == '[TEST]'

    def test_initialization_with_verbose_false(self, smtp_config: SMTPConfig) -> None:
        """Test Notifier accepts verbose=False."""
        notifier = Notifier(smtp=smtp_config, verbose=False)

        assert notifier.verbose is False


class TestEmailSending:
    """Test email sending functionality."""

    def test_send_email_with_tls(self, smtp_config: SMTPConfig) -> None:
        """Test email sending with TLS enabled."""
        notifier = Notifier(smtp=smtp_config)

        with patch('automate.eserv.util.notifications.smtplib.SMTP') as mock_smtp_class:
            mock_server = Mock()
            mock_smtp_class.return_value = mock_server

            notifier._send_email('Test Subject', 'Test Body')

            # Verify SMTP server created with correct host/port
            mock_smtp_class.assert_called_once_with('smtp.example.com', 587)

            # Verify TLS started
            mock_server.starttls.assert_called_once()

            # Verify login called
            mock_server.login.assert_called_once_with('notify@example.com', 'password123')

            # Verify message sent
            mock_server.send_message.assert_called_once()

            # Verify connection closed
            mock_server.quit.assert_called_once()

    def test_send_email_without_tls(self, smtp_config_no_auth: SMTPConfig) -> None:
        """Test email sending without TLS."""
        notifier = Notifier(smtp=smtp_config_no_auth)

        with patch('automate.eserv.util.notifications.smtplib.SMTP') as mock_smtp_class:
            mock_server = Mock()
            mock_smtp_class.return_value = mock_server

            notifier._send_email('Test Subject', 'Test Body')

            # Verify SMTP server created
            mock_smtp_class.assert_called_once_with('smtp.example.com', 25)

            # Verify TLS not started
            mock_server.starttls.assert_not_called()

            # Verify no login (no username/password)
            mock_server.login.assert_not_called()

            # Verify message sent
            mock_server.send_message.assert_called_once()

    def test_send_email_handles_exception(self, smtp_config: SMTPConfig) -> None:
        """Test email sending handles SMTP exceptions gracefully."""
        notifier = Notifier(smtp=smtp_config)

        with patch('automate.eserv.util.notifications.smtplib.SMTP') as mock_smtp_class:
            mock_smtp_class.side_effect = Exception('SMTP connection failed')

            # Should not raise - exceptions are logged
            notifier._send_email('Test Subject', 'Test Body')


class TestUploadSuccessNotification:
    """Test upload success notification."""

    def test_notify_upload_success_formats_message(self, smtp_config: SMTPConfig) -> None:
        """Test success notification formats message correctly."""
        notifier = Notifier(smtp=smtp_config)

        with patch.object(notifier, '_send_email') as mock_send:
            notifier.notify_upload_success(
                case_name='Smith v. Jones',
                folder_path='/Clio/Smith v. Jones',
                file_count=3,
            )

            # Verify _send_email called with correct subject
            assert mock_send.call_count == 1
            subject, body = mock_send.call_args[0]

            assert subject == 'Upload Success: Smith v. Jones'
            assert 'Smith v. Jones' in body
            assert '/Clio/Smith v. Jones' in body
            assert '3' in body


class TestManualReviewNotification:
    """Test manual review notification."""

    def test_notify_manual_review_basic(self, smtp_config: SMTPConfig) -> None:
        """Test manual review notification with basic info."""
        notifier = Notifier(smtp=smtp_config)

        with patch.object(notifier, '_send_email') as mock_send:
            notifier.notify_manual_review(
                case_name='Doe v. Roe',
                reason='No matching folder found',
            )

            subject, body = mock_send.call_args[0]

            assert subject == 'Manual Review Required: Doe v. Roe'
            assert 'Doe v. Roe' in body
            assert 'No matching folder found' in body

    def test_notify_manual_review_with_details_verbose(self, smtp_config: SMTPConfig) -> None:
        """Test manual review notification includes details when verbose."""
        notifier = Notifier(smtp=smtp_config, verbose=True)

        with patch.object(notifier, '_send_email') as mock_send:
            notifier.notify_manual_review(
                case_name='Doe v. Roe',
                reason='Fuzzy match below threshold',
                details={'threshold': '0.8', 'best_match': '0.65'},
            )

            subject, body = mock_send.call_args[0]

            assert 'threshold' in body
            assert '0.8' in body
            assert 'best_match' in body

    def test_notify_manual_review_without_details_when_not_verbose(
        self,
        smtp_config: SMTPConfig,
    ) -> None:
        """Test manual review notification excludes detail values when not verbose."""
        notifier = Notifier(smtp=smtp_config, verbose=False)

        with patch.object(notifier, '_send_email') as mock_send:
            notifier.notify_manual_review(
                case_name='Doe v. Roe',
                reason='Match score too low',
                details={'best_match_score': '0.65', 'min_threshold': '0.8'},
            )

            subject, body = mock_send.call_args[0]

            # Detail key/values should not appear in body
            assert 'best_match_score' not in body
            assert 'min_threshold' not in body
            assert '0.65' not in body
            assert '0.8' not in body


class TestErrorNotification:
    """Test error notification."""

    def test_notify_error_basic(self, smtp_config: SMTPConfig) -> None:
        """Test error notification with basic info."""
        notifier = Notifier(smtp=smtp_config)

        with patch.object(notifier, '_send_email') as mock_send:
            notifier.notify_error(
                case_name='Smith v. Jones',
                stage='download',
                error='Network timeout',
            )

            subject, body = mock_send.call_args[0]

            assert subject == 'Pipeline Error: Smith v. Jones'
            assert 'Smith v. Jones' in body
            assert 'download' in body
            assert 'Network timeout' in body

    def test_notify_error_with_context_verbose(self, smtp_config: SMTPConfig) -> None:
        """Test error notification includes context when verbose."""
        notifier = Notifier(smtp=smtp_config, verbose=True)

        with patch.object(notifier, '_send_email') as mock_send:
            notifier.notify_error(
                case_name='Smith v. Jones',
                stage='download',
                error='Network timeout',
                context={'url': 'https://example.com', 'attempts': '3'},
            )

            subject, body = mock_send.call_args[0]

            assert 'url' in body
            assert 'https://example.com' in body
            assert 'attempts' in body

    def test_notify_error_without_context_when_not_verbose(
        self,
        smtp_config: SMTPConfig,
    ) -> None:
        """Test error notification excludes context when not verbose."""
        notifier = Notifier(smtp=smtp_config, verbose=False)

        with patch.object(notifier, '_send_email') as mock_send:
            notifier.notify_error(
                case_name='Smith v. Jones',
                stage='download',
                error='Network timeout',
                context={'url': 'https://example.com', 'attempts': '3'},
            )

            subject, body = mock_send.call_args[0]

            # Context should not appear in body
            assert 'url' not in body
            assert 'attempts' not in body
