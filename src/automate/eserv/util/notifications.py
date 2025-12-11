"""Email notification system for pipeline events.

Sends email alerts for upload results, errors, and manual review requests.
Uses SMTP configuration for delivery.

Classes:
    NotificationConfig: Configuration for notification content.
    Notifier: Email notification sender.
"""

from __future__ import annotations

import smtplib
from dataclasses import dataclass, field
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import TYPE_CHECKING

from rampy import create_field_factory

from setup_console import console

if TYPE_CHECKING:
    from automate.eserv.util.configuration import SMTPConfig


@dataclass(slots=True, frozen=True)
class NotificationConfig:
    """Configuration for notification email content.

    Attributes:
        subject_prefix: Prefix for email subject lines.
        include_details: Whether to include detailed logs in emails.

    """

    subject_prefix: str = '[ESERV]'
    include_details: bool = True


@dataclass
class Notifier:
    """Sends email notifications for pipeline events.

    Attributes:
        smtp_config: SMTP configuration for email delivery.
        notification_config: Configuration for notification content.

    """

    smtp_config: SMTPConfig
    notification_config: NotificationConfig = field(init=False)

    def __post_init__(self) -> None:
        from automate.eserv.util.types import NotificationConfig

        self.notification_config = NotificationConfig()

    def _send_email(self, subject: str, body: str) -> None:
        """Send an email notification.

        Args:
            subject: Email subject line.
            body: Email body (plain text).

        """
        msg = MIMEMultipart()
        msg['From'] = self.smtp_config.from_addr
        msg['To'] = self.smtp_config.to_addr
        msg['Subject'] = f'{self.notification_config.subject_prefix} {subject}'
        msg.attach(MIMEText(body, 'plain'))

        try:
            if self.smtp_config.use_tls:
                server = smtplib.SMTP(self.smtp_config.server, self.smtp_config.port)
                server.starttls()
            else:
                server = smtplib.SMTP(self.smtp_config.server, self.smtp_config.port)

            if self.smtp_config.username and self.smtp_config.password:
                server.login(self.smtp_config.username, self.smtp_config.password)

            server.send_message(msg)
            server.quit()

            console.info('Email notification sent', subject=subject)
        except Exception:
            console.exception('Failed to send email notification', subject=subject)

    def notify_upload_success(self, case_name: str, folder_path: str, file_count: int) -> None:
        """Notify successful document upload.

        Args:
            case_name: Name of the case.
            folder_path: Dropbox folder path where files were uploaded.
            file_count: Number of files uploaded.

        """
        subject = f'Upload Success: {case_name}'
        body = f"""
Document upload successful.

Case: {case_name}
Folder: {folder_path}
Files Uploaded: {file_count}
"""
        self._send_email(subject, body)

    def notify_manual_review(
        self,
        case_name: str,
        reason: str,
        details: dict[str, str] | None = None,
    ) -> None:
        """Notify that manual review is required.

        Args:
            case_name: Name of the case.
            reason: Reason for manual review.
            details: Optional additional details.

        """
        subject = f'Manual Review Required: {case_name}'
        body = f"""
Manual review required for document upload.

Case: {case_name}
Reason: {reason}
"""
        if details and self.notification_config.include_details:
            body += '\nDetails:\n'
            for key, value in details.items():
                body += f'  {key}: {value}\n'

        self._send_email(subject, body)

    def notify_error(
        self,
        case_name: str,
        stage: str,
        error: str,
        context: dict[str, str] | None = None,
    ) -> None:
        """Notify pipeline error.

        Args:
            case_name: Name of the case.
            stage: Pipeline stage where error occurred.
            error: Error message.
            context: Optional additional context.

        """
        subject = f'Pipeline Error: {case_name}'
        body = f"""
Error occurred during document processing.

Case: {case_name}
Stage: {stage}
Error: {error}
"""
        if context and self.notification_config.include_details:
            body += '\nContext:\n'
            for key, value in context.items():
                body += f'  {key}: {value}\n'

        self._send_email(subject, body)


get_notifier = create_field_factory(Notifier)
