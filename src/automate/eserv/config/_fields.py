from __future__ import annotations

__all__ = ['BaseFields', 'MonitoringFields', 'SMTPFields']

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from automate.eserv.config.utils import email_env_var, env_var, int_env_var

if TYPE_CHECKING:
    from pathlib import Path

    from automate.eserv.types import *


@dataclass(frozen=True, init=False)
class MonitoringFields:
    monitor_num_days: int = field(default_factory=int_env_var('MONITORING_LOOKBACK_DAYS', 1))
    monitor_mail_folder_path: list[str] = field(
        default_factory=env_var(
            key='MONITORING_FOLDER_PATH',
            into=lambda s: [_.strip() for _ in s.split(',')],
        ),
        metadata={'format': 'csv'},
    )


@dataclass(frozen=True, init=False)
class SMTPFields:
    smtp_server: str = field(default_factory=env_var('SMTP_SERVER'))
    smtp_port: int = field(default_factory=int_env_var('SMTP_PORT', 587))
    smtp_sender: EmailAddress = field(default_factory=email_env_var('SMTP_FROM_ADDR'))
    smtp_recipient: EmailAddress = field(default_factory=email_env_var('SMTP_TO_ADDR'))
    smtp_username: str | None = field(default_factory=env_var('SMTP_USERNAME', optional=True))
    smtp_password: str | None = field(default_factory=env_var('SMTP_PASSWORD', optional=True))
    smtp_use_tls: bool = field(
        default_factory=env_var(
            key='SMTP_USE_TLS',
            default='true',
            into=lambda s: s.lower() in {'true', '1', 'yes'},
        )
    )


@dataclass(frozen=True, init=False)
class BaseFields:
    dotenv_path: Path | None = field(default=None)
    index_max_age: int = field(default_factory=int_env_var('INDEX_CACHE_TTL_HOURS', 4))
    manual_review_folder: str = field(default_factory=env_var('MANUAL_REVIEW_FOLDER', '/MANUAL_REVIEW/'))
