from __future__ import annotations

__all__ = ['_BaseFields', '_MonitoringFields', '_SMTPFields']

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from automate.eserv.config.utils import ev_email_factory, ev_factory, ev_int_factory

if TYPE_CHECKING:
    from pathlib import Path

    from automate.eserv.types import *


@dataclass(frozen=True, init=False)
class _MonitoringFields:
    monitor_num_days: int = field(default_factory=ev_int_factory('MONITORING_LOOKBACK_DAYS', 1))
    monitor_mail_folder_path: list[str] = field(
        default_factory=ev_factory(
            key='MONITORING_FOLDER_PATH',
            into=lambda s: [_.strip() for _ in s.split(',')],
        ),
        metadata={'format': 'csv'},
    )


@dataclass(frozen=True, init=False)
class _SMTPFields:
    smtp_server: str = field(default_factory=ev_factory('SMTP_SERVER'))
    smtp_port: int = field(default_factory=ev_int_factory('SMTP_PORT', 587))
    smtp_sender: EmailAddress = field(default_factory=ev_email_factory('SMTP_FROM_ADDR'))
    smtp_recipient: EmailAddress = field(default_factory=ev_email_factory('SMTP_TO_ADDR'))
    smtp_username: str | None = field(default_factory=ev_factory('SMTP_USERNAME', optional=True))
    smtp_password: str | None = field(default_factory=ev_factory('SMTP_PASSWORD', optional=True))
    smtp_use_tls: bool = field(
        default_factory=ev_factory(
            key='SMTP_USE_TLS',
            default='true',
            into=lambda s: s.lower() in {'true', '1', 'yes'},
        )
    )


@dataclass(frozen=True, init=False)
class _BaseFields:
    dotenv_path: Path | None = field(default=None)
    index_max_age: int = field(default_factory=ev_int_factory('INDEX_CACHE_TTL_HOURS', 4))
    manual_review_folder: str = field(default_factory=ev_factory('MANUAL_REVIEW_FOLDER', '/MANUAL_REVIEW/'))
