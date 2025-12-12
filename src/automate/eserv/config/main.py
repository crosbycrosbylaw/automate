from __future__ import annotations

__all__ = ['Config']

from dataclasses import dataclass, field, fields
from typing import TYPE_CHECKING, no_type_check

from rampy import make_factory

from automate.eserv.config.utils import email_env_var, env_var, int_env_var
from setup_console import console

from ._credentials import CredentialsConfig
from ._paths import PathsConfig

if TYPE_CHECKING:
    from os import PathLike
    from pathlib import Path

    from automate.eserv.types.typechecking import SMTPConfig

    from .utils import EmailAddress


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


@dataclass(frozen=True, slots=True)
class Config(
    MonitoringFields,
    SMTPFields,
    BaseFields,
):
    """Root configuration with all nested scopes.

    Attributes:
        paths: File storage paths.
        creds: OAuth2 credentials.

    """

    paths: PathsConfig = field(init=False)
    creds: CredentialsConfig = field(init=False)

    def __new__(cls, dotenv_path: PathLike[str] | None = None) -> Config:
        config = super().__new__(cls)
        object.__setattr__(config, 'paths', (paths := PathsConfig(dotenv_path=dotenv_path)))
        object.__setattr__(config, 'creds', CredentialsConfig(paths.credentials))
        return config

    def __post_init__(self) -> None:
        """Print basic configuration information to the console after initialization."""
        console.info(
            event='configuration loaded',
            dotenv_path=f'{self.dotenv_path!s}',
            service_dir=f'{self.paths.service!s}',
            cache_ttl=f'{self.index_max_age!s}',
            smtp_server=self.smtp_server,
        )

    @no_type_check
    def smtp(self) -> SMTPConfig:
        prefix = 'smtp_'
        return {
            f.name.removeprefix(prefix): getattr(self, f.name)
            for f in fields(self)
            if f.name.startswith(prefix)
        }


configure = make_factory(Config)
