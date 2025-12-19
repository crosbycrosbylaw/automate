from __future__ import annotations

__all__ = ['Config']

from dataclasses import InitVar, dataclass, field, fields
from typing import TYPE_CHECKING, Self, no_type_check

from automate.eserv.config.utils import email_variable, env_var, integer_variable
from setup_console import mode, mode_console

from ._credentials import CredentialsConfig
from ._paths import PathsConfig

if TYPE_CHECKING:
    from automate.eserv.types.typechecking import BaseConfig, MonitoringConfig, SMTPConfig

    from .types import *
    from .utils import EmailAddress


@dataclass(frozen=True)
class MonitoringFields:
    monitor_num_days: int = field(default_factory=integer_variable('MONITORING_LOOKBACK_DAYS', 1))
    monitor_mail_folder_path: list[str] = field(
        default_factory=env_var(
            key='MONITORING_FOLDER_PATH',
            into=lambda s: [_.strip() for _ in s.split(',')],
        ),
        metadata={'format': 'csv'},
    )


@dataclass(frozen=True)
class SMTPFields:
    smtp_server: str = field(default_factory=env_var('SMTP_SERVER'))
    smtp_port: int = field(default_factory=integer_variable('SMTP_PORT', 587))
    smtp_sender: EmailAddress = field(default_factory=email_variable('SMTP_FROM_ADDR'))
    smtp_recipient: EmailAddress = field(default_factory=email_variable('SMTP_TO_ADDR'))
    smtp_username: str | None = field(default_factory=env_var('SMTP_USERNAME', optional=True))
    smtp_password: str | None = field(default_factory=env_var('SMTP_PASSWORD', optional=True))
    smtp_use_tls: bool = field(
        default_factory=env_var(
            key='SMTP_USE_TLS',
            default='true',
            into=lambda s: s.lower() in {'true', '1', 'yes'},
        )
    )


@dataclass(frozen=True)
class BaseFields:
    index_max_age: int = field(default_factory=integer_variable('INDEX_CACHE_TTL_HOURS', 4))
    manual_review_folder: str = field(default_factory=env_var('MANUAL_REVIEW_FOLDER', '/MANUAL_REVIEW/'))
    certificate_thumbprint: str | None = field(default_factory=env_var('CERT_THUMBPRINT', optional=True))


@dataclass(frozen=True, slots=True)
class Config(MonitoringFields, SMTPFields, BaseFields):
    """Root configuration with all nested scopes.

    Attributes:
        paths: File storage paths.
        creds: OAuth2 credentials.

    """

    dotenv_path: InitVar[StrPath | None] = field(default=None)

    paths: PathsConfig = field(init=False)
    creds: CredentialsConfig = field(init=False)

    _verbose: ModeConsole = field(init=False, default_factory=mode_console(mode.VERBOSE))

    @classmethod
    def _setup(cls, dotenv_path: StrPath | None = None) -> Self:
        self = super().__new__(cls)
        object.__setattr__(self, 'paths', paths := PathsConfig(dotenv=dotenv_path))
        object.__setattr__(self, 'creds', CredentialsConfig(path=paths.credentials))
        super().__init__(self)

        return self

    def __new__(cls, dotenv_path: StrPath | None = None) -> Config:
        return getattr(cls, '_instance', cls._setup(dotenv_path))

    def __post_init__(self, dotenv_path: ...) -> None:
        self._verbose.info('SMTP configuration', **self.smtp())
        self._verbose.info('Monitoring configuration', **self.monitoring())
        self._verbose.info('Base configuration', **self.base())

        console = self._verbose.unwrap()
        console.info('Loaded configuration', **{} if not dotenv_path else {'dotenv_path': dotenv_path})

    @no_type_check
    def smtp(self) -> SMTPConfig:
        return {
            f.name.removeprefix('smtp_'): getattr(self, f.name)
            for f in fields(self)
            if f.name.startswith('smtp_')
        }

    @no_type_check
    def monitoring(self) -> MonitoringConfig:
        return {
            f.name.removeprefix('monitor_'): getattr(self, f.name)
            for f in fields(self)
            if f.name.startswith('monitor_')
        }

    @no_type_check
    def base(self) -> BaseConfig:
        return {
            f.name: getattr(self, f.name)
            for f in fields(self)
            if not any(f.name.startswith(x) for x in ('_', 'certificate', 'monitoring', 'smtp'))
        }


configure = Config
