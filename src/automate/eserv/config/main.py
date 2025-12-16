from __future__ import annotations

__all__ = ['Config']

from dataclasses import InitVar, dataclass, field, fields
from typing import TYPE_CHECKING, no_type_check

from rampy import make_factory

from automate.eserv.config.utils import email_variable, env_var, integer_variable
from setup_console import console

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

    dotenv_path: InitVar[StrPath | None] = None

    paths: PathsConfig = field(init=False)
    creds: CredentialsConfig = field(init=False)

    def __new__(cls, dotenv_path: StrPath | None = None) -> Config:
        from .utils import ensure_fields

        paths = PathsConfig(dotenv=dotenv_path)
        creds = CredentialsConfig(path=paths.credentials)

        this = super().__new__(cls)
        object.__setattr__(this, 'paths', paths)
        object.__setattr__(this, 'creds', creds)
        super().__init__(this)
        return ensure_fields(this)

    def __post_init__(self, dotenv_path: StrPath | None) -> None:
        console.info(
            event='configuration loaded',
            dotenv_path=dotenv_path,
            service_dir=self.paths.service,
            cache_ttl=self.index_max_age,
            smtp_server=self.smtp_server,
        )

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
        return {f.name: getattr(self, f.name) for f in fields(self) if f.name}


configure = make_factory(Config)


def get_config(dotenv_path: StrPath | None = None) -> Config:
    return Config(dotenv_path=dotenv_path)
