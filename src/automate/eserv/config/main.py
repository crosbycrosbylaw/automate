from __future__ import annotations

__all__ = ['Config']

import dataclasses
from dataclasses import InitVar, dataclass, field, fields
from typing import TYPE_CHECKING, no_type_check

from rampy import make_factory

from automate.eserv.config.utils import email_env_var, env_var, int_env_var
from setup_console import console

from ._credentials import CredentialsConfig
from ._paths import PathsConfig

if TYPE_CHECKING:
    from os import PathLike

    from automate.eserv.types.typechecking import BaseConfig, MonitoringConfig, SMTPConfig

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
    index_max_age: int = field(default_factory=int_env_var('INDEX_CACHE_TTL_HOURS', 4))
    manual_review_folder: str = field(default_factory=env_var('MANUAL_REVIEW_FOLDER', '/MANUAL_REVIEW/'))
    certificate_thumbprint: str | None = field(default_factory=env_var('CERT_THUMBPRINT', optional=True))


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

    dotenv_path: InitVar[PathLike[str] | None] = None

    paths: PathsConfig = field(init=False)
    creds: CredentialsConfig = field(init=False)

    def __new__(cls, dotenv_path: PathLike[str] | None = None) -> Config:
        config = super().__new__(cls)

        # Initialize paths first (triggers env loading)
        object.__setattr__(config, 'paths', (paths := PathsConfig(dotenv_path=dotenv_path)))

        # Initialize all fields with default_factory (since __init__ is bypassed)
        for f in fields(cls):
            if f.init and f.default_factory is not dataclasses.MISSING:  # type: ignore
                object.__setattr__(config, f.name, f.default_factory())

        # Initialize credentials last (requires paths.credentials)
        object.__setattr__(config, 'creds', CredentialsConfig(path=paths.credentials))

        config.print()
        return config

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

    def print(self) -> None:
        console.info(
            event='configuration loaded',
            dotenv_path=f'{self.paths.env_path()!s}',
            service_dir=f'{self.paths.service!s}',
            cache_ttl=f'{self.index_max_age!s}',
            smtp_server=self.smtp_server,
        )

    @staticmethod
    def default() -> Config:
        dotenv_path = PathsConfig.env_path()
        return Config(dotenv_path=dotenv_path)


configure = make_factory(Config)


def get_config() -> Config:
    return Config.default()
