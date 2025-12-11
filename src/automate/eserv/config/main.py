from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, no_type_check

from rampy import create_field_factory

from automate.eserv.config._credentials import *
from automate.eserv.config._fields import *
from automate.eserv.config._paths import *

if TYPE_CHECKING:
    from os import PathLike

    from automate.eserv.types import SMTPConfig

from setup_console import console


@dataclass(frozen=True, slots=True)
class Config(
    _MonitoringFields,
    _SMTPFields,
    _BaseFields,
):
    """Root configuration with all nested scopes.

    Attributes:
        smtp: SMTP configuration for email notifications.
        dropbox: Dropbox API configuration.
        paths: File storage paths.
        state: Email state tracking configuration.
        cache: Cache configuration.

    """

    paths: _PathsConfig = field(init=False)
    creds: _CredentialsConfig = field(init=False)

    def __new__(cls, dotenv_path: PathLike[str] | None = None) -> Config:
        config = super().__new__(cls)
        object.__setattr__(config, 'paths', (paths := _PathsConfig(dotenv_path=dotenv_path)))
        object.__setattr__(config, 'creds', _CredentialsConfig(paths.credentials))
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


configure = create_field_factory(Config)
