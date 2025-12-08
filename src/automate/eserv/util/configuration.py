"""Application configuration loaded from environment variables.

Provides nested dataclasses for scoped configuration (SMTP, Dropbox, etc.)
with validation, type coercion, and sensible development defaults.

Uses python-dotenv to load .env files and validates all required fields
and formats at application startup.

Classes:
    SMTPConfig: Email delivery configuration.
    CredentialsConfig: API authorization configurations.
    PathsConfig: File storage paths.
    EmailStateConfig: Email state tracking configuration.
    CacheConfig: Cache configuration.
    Config: Root configuration with all nested scopes.

"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from dotenv import load_dotenv
from rampy import console

from automate.eserv.errors.types import InvalidFormatError, MissingVariableError
from automate.eserv.util.oauth_manager import CredentialManager


@dataclass(slots=True, frozen=True)
class SMTPConfig:
    """SMTP configuration for email notifications.

    Attributes:
        server: SMTP server hostname.
        port: SMTP port (typically 587 for TLS).
        from_addr: Sender email address.
        to_addr: Recipient email address.
        username: SMTP username (optional if not requiring authentication).
        password: SMTP password or app-specific password.
        use_tls: Whether to use TLS encryption.

    """

    server: str
    port: int
    from_addr: str
    to_addr: str
    username: str | None = None
    password: str | None = None
    use_tls: bool = True

    @classmethod
    def from_env(cls) -> SMTPConfig:
        """Load SMTP configuration from environment variables.

        Raises:
            TypeError: If the value recieved for the `port` is not an integer.
            MissingVariableError: If required fields are missing.
            InvalidFormatError: If any variable values are of an invalid format.

        """
        server = os.getenv('SMTP_SERVER')
        port_str = os.getenv('SMTP_PORT', '587')
        from_addr = os.getenv('SMTP_FROM_ADDR')
        to_addr = os.getenv('SMTP_TO_ADDR')
        username = os.getenv('SMTP_USERNAME')
        password = os.getenv('SMTP_PASSWORD')
        use_tls = os.getenv('SMTP_USE_TLS', 'true').lower() in {'true', '1', 'yes'}

        if not server:
            raise MissingVariableError(name='SMTP_SERVER')
        if not from_addr:
            raise MissingVariableError(name='SMTP_FROM_ADDR')
        if not to_addr:
            raise MissingVariableError(name='SMTP_TO_ADDR')

        try:
            port = int(port_str)
        except ValueError as e:
            message = f'SMTP_PORT must be an integer string, got: {port_str}'
            raise TypeError(message) from e

        # Validate email format

        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

        if not email_pattern.match(from_addr):
            raise InvalidFormatError(name='SMTP_FROM_ADDR', value=from_addr)
        if not email_pattern.match(to_addr):
            raise InvalidFormatError(name='SMTP_TO_ADDR', value=to_addr)

        return cls(
            server=server,
            port=port,
            from_addr=from_addr,
            to_addr=to_addr,
            username=username,
            password=password,
            use_tls=use_tls,
        )


@dataclass(slots=True, frozen=True)
class PathsConfig:
    """File storage paths.

    Attributes:
        service_dir: Directory for service data (state, cache, logs).
        manual_review_folder: Dropbox folder path for manual review uploads.

    """

    service_dir: Path
    manual_review_folder: str

    @classmethod
    def from_env(cls) -> PathsConfig:
        """Load paths configuration from environment variables.

        Raises:
            MissingVariableError: If required paths are missing.

        """
        if not (manual_review := os.getenv('MANUAL_REVIEW_FOLDER')):
            raise MissingVariableError(name='MANUAL_REVIEW_FOLDER')

        if path_string := os.getenv('SERVICE_DIR'):
            service_dir = Path(path_string).resolve()
            service_dir.mkdir(parents=True, exist_ok=True)
        else:
            from rampy import rootpath

            service_dir = rootpath('service', mkdir=True)

        return cls(service_dir=service_dir, manual_review_folder=manual_review)


@dataclass(slots=True, frozen=True)
class EmailStateConfig:
    """Email state tracking configuration.

    Attributes:
        state_file: Path to email state JSON file.

    """

    state_file: Path

    @classmethod
    def from_env(cls, service_dir: Path) -> EmailStateConfig:
        """Load email state configuration.

        Args:
            service_dir: Service directory from PathsConfig.

        """
        return cls(state_file=service_dir / 'state.json')


@dataclass(slots=True, frozen=True)
class CacheConfig:
    """Cache configuration.

    Attributes:
        index_file: Path to Dropbox index cache file.
        ttl_hours: Cache time-to-live in hours.

    """

    index_file: Path
    ttl_hours: int

    @classmethod
    def from_env(cls, service_dir: Path) -> CacheConfig:
        """Load cache configuration from environment variables.

        Args:
            service_dir: Service directory from PathsConfig.

        Raises:
            TypeError:
                If the `INDEX_CACHE_TTL_HOURS` variable is not an integer string.

        """
        ttl_str = os.getenv('INDEX_CACHE_TTL_HOURS', '4')

        try:
            ttl_hours = int(ttl_str)
        except ValueError as e:
            message = f'INDEX_CACHE_TTL_HOURS must be an integer, got: {ttl_str}'
            raise TypeError(message) from e

        return cls(index_file=service_dir / 'dbx_index.json', ttl_hours=ttl_hours)


@dataclass(frozen=True, slots=True)
class MonitoringConfig:
    """Monitoring configuration."""

    num_days: int
    folder_path: str
    graph_api_base_url: str = 'https://graph.microsoft.com/v1.0'

    @classmethod
    def from_env(cls) -> MonitoringConfig:
        """Load monitoring configuration from environment variables.

        Returns:
            MonitoringConfig: Monitoring configuration with lookback days and folder path.

        """
        return cls(
            num_days=int(os.getenv('MONITORING_LOOKBACK_DAYS', '1')),
            folder_path=os.getenv(
                'MONITORING_FOLDER_PATH',
                'Inbox/File Handling - All/Filing Accepted / Notification of Service / Courtesy Copy',
            ),
        )


@dataclass(slots=True, frozen=True)
class Config:
    """Root configuration with all nested scopes.

    Attributes:
        smtp: SMTP configuration for email notifications.
        dropbox: Dropbox API configuration.
        paths: File storage paths.
        state: Email state tracking configuration.
        cache: Cache configuration.

    """

    dotenv_path: ClassVar[Path | None] = None
    dotenv_loaded: ClassVar[bool] = False

    @classmethod
    def load(cls, dotenv: Path | None, **kwds: Any) -> None:
        """Load environment variables from the specified .env file and update class attributes.

        Args:
            dotenv (Path | None):
                Path to a `.env` file to load, or `None` to resolve with `dotenv.find_dotenv`.
            **kwds (Any):
                Keyword arguments to pass through to the `dotenv.load_dotenv` method.

        """
        cls.dotenv_path = None if not dotenv else dotenv.resolve(strict=True)
        cls.dotenv_loaded = load_dotenv(cls.dotenv_path, **kwds)

    credentials: CredentialManager

    smtp: SMTPConfig
    paths: PathsConfig
    state: EmailStateConfig
    cache: CacheConfig
    monitoring: MonitoringConfig

    def __post_init__(self) -> None:
        """Print basic configuration information to the console after initialization."""
        console.bind(
            dotenv_path=f'{self.dotenv_path!s}',
            service_dir=f'{self.paths.service_dir!s}',
            cache_ttl=f'{self.cache.ttl_hours!s}',
            smtp_server=self.smtp.server,
        ).info('Configuration loaded')


def config_factory(dotenv: Path | None = None) -> Config:
    """Load complete configuration from environment variables.

    Args:
        dotenv: Optional path to .env file. If None, uses default .env in cwd.

    """
    # When a specific dotenv path is provided (e.g., for testing), override existing env vars
    Config.load(dotenv, override=dotenv is not None)

    if not (cred_path := os.getenv('CREDENTIALS_PATH')):
        raise MissingVariableError(name='CREDENTIALS_PATH')

    cred_path = Path(cred_path).resolve(strict=True)

    return Config(
        credentials=CredentialManager(cred_path),
        smtp=SMTPConfig.from_env(),
        monitoring=MonitoringConfig.from_env(),
        paths=(paths := PathsConfig.from_env()),
        cache=CacheConfig.from_env(paths.service_dir),
        state=EmailStateConfig.from_env(paths.service_dir),
    )
