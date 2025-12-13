from __future__ import annotations

import enum
from sys import stdin

from zmq import Enum

__all__ = ['PathsConfig']

from dataclasses import InitVar, dataclass, field
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Self

from dotenv import load_dotenv

from automate.eserv.config.utils import env_var, hint

if TYPE_CHECKING:
    from os import PathLike

    from automate.eserv.types import *


class EnvStatus(Enum):
    SUCCESS = enum.auto()
    ERROR = enum.auto()

    @classmethod
    def from_path(cls, dotenv_path: PathLike[str] | None) -> EnvStatus:
        if load_dotenv(dotenv_path, override=bool(dotenv_path)):
            return cls.SUCCESS
        return cls.ERROR


def _validate_path(strpath: str | None, parent: Path) -> Path | None:
    if strpath is None:
        return None

    try:
        path = parent.joinpath(strpath).resolve(strict=True)
    except FileNotFoundError:
        return None
    else:
        return path


@dataclass(frozen=True)
class PathsConfig:
    """File storage paths."""

    _instance: ClassVar[Self | None] = None

    _env_path: ClassVar[PathLike[str] | None] = None
    _env_status: ClassVar[EnvStatus | None] = None

    @classmethod
    def check_env(cls) -> bool:
        return cls._env_status == EnvStatus.SUCCESS

    @classmethod
    def env_path(cls) -> Path | None:
        if cls._env_path:
            return Path(cls._env_path).resolve(strict=True)
        return None

    @classmethod
    def default(cls) -> Self:
        return cls(cls._env_path)

    dotenv_path: InitVar[PathLike[str] | None]

    def __new__(cls, dotenv_path: PathLike[str] | None = None) -> PathsConfig:
        if not cls._instance or cls._env_path != dotenv_path:
            cls._env_path = dotenv_path
            cls._env_status = EnvStatus.from_path(dotenv_path)
            cls._instance = super().__new__(cls)
        return cls._instance

    root: Path = field(
        init=False,
        default_factory=env_var(
            key='PROJECT_ROOT',
            into=lambda s: hint('expected an existing directory')
            if not (path := Path(s).resolve()).exists()
            else path.absolute(),
        ),
    )

    _service: str = field(
        init=False,
        default_factory=env_var(key='SERVICE_DIR', default='.service'),
    )
    _credentials: str = field(
        init=False,
        default_factory=env_var(key='CREDENTIALS_FILE', default='credentials.json'),
    )
    _state: str = field(
        init=False,
        default_factory=env_var(key='STATE_FILE', default='state.json'),
    )
    _index: str = field(
        init=False,
        default_factory=env_var(key='INDEX_FILE', default='index.json'),
    )
    _private_key: str | None = field(
        init=False,
        default_factory=env_var(key='CERT_PRIVATE_KEY_PATH', optional=True),
    )

    @cached_property
    def service(self) -> Path:
        path = self.root.joinpath(self._service).resolve()
        if not path.exists():
            path.mkdir(parents=True)
        return path

    @cached_property
    def credentials(self) -> Path:
        return self.root.joinpath(self._credentials).resolve(strict=True)

    @cached_property
    def state(self) -> Path:
        segment = self._state.removeprefix(self._service)
        path = self.service.joinpath(segment).resolve()
        if not path.exists():
            path.touch()
        return path.resolve(strict=True)

    @cached_property
    def index(self) -> Path:
        segment = self._index.removeprefix(self._service)
        path = self.service.joinpath(segment).resolve()
        if not path.exists():
            path.touch()
        return path.resolve(strict=True)

    @cached_property
    def error_log(self) -> Path:
        path = self.service.joinpath('error_log.json').resolve()
        if not path.exists():
            path.touch()
        return path

    @cached_property
    def private_key(self) -> Path:
        if path := _validate_path(self._private_key, self.root):
            return path

        if path := stdin.isatty() and _validate_path(
            strpath=input('Enter CERT_PRIVATE_KEY_PATH: '),
            parent=self.root,
        ):
            return path

        raise MissingVariableError('CERT_PRIVATE_KEY_PATH')

    def resolve(self, *segments: PathLike[str]) -> Path:
        return self.root.joinpath(*segments).resolve()


def get_paths() -> PathsConfig:
    return PathsConfig.default()
