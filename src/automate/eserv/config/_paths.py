from __future__ import annotations

import enum
import os
from dataclasses import InitVar, dataclass, field
from functools import cached_property
from os import PathLike
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Self

from dotenv import find_dotenv, load_dotenv
from zmq import Enum

from automate.eserv.config.utils import env_var, hint, path_variable

if TYPE_CHECKING:
    from .types import *


class EnvStatus(Enum):
    NOT_LOADED = enum.auto()
    LOAD_SUCCESS = enum.auto()
    LOAD_ERROR = enum.auto()

    @classmethod
    def from_path(cls, dotenv_path: StrPath | None) -> tuple[Path, EnvStatus]:
        if isinstance(dotenv_path, PathLike):
            path = Path(dotenv_path)
        else:
            path = Path(find_dotenv(dotenv_path or '.env'))

        if os.getenv('PYTHON_DOTENV_DISABLED') == path.name:
            return path, EnvStatus.LOAD_SUCCESS

        if strict := load_dotenv(path, override=bool(path)):
            status = EnvStatus.LOAD_SUCCESS
            os.environ['PYTHON_DOTENV_DISABLED'] = path.name
        else:
            status = EnvStatus.LOAD_ERROR

        return path.resolve(strict=strict), status


def _into_root(string: str):
    try:
        path = Path(string).resolve(strict=True)
    except FileNotFoundError:
        return hint('failed to resolve root directory')
    else:
        return path


@dataclass
class PathsConfig:
    """File storage paths."""

    _instance: ClassVar[Self]
    _status: ClassVar[EnvStatus] = EnvStatus.NOT_LOADED
    _dotenv: ClassVar[Path | None] = None

    @classmethod
    def _init_env(cls, dotenv_path: StrPath | None = None) -> bool:
        cls._dotenv, cls._status = EnvStatus.from_path(dotenv_path)

        if success := cls._status == EnvStatus.LOAD_SUCCESS:
            return success

        from setup_console import console

        console.warning(f'Failed to load environment from {cls._dotenv!s}')
        return success

    dotenv: InitVar[StrPath | None] = None

    root: Path = field(
        init=False,
        default_factory=path_variable(key='PROJECT_ROOT', into=_into_root),
    )
    credentials: Path = field(
        init=False,
        default_factory=path_variable('CREDENTIALS_FILE', 'credentials.json'),
    )
    private_key: Path | None = field(
        init=False,
        default_factory=env_var('CERT_PRIVATE_KEY_FILE', optional=True, into=Path),
    )

    @cached_property
    def service(self) -> Path:
        path = self.resolve(os.getenv('SERVICE_DIR', '.service'))
        if not path.exists():
            path.mkdir(parents=True)
        return path

    index: Path = field(init=False)
    state: Path = field(init=False)
    errors: Path = field(init=False)

    def __new__(cls, dotenv: StrPath | None = None) -> PathsConfig:
        if not hasattr(cls, '_instance'):
            cls._init_env(dotenv)
            this = super().__new__(cls)
            this.__init__(dotenv)
            cls._instance = this
        return cls._instance

    def __post_init__(self, dotenv: StrPath | None) -> None:
        self._rebase()
        self._scaffold()

    def _rebase(self) -> None:
        for name in 'credentials', 'private_key':
            if (path := getattr(self, name, None)) and not path.is_absolute():
                setattr(self, name, self.resolve(path, strict=True))

    def _scaffold(self) -> None:
        svc = self.service
        for name in 'index', 'state', 'errors':
            path = svc.joinpath(name).with_suffix('.json')
            path.touch(exist_ok=True)
            setattr(self, name, path)

    def resolve(self, *segments: str | Path, strict: bool = False) -> Path:
        return self.root.joinpath(*segments).resolve(strict=strict)


def get_paths(dotenv: StrPath | None = None) -> PathsConfig:
    return PathsConfig(dotenv=dotenv)
