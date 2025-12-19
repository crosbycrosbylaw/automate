from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from functools import cached_property
from os import PathLike
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Self

from dotenv import find_dotenv, load_dotenv
from zmq import Enum

from automate.eserv.config.utils import env_var, hint, path_variable, vprinter

if TYPE_CHECKING:
    from automate.eserv.config.utils import ModeConsole

    from .types import *


class EnvStatus(Enum):
    NOT_LOADED = 'none'
    LOAD_SUCCESS = 'ok'
    LOAD_ERROR = 'error'

    @classmethod
    def from_path(cls, dotenv_path: StrPath | None) -> tuple[Path, EnvStatus]:
        if isinstance(dotenv_path, Path):
            path = dotenv_path.absolute()
        elif isinstance(dotenv_path, PathLike):
            path = Path(dotenv_path)
        else:
            path = Path(find_dotenv(dotenv_path or '.env'))

        if not path.is_file():
            raise FileNotFoundError(path)

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
        if not path.is_dir():
            return hint('path must be a directory')
    except FileNotFoundError:
        return hint('failed to resolve root directory')
    else:
        return path


@dataclass
class PathsConfig:
    """File storage paths."""

    _instance: ClassVar[Self]

    dotenv: StrPath | None = field(default=None)
    env_status: EnvStatus = field(init=False, default=EnvStatus.NOT_LOADED)

    _verbose: ModeConsole = field(init=False, default_factory=vprinter)

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

    def __new__(cls, dotenv: StrPath | None = None) -> Self:
        return getattr(cls, '_instance', cls._setup(dotenv))

    @classmethod
    def _setup(cls, dotenv_path: ...) -> Self:
        dotenv, status = EnvStatus.from_path(dotenv_path)
        self = super().__new__(cls)
        self.__init__(dotenv)
        self.env_status = status
        cls._instance = self

        if self.env_status is not EnvStatus.LOAD_SUCCESS:
            self._verbose.warning('Environment load error', status=self.env_status.value)

        for name in 'credentials', 'private_key':
            if (path := getattr(self, name, None)) and not path.is_absolute():
                setattr(self, name, self.resolve(path, strict=True))

        for name in 'index', 'state', 'errors':
            path = (self.service / f'{name}.json').resolve()
            path.touch(exist_ok=True)
            setattr(self, name, path)

        self._verbose.info(event='Path configuration', **self.fs())
        self._verbose.unwrap().info('Loaded paths')

        return self

    def resolve(self, *segments: str | Path, strict: bool = False) -> Path:
        return self.root.joinpath(*segments).resolve(strict=strict)

    def fs(self) -> dict[str, str]:
        return {
            f.name: str(p.relative_to(self.root))
            for f in fields(self)
            if 'Path' in str(f.type) and (p := getattr(self, f.name))
        }


def get_paths() -> PathsConfig:
    return PathsConfig()
