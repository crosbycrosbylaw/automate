from __future__ import annotations

__all__ = ['PathsConfig']

from dataclasses import InitVar, dataclass, field
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from dotenv import load_dotenv

from automate.eserv.config.utils import env_var, hint

if TYPE_CHECKING:
    from os import PathLike

    from automate.eserv.types import *


@dataclass(frozen=True)
class PathsConfig:
    """File storage paths."""

    _status: ClassVar[bool | None] = None

    @classmethod
    def get_status(cls) -> bool | None:
        return cls._status

    dotenv_path: InitVar[PathLike[str] | None]

    def __new__(cls, dotenv_path: PathLike[str] | None = None) -> PathsConfig:
        cls._status = load_dotenv(dotenv_path, override=bool(dotenv_path))
        config = super().__new__(cls)
        if dotenv_path is not None:
            object.__setattr__(config, 'dotenv', dotenv_path)
        return config

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

    def resolve(self, *segments: PathLike[str]) -> Path:
        return self.root.joinpath(*segments).resolve()
