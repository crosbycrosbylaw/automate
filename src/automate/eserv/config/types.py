__all__ = [
    'CredentialsConfig',
    'DataclassInstance',
    'DataclassType',
    'EmailAddress',
    'PathsConfig',
    'StrPath',
    'ValidationHint',
]


from os import PathLike
from typing import TYPE_CHECKING, ClassVar, Protocol

from ._credentials import CredentialsConfig
from ._paths import PathsConfig
from .utils import EmailAddress, ValidationHint

if TYPE_CHECKING:
    from dataclasses import Field


class DataclassInstance(Protocol):
    __dataclass_fields__: ClassVar[dict[str, Field]]


type DataclassType = type[DataclassInstance]
type StrPath = str | PathLike[str]
