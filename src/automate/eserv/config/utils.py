from __future__ import annotations

__all__ = ['email_env_var', 'env_var', 'hint', 'int_env_var']

import os
import re
from typing import TYPE_CHECKING, Literal, overload

from rampy import create_field_factory

from automate.eserv.errors.types import InvalidFormatError, MissingVariableError

if TYPE_CHECKING:
    from collections.abc import Callable

    from automate.eserv.types import *


class ValidationHint:
    def __init__(self, string: str):
        self.__str__ = lambda: string


hint = create_field_factory(ValidationHint)


@overload
def env_var[T = str](
    key: str,
    *,
    into: Callable[[str], T] = str,
    optional: Literal[True],
) -> Callable[[], T | None]: ...
@overload
def env_var[T = str](
    key: str,
    default: str | None = None,
    into: Callable[[str], T | ValidationHint] = str,
) -> Callable[[], T]: ...
def env_var[T = str](
    key: str,
    default: str | None = None,
    into: Callable[[str], T | ValidationHint] = str,
    optional: bool = False,
) -> ...:
    def _factory() -> ...:
        value = os.getenv(key, default)

        if value is None:
            if not optional:
                raise MissingVariableError(name=key)
            return None

        try:
            output = into(value)
        except (TypeError, ValueError) as e:
            raise InvalidFormatError(key, value, str(e)) from e
        else:
            if isinstance(output, ValidationHint):
                raise InvalidFormatError(key, value, str(output))

            return output

    return _factory


def int_env_var(key: str, default: int | None = None):

    def _into(s: str):
        try:
            return int(s)
        except ValueError:
            return hint('expected an integer')

    return env_var(key, default=None if not isinstance(default, int) else str(default), into=_into)


def email_env_var(key: str):
    pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    into = lambda s: EmailAddress(s) if pattern.match(s) else hint('expected valid email address')
    return env_var(key, into=into)
