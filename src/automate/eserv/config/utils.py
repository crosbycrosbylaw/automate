from __future__ import annotations

__all__ = ['email_env_var', 'env_var', 'get_example_env_dict', 'hint', 'int_env_var']

import os
import re
from typing import TYPE_CHECKING, Final, Literal, NewType, overload

from rampy import make_factory

from automate.eserv.errors.types import InvalidFormatError, MissingVariableError

if TYPE_CHECKING:
    from collections.abc import Callable


EmailAddress = NewType('EmailAddress', str)


class ValidationHint:
    def __init__(self, string: str):
        self.__str__ = lambda: string


hint = make_factory(ValidationHint)

_REGISTRY: Final[dict[str, str]] = {}


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

    if default or optional:
        _REGISTRY[key] = default or ''

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
    from automate.eserv.config.types import EmailAddress

    pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    into = lambda s: EmailAddress(s) if pattern.match(s) else hint('expected valid email address')
    return env_var(key, into=into)


def get_example_env_dict() -> dict[str, str]:
    registry = _REGISTRY.copy()

    registry.setdefault('PROJECT_ROOT', './')
    registry.setdefault('SMTP_SERVER', 'smtp.example.com')
    registry.setdefault('SMTP_FROM_ADDR', 'test@example.com')
    registry.setdefault('SMTP_TO_ADDR', 'test@example.com')

    return registry
