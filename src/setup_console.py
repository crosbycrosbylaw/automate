from __future__ import annotations

__all__ = ['DynConsole', 'Evaluator', 'ModeConsole']

from abc import abstractmethod
from types import new_class
from typing import TYPE_CHECKING, Any, ClassVar, Protocol

from rampy import console as _console
from rampy import mode
from structlog import get_logger
from structlog.stdlib import BoundLogger

if TYPE_CHECKING:
    from collections.abc import Callable


# -- Standard Loggers -- #

console = _console.root()


def get_console(**kwds: Any):
    return _console.bind(**kwds)


# -- Conditional Loggers -- #


def _noop(*args: ..., **kwds: ...) -> None:
    return


class _SupportsBool(Protocol):
    @abstractmethod
    def __bool__(self) -> bool: ...


type Evaluator = Callable[[], bool] | _SupportsBool


class DynConsole[T: Evaluator = Evaluator](BoundLogger):
    KEYWORDS: ClassVar[list[str]] = [
        'info',
        'warning',
        'error',
        'exception',
        'debug',
        'critical',
    ]

    _evaluator: ClassVar[Callable[..., bool]]
    _wraps: ClassVar[BoundLogger]

    def __init__(self):
        console = self._wraps
        super(BoundLogger, self).__init__(console._logger, console._processors, console._context)

    def __getattribute__(self, name):
        bypass_conditions = [
            not callable(value := object.__getattribute__(self, name)),
            object.__getattribute__(self, '_evaluator').__call__(),
            all(x not in name for x in object.__getattribute__(self, 'KEYWORDS')),
        ]
        return value if any(bypass_conditions) else _noop

    def unwrap(self) -> BoundLogger:
        return self._wraps


def dyn_console[T: Evaluator](evaluator: T, /, **kwds: Any) -> type[DynConsole[T]]:
    return new_class(
        name=getattr(evaluator, '__name__', evaluator.__class__.__name__).capitalize()
        + 'ConditionalLogger',
        bases=(DynConsole,),
        exec_body=lambda attrs: attrs.update(
            _evaluator=evaluator if callable(evaluator) else evaluator.__bool__,
            _wraps=get_logger().bind(**kwds),
        ),
    )


type ModeConsole = DynConsole[mode]


def mode_console[T: mode](evaluator: T) -> type[DynConsole[T]]:
    return dyn_console(evaluator)
