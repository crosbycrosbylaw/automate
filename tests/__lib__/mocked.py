from __future__ import annotations

__all__ = ['Mocked', 'mock']

from functools import partial
from typing import TYPE_CHECKING, TypeGuard, overload
from unittest.mock import *

if TYPE_CHECKING:
    from typing import Any


def is_mock(x: Any) -> TypeGuard[Mock]:
    try:
        condition = any([
            isinstance(x, Mock),
            issubclass(x, Mock),
            issubclass(type(x), Mock),
        ])
    except Exception:
        return False
    else:
        return condition


class Mocked[T = Any](MagicMock):
    _map: dict[str, Any]
    _spec: type[T]

    name: str
    return_value: T

    def __call__(self, *_args: ..., **_kwds: ...) -> T: ...

    @staticmethod
    def _cache(mocked: Mocked[Any], **kwds: Any) -> NonCallableMagicMock:
        mocked._map.update(kwds)
        mock_instance = NonCallableMagicMock(spec=mocked._spec, **mocked._map)
        object.__setattr__(mocked, 'return_value', mock_instance)
        return mock_instance

    def new(self, **kwds: Any) -> NonCallableMagicMock:
        if is_mock(mock := self.return_value):
            mock.configure_mock(**kwds)
        else:
            mock = Mocked._cache(self, **kwds)

        mock.reset_mock()
        return mock

    def copy(self, **changes: Any) -> Mocked[T]:
        copy = mock(spec=self._spec, **self._map, **changes)
        object.__setattr__(copy, 'name', f'{copy.name}::copy')
        return copy

    _get_child_mock = new

    @classmethod
    def __new__[A](
        cls,
        spec: type[A],
        namespace: dict[str, Any] | None = None,
        *,
        instance: bool = False,
        **kwds: Any,
    ) -> Mocked[A]:
        """Create an autospec mock for the given type with optional config overrides."""
        # create the base MagicMock from create_autospec
        attrs = {**(namespace or {}), **kwds}

        mock: MagicMock = create_autospec(spec, spec_set=True, instance=instance)

        # bind methods and attributes
        object.__setattr__(mock, '_spec', spec)
        object.__setattr__(mock, '_map', attrs)
        object.__setattr__(mock, 'get', partial(Mocked.get, mock))
        object.__setattr__(mock, 'new', partial(Mocked.new, mock))
        object.__setattr__(mock, 'copy', partial(Mocked.copy, mock))
        object.__setattr__(mock, 'name', mock._extract_mock_name())

        # configure factories and instances accordingly
        if not instance:
            Mocked._cache(mock)
        else:
            mock.configure_mock(**attrs)

        return mock

    def get(self, attr: str) -> Any | Mock:
        obj = None

        if attr in self._map:
            return self._map[attr]

        for a in [attr] if '.' not in attr else attr.split('.'):
            if hasattr(obj, a):
                obj = getattr(obj, a)
            elif any(x.startswith(a) for x in self._map):
                obj = getattr(self.return_value, a)
            elif hasattr(self, a):
                obj = getattr(self, a)

        if obj is None:
            raise AttributeError(f'{attr}\n{obj=}\n{self._map=}')

        return obj


if TYPE_CHECKING:

    @overload
    def mock[T](
        spec: type[T],
        namespace: dict[str, Any],
        *,
        instance: bool = False,
    ) -> Mocked[T]: ...
    @overload
    def mock[T](
        spec: type[T],
        *,
        instance: bool = False,
        **kwds: Any,
    ) -> Mocked[T]: ...
    def mock(*_args: ..., **_kwds: ...) -> ...: ...


mock = Mocked.__new__
