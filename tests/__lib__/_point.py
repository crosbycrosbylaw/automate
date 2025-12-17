from __future__ import annotations

__all__ = ['Point', 'point_values']
from dataclasses import astuple, dataclass


@dataclass
class Point:
    x: int = 0
    y: int = 0
    z: int = 0

    def values(self) -> tuple[int, ...]:
        return astuple(self)


def point_values() -> tuple[int, ...]:
    return Point().values()
