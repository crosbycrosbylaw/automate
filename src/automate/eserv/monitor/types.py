from __future__ import annotations

from typing import Literal, NewType

__all__ = ['EmailProcessor', 'GraphClient', 'StatusFlag']

from .client import GraphClient
from .processor import EmailProcessor

StatusFlag = NewType('StatusFlag', dict[Literal['id', 'value'], str])
