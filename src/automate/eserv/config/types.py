__all__ = ['Config', 'EmailAddress', 'ValidationHint']

from typing import NewType

from .main import Config
from .utils import ValidationHint

EmailAddress = NewType('EmailAddress', str)
