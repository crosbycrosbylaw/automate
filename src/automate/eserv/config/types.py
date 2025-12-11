__all__ = [
    'BaseFields',
    'Config',
    'CredentialsConfig',
    'EmailAddress',
    'MonitoringFields',
    'PathsConfig',
    'SMTPFields',
    'ValidationHint',
]

from typing import NewType

from ._credentials import CredentialsConfig
from ._fields import BaseFields, MonitoringFields, SMTPFields
from ._paths import PathsConfig
from .main import Config
from .utils import ValidationHint

EmailAddress = NewType('EmailAddress', str)
