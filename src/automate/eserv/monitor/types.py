from __future__ import annotations

from typing import Any, ClassVar, Literal, NewType, Protocol

__all__ = [
    'EmailProcessor',
    'GetQueryParameter',
    'GraphClient',
    'MSGraphQueryRequest',
    'MailFolder',
    'MailFoldersRequestBuilder',
    'Message',
    'MessagesRequestBuilder',
    'RequestConfiguration',
    'SingleValueLegacyExtendedProperty',
    'StatusFlag',
    'UserItemRequestBuilder',
]
from kiota_abstractions.base_request_configuration import RequestConfiguration
from msgraph.generated.models.mail_folder import MailFolder
from msgraph.generated.models.message import Message
from msgraph.generated.models.single_value_legacy_extended_property import (
    SingleValueLegacyExtendedProperty,
)
from msgraph.generated.users.item.mail_folders.item.messages.messages_request_builder import (
    MessagesRequestBuilder,
)
from msgraph.generated.users.item.mail_folders.mail_folders_request_builder import (
    MailFoldersRequestBuilder,
)
from msgraph.generated.users.item.user_item_request_builder import UserItemRequestBuilder

from .client import GraphClient
from .processor import EmailProcessor
from .request import MSGraphQueryRequest


class GetQueryParameter(Protocol):
    __dataclass_fields__: ClassVar[dict[str, Any]]

    def get_query_parameter(self, original_name: str) -> str: ...


StatusFlag = NewType('StatusFlag', dict[Literal['id', 'value'], str])
