from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, NewType, Protocol, runtime_checkable

__all__ = [
    'EmailProcessor',
    'GraphClient',
    'MailFolder',
    'MailFoldersRequestBuilder',
    'Message',
    'MessagesRequestBuilder',
    'QueryParameters',
    'RequestConfiguration',
    'SingleValueLegacyExtendedProperty',
    'StatusFlag',
    'UserItemRequestBuilder',
]
from kiota_abstractions.base_request_configuration import RequestConfiguration
from msgraph.generated.models.mail_folder import MailFolder
from msgraph.generated.models.message import Message
from msgraph.generated.models.single_value_legacy_extended_property import SingleValueLegacyExtendedProperty
from msgraph.generated.users.item.mail_folders.item.messages.messages_request_builder import (
    MessagesRequestBuilder,
)
from msgraph.generated.users.item.mail_folders.mail_folders_request_builder import (
    MailFoldersRequestBuilder,
)
from msgraph.generated.users.item.user_item_request_builder import UserItemRequestBuilder

from .client import GraphClient
from .processor import EmailProcessor


@dataclass
@runtime_checkable
class QueryParameters(Protocol):
    def get_query_parameter(self, original_name: str) -> str: ...


class CollectionResponse[T](Protocol):
    value: list[T] | None


class ItemResponse[T](Protocol):
    value: T | None


type Response[T] = CollectionResponse[T] | ItemResponse[T]


class BuilderProto[T](Protocol):
    async def get(self, request_configuration: RequestConfiguration[Any]) -> Response[T] | None: ...
    def with_url(self, raw_url: str) -> Any: ...


StatusFlag = NewType('StatusFlag', dict[Literal['id', 'value'], str])
