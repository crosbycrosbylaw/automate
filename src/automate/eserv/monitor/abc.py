from __future__ import annotations

__all__ = ['GraphRequestBuilder', 'QueryParameters']

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from kiota_abstractions.base_request_configuration import RequestConfiguration


class _CollectionResponse[T](Protocol):
    value: list[T] | None


class _ItemResponse[T](Protocol):
    value: T | None


type _GraphResponse[T] = _CollectionResponse[T] | _ItemResponse[T]


class GraphRequestBuilder[T](Protocol):
    async def get(self, request_configuration: RequestConfiguration[Any]) -> _GraphResponse[T] | None: ...
    def with_url(self, raw_url: str) -> Any: ...


@dataclass
@runtime_checkable
class QueryParameters(Protocol):
    def get_query_parameter(self, original_name: str) -> str: ...
