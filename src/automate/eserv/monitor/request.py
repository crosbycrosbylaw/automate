from __future__ import annotations

__all__ = ['GraphRequest']

from dataclasses import dataclass, field, fields
from typing import TYPE_CHECKING

from kiota_abstractions.base_request_configuration import RequestConfiguration
from rampy import make_factory

if TYPE_CHECKING:
    from .abc import GraphRequestBuilder, QueryParameters


@dataclass
class GraphRequest[T]:
    builder: GraphRequestBuilder[T]

    count: bool | None = field(default=None, doc='Include count of items')
    expand: list[str] | None = field(default=None, doc='Expand related entities')
    filter: str | None = field(default=None, doc='Filter items by property values')
    orderby: list[str] | None = field(default=None, doc='Order items by property values')
    search: str | None = field(default=None, doc='Search items by search phrases')
    select: list[str] | None = field(default=None, doc='Select properties to be returned')
    skip: int | None = field(default=None, doc='Skip the first n items')
    top: int | None = field(default=None, doc='Show only the first n items')

    odata_next_link: str | None = field(init=False)

    def _qs(self) -> QueryParameters:
        cls = getattr(self.builder, next(a for a in dir(self.builder) if a.endswith('QueryParameters')))
        return cls(**{f.name: getattr(self, f.name) for f in fields(self) if f.doc is not None})

    async def get(self) -> list[T]:
        response = await self.builder.get(RequestConfiguration(query_parameters=self._qs()))
        self.odata_next_link = getattr(response, 'odata_next_link', None)
        value = getattr(response, 'value', [])
        return value if isinstance(value, list) else [value]

    async def collect(self) -> list[T]:
        out: list[T] = []
        while next(self):
            out += await self.get()
        return out

    def __next__(self) -> bool:
        if not hasattr(self, 'odata_next_link'):
            return True

        if self.odata_next_link is not None:
            self.builder = self.builder.with_url(self.odata_next_link)
            return True

        return False


build_request = make_factory(GraphRequest)
