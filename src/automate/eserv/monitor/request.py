from __future__ import annotations

from dataclasses import InitVar, dataclass, field, fields
from typing import TYPE_CHECKING, Any, ClassVar

from kiota_abstractions.base_request_builder import BaseRequestBuilder
from kiota_abstractions.base_request_configuration import RequestConfiguration
from rampy import make_factory

if TYPE_CHECKING:
    from msgraph.graph_service_client import GraphServiceClient

    from .types import GetQueryParameter


@dataclass
class requestspec[I: Any = Any]:
    path_parameters: str | dict[str, Any]


def parse_spec(spec: requestspec[Any]) -> tuple[str, str | dict[str, Any]]:
    return str(hash(spec.path_parameters)), spec.path_parameters


@dataclass(kw_only=True)
class MSGraphQueryRequest[I: Any = Any]:
    odata_next_link_map: ClassVar[dict[str, Any]]

    spec: InitVar[requestspec[I]] = field(kw_only=False)

    client: GraphServiceClient = field(metadata={'exclude': True})

    count: bool | None = field(default=None, doc='Include count of items')
    expand: list[str] | None = field(default=None, doc='Expand related entities')
    filter: str | None = field(default=None, doc='Filter items by property values')
    orderby: list[str] | None = field(default=None, doc='Order items by property values')
    search: str | None = field(default=None, doc='Search items by search phrases')
    select: list[str] | None = field(default=None, doc='Select properties to be returned')
    skip: int | None = field(default=None, doc='Skip the first n items')
    top: int | None = field(default=None, doc='Show only the first n items')

    @classmethod
    def _register(cls, spec: requestspec[Any]) -> tuple[str, str | dict[str, Any]]:
        parsed = parse_spec(spec)
        cls.odata_next_link_map.setdefault(parsed[0], None)
        return parsed

    def __post_init__(self, spec: requestspec[I]) -> None:
        self.key, path_params = self._register(spec)
        self.builder = BaseRequestBuilder(
            self.client.request_adapter,
            self.client.url_template,
            path_params,
        )

    def configure[T: GetQueryParameter](self) -> RequestConfiguration[Any]:
        cls = getattr(
            self.builder,
            next(x for x in dir(self.builder) if x.endswith('GetQueryParameters')),
        )
        return RequestConfiguration(
            query_parameters=cls(**{
                f.name: getattr(self, f.name) for f in fields(cls) if hasattr(self, f.name)
            })
        )

    @classmethod
    def _get_next_link(cls, spec_key: str) -> str | None:
        return cls.odata_next_link_map.get(spec_key)

    @classmethod
    def _set_next_link(cls, spec_key: str, next_link: str | None) -> None:
        cls.odata_next_link_map[spec_key] = next_link

    async def __next__(self) -> bool:
        """Return a flag indicating the builder has been updated with the `odata_next_link` from the previous request."""
        if odata_next_link := self._get_next_link(self.key):
            self.builder = self.builder.with_url(odata_next_link)
        return bool(odata_next_link)

    async def get(self) -> list[I]:
        response = await self.builder.get(self.configure())
        self._set_next_link(self.key, getattr(response, 'odata_next_link', None))
        return getattr(response, 'value', [])


build_msgraph_query_request = make_factory(MSGraphQueryRequest)
