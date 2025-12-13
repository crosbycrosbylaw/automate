__all__ = [
    'DownloadInfo',
    'EmailInfo',
    'EmailRecord',
    'PartialEmailRecord',
    'TokenManager',
    'UploadInfo',
]

from dataclasses import asdict, astuple, dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, Self, runtime_checkable

if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path

    from automate.eserv.util.oauth_credential import OAuthCredential


@dataclass(frozen=True, slots=True)
class PartialEmailRecord:
    """Basic email metadata fetched from Outlook."""

    uid: str
    sender: str
    subject: str


EmailInfo = PartialEmailRecord


@dataclass(frozen=True, slots=True)
class EmailRecord(EmailInfo):
    """All relevant email metadata fetched from Outlook."""

    received_at: datetime
    html_body: str


@dataclass(slots=True, frozen=True)
class UploadInfo:
    """Information about an upload operation.

    Attributes:
        doc_count: The number of documents uploaded.
        case_name: The name of the case associated with the upload, or None if not applicable.

    """

    doc_count: int
    case_name: str = field(default='unknown')

    def unpack(self) -> tuple[int, str]:
        return astuple(self)

    def asdict(self) -> dict[str, int | str]:
        return asdict(self)


@dataclass(slots=True)
class DownloadInfo:
    """Information about a file to be downloaded.

    Attributes:
        source (str): The URL or path from which to download the file.
        filename (str): The name to use when saving the downloaded file.

    """

    source: str
    lead_name: str = field(default='untitled')

    store_path: Path = field(init=False)

    def __post_init__(self) -> None:
        from automate.eserv import get_doc_store

        self.store_path = get_doc_store(self.lead_name)

    def unpack(self) -> tuple[str, str, Path]:
        return astuple(self)

    def asdict(self) -> dict[str, str]:
        out = asdict(self)
        out['store_path'] = self.store_path.as_posix()
        return out


@runtime_checkable
@dataclass
class TokenManager[T](Protocol):
    credential: OAuthCredential[Self] = field(init=True)

    def _refresh_token(self) -> dict[str, Any]: ...

    _client: T | None = field(init=False, default=None, repr=False)

    @property
    def client(self) -> T: ...
