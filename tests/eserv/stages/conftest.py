"""Unit tests for upload module.

Tests cover:
- DropboxManager lazy client initialization
- Folder index fetching with pagination
- File upload orchestration
- upload_documents workflow
- Folder matching vs manual review routing
- Multi-file naming logic
- Notification dispatch
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import field
from typing import TYPE_CHECKING, Any, Self
from unittest.mock import MagicMock, Mock, patch

import pytest
from pytest_fixture_classes import fixture_class
from rampy import test

from automate.eserv.upload import upload_documents

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Sequence
    from inspect import BoundArguments
    from pathlib import Path

    from automate.eserv.types import IntermediaryResult


@pytest.fixture
def mock_credential() -> Mock:
    """Create mock OAuthCredential."""
    return Mock(
        access_token='test_access_token',
        refresh_token='test_refresh_token',
        client_id='test_client_id',
        client_secret='test_client_secret',
    )


@pytest.fixture
def mock_paths() -> Mock:
    return Mock(manual_review_folder='/Manual Review/')


@pytest.fixture
def mock_cache(directory: Path) -> Mock:
    return Mock(index_file=directory / 'tmp' / 'index_cache.json', ttl_hours=4)


@pytest.fixture
def mock_smtp() -> Mock:
    return Mock(
        server='smtp.test.com',
        port=587,
        from_addr='test@example.com',
        to_addr='recipient@example.com',
    )


@pytest.fixture
def mock_config(
    mock_credential: Mock,
    mock_paths: Mock,
    mock_cache: Mock,
    mock_smtp: Mock,
) -> Mock:
    """Create mock Config object."""
    mock_credentials = Mock(__getitem__=Mock(return_value=mock_credential))
    return Mock(
        credentials=mock_credentials,
        paths=mock_paths,
        cache=mock_cache,
        smtp=mock_smtp,
    )


@pytest.fixture
def mock_document(directory: Path) -> Path:
    """Create mock PDF file."""
    pdf_path = directory / 'test_document.pdf'
    pdf_path.write_bytes(b'%PDF-1.4\nMock PDF content')
    return pdf_path


@fixture_class(name='run_upload_subtest')
class UploadDocumentSubtestFixture(test.subtestfix):
    subtests: ...
    factory = staticmethod(upload_documents)

    mock_config: Mock
    mock_cache: Mock

    mock_matcher: Mock = field(init=False, default_factory=Mock)
    mock_dbx: Mock = field(init=False, default_factory=Mock)
    mock_notifier: Mock = field(init=False, default_factory=Mock)

    @contextmanager
    def context(self) -> Generator[Any]:
        try:
            with (
                patch('automate.eserv.upload.IndexCache', Mock(return_value=self.mock_cache)),
                patch('automate.eserv.upload.FolderMatcher', Mock(return_value=self.mock_matcher)),
                patch(
                    'automate.eserv.upload.Notifier',
                    MagicMock(
                        return_value=self.mock_notifier,
                        spec=['notify_upload_success', 'notify_manual_review', 'notify_error'],
                    ),
                ),
            ):
                yield
        finally:
            pass

    def converter(self, **kwds: Any) -> BoundArguments:
        cached_paths = kwds.pop('cached_paths', ())
        case_name = kwds.pop('case_name', 'Unknown')

        self.mock_cache.configure_mock(**{
            'is_stale.return_value': kwds.pop('stale_cache', False),
            'get_all_paths.return_value': cached_paths,
        })

        match_returns = None
        index_returns = {}

        for path in cached_paths:
            index_returns[path] = {
                'name': path.split('/').pop().strip(),
            }
            if match_returns or not case_name:
                continue
            if case_name in path:
                match_returns = Mock(folder_path=path)

        self.mock_matcher.configure_mock(**{
            'find_best_match.return_value': match_returns,
        })

        self.mock_dbx.configure_mock(**{
            'uploaded': kwds.pop('uploaded', []),
            'index.return_value': index_returns,
        })

        self.mock_config.configure_mock(**{
            'creds.dropbox.manager': self.mock_dbx,
        })
        return super().bind_factory(
            documents=kwds['documents'],
            case_name=case_name,
            lead_name=kwds.pop('lead_name', 'Motion'),
            config=self.mock_config,
        )

    if TYPE_CHECKING:

        def __call__(
            self,
            name: str,
            *,
            documents: Sequence[Path],
            case_name: str | None = 'Unknown',
            lead_name: str | None = 'Motion',
            stale_cache: bool = False,
            cached_paths: Sequence[str] = (),
            uploaded: Sequence[str] = (),
            extensions: Callable[[Self], Sequence[None] | dict[str, Any]] | None = None,
            assertions: Callable[[IntermediaryResult], dict[str, Any]] | None = None,
            **kwds: ...,
        ) -> None: ...
