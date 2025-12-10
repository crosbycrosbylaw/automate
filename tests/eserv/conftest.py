from __future__ import annotations

import typing

import pytest
from pytest_fixture_classes import fixture_class
from rampy.test import directory  # noqa: F401

from tests.eserv.lib import SAMPLE_EMAIL

if typing.TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path

    from automate.eserv.types import EmailRecord


@pytest.fixture
def record() -> EmailRecord:
    from automate.eserv.record import record_factory

    return record_factory(SAMPLE_EMAIL)


@fixture_class(name='setup_files')
class SetupFilesFixture:
    directory: Path

    def __call__(self, registry: Mapping[str, bytes]) -> Sequence[Path]:
        out: list[Path] = []

        for name, content in registry.items():
            path = self.directory / name
            path.write_bytes(content)

            out.append(path)

        return out
