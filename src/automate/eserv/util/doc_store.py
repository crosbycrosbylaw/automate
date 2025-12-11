from __future__ import annotations

import contextlib
import typing

if typing.TYPE_CHECKING:
    from pathlib import Path

from rampy import rootpath

# -- Temporary Files -- #

TMP = rootpath('service', 'tmp', mkdir=True)


def _prune_temp() -> None:
    for p in TMP.iterdir():
        if p.is_dir() and not [*p.iterdir()]:
            with contextlib.suppress(PermissionError):
                p.unlink()


def _clean_document_name(raw: str | None) -> str:
    prefix = '' if not raw else f'{raw}_'
    return ''.join(c for c in f'{prefix}temp_store' if c.isalnum() or c in {'.', '_', '-'})


def get_doc_store(name: str | None = None) -> Path:
    """Get a temporary directory to store downloaded documents."""
    _prune_temp()

    cleaned = _clean_document_name(name)

    path = TMP / cleaned
    path.mkdir(parents=True, exist_ok=True)

    return path.resolve(strict=True)
