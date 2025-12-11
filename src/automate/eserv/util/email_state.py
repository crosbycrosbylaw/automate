from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, overload

import orjson
from rampy.util import create_field_factory

from automate.eserv.monitor.result import result_factory
from automate.eserv.types.results import ProcessedResult
from setup_console import console

if TYPE_CHECKING:
    from pathlib import Path

    from automate.eserv.types import EmailRecord, ErrorDict, ProcessedResultDict


@dataclass
class EmailState:
    """Audit log for processed emails (UID-based)."""

    json_path: Path
    _entries: dict[str, ProcessedResult] = field(default_factory=dict, init=False)

    @property
    def processed(self) -> set[str]:
        """Get the set of processed email UIDs."""
        return {*self._entries.keys()}

    def __post_init__(self) -> None:
        """Load email state from disk after initialization."""
        self._load()

    def _load(self) -> None:
        """Load from JSON, fresh start if missing."""
        if not self.json_path.exists():
            self._entries = {}
            return

        try:
            with self.json_path.open('rb') as f:
                data: dict[str, ProcessedResultDict] = orjson.loads(f.read())

            self._entries = {uid: result_factory(entry) for uid, entry in data.items()}
        except Exception:
            console.exception('EmailState loading')
            self._entries = {}

    @overload
    def record(self, result: ProcessedResult, /) -> None: ...
    @overload
    def record(self, record: EmailRecord, /, error: ErrorDict | None = None) -> None: ...
    def record(
        self,
        arg: EmailRecord | ProcessedResult,
        error: ErrorDict | None = None,
    ) -> None:
        """Record processed email."""
        if isinstance(arg, ProcessedResult):
            if arg.record is not None:
                self._entries[arg.record.uid] = arg
        else:
            self._entries[arg.uid] = result_factory(record=arg, error=error)

        self._save()

    def is_processed(self, uid: str) -> bool:
        """Check if email has been processed."""
        return uid in self._entries

    def clear_flags(self, uid: str) -> None:
        """Clear flags to allow reprocessing (removes entry)."""
        self._entries.pop(uid, None)
        self._save()

    def _save(self) -> None:
        """Persist to JSON."""
        data: dict[str, ProcessedResultDict] = {uid: entry.asdict() for uid, entry in self._entries.items()}

        self.json_path.parent.mkdir(parents=True, exist_ok=True)

        with self.json_path.open('wb') as f:
            f.write(orjson.dumps(data, option=orjson.OPT_INDENT_2))


state_tracker_factory = create_field_factory(EmailState)
