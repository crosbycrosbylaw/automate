from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, overload

import orjson
from rampy.util import make_factory
from setup_console import console

from automate.eserv.monitor.result import process_pipeline_result
from automate.eserv.types.results import ProcessedResult

if TYPE_CHECKING:
    from automate.eserv.types import EmailRecord, ErrorDict, ProcessedResultDict


@dataclass
class StateTracker:
    """Audit log for processed emails (UID-based)."""

    path: Path

    _entries: dict[str, ProcessedResult] = field(default_factory=dict, init=False)

    @property
    def processed(self) -> set[str]:
        """Get the set of processed email UIDs."""
        return {*self._entries.keys()}

    def __post_init__(self) -> None:
        """Load email state from disk after initialization."""
        self.print = console.bind(entries=self._entries, path=self.path.as_posix())

        if self.path.exists():
            self._load()

    def _load(self) -> None:
        """Load from JSON, fresh start if missing."""

        try:
            with self.path.open("rb") as f:
                data: dict[str, ProcessedResultDict] = orjson.loads(f.read() or b"{}")

            self._entries = {
                uid: process_pipeline_result(entry) for uid, entry in data.items()
            }
        except Exception:
            self.print.exception()
            self._entries = {}

        else:
            self.print.info(event="Loaded audit log")

    @overload
    def record(self, result: ProcessedResult, /) -> None: ...
    @overload
    def record(
        self, record: EmailRecord, /, error: ErrorDict | None = None
    ) -> None: ...
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
            self._entries[arg.uid] = process_pipeline_result(record=arg, error=error)

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
        data: dict[str, ProcessedResultDict] = {
            uid: entry.asdict() for uid, entry in self._entries.items()
        }

        self.path.parent.mkdir(parents=True, exist_ok=True)

        with self.path.open("wb") as f:
            f.write(orjson.dumps(data, option=orjson.OPT_INDENT_2))


get_state_tracker = make_factory(StateTracker)
