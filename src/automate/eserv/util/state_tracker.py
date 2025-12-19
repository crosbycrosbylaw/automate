from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar, Final, Self, overload

import orjson

from automate.eserv.monitor.result import process_pipeline_result
from automate.eserv.types.results import ProcessedResult
from setup_console import mode, mode_console

if TYPE_CHECKING:
    from pathlib import Path

    from automate.eserv.types import EmailRecord, ErrorDict, ProcessedResultDict
    from setup_console import ModeConsole

_MIN_CONTENT_LENGTH: Final[int] = len(b'{}')


@dataclass
class StateTracker:
    """Audit log for processed emails (UID-based)."""

    _instance: ClassVar[Self]

    path: Path

    _entries: dict[str, ProcessedResult] = field(init=False, repr=False)
    _print: ModeConsole = field(init=False, repr=False)

    @property
    def processed(self) -> set[str]:
        """Get the set of processed email UIDs."""
        return {*self._entries.keys()}

    def __new__(cls, path: Path) -> Self:
        return getattr(cls, '_instance', cls._setup(path))

    @classmethod
    def _setup(cls, path: Path) -> Self:
        self = super().__new__(cls)
        # Initialize mutable state BEFORE calling __init__ to prevent re-initialization
        object.__setattr__(self, '_entries', {})
        object.__setattr__(self, '_print', mode_console(mode.VERBOSE)())
        self.__init__(path)
        cls._instance = self

        console = self._print.unwrap().bind(path=str(self.path))

        try:
            content = self.path.read_bytes()

            if len(content) >= _MIN_CONTENT_LENGTH:
                data: dict[str, ProcessedResultDict] = orjson.loads(content)
            else:
                data = {}

            for uid, entry in data.items():
                self._entries[uid] = process_pipeline_result(entry)

        except orjson.JSONDecodeError:
            console.warning('Failed to parse audit log')

        except TypeError, ValueError, FileNotFoundError:
            console.exception(cls._setup.__qualname__)

        else:
            if entries := self._entries:
                self._print.info('Parsed result entries', count=len(entries))

        console.info(event='Loaded audit log')
        return self

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
        data: dict[str, ProcessedResultDict] = {uid: entry.asdict() for uid, entry in self._entries.items()}

        self.path.parent.mkdir(parents=True, exist_ok=True)

        with self.path.open('wb') as f:
            f.write(orjson.dumps(data, option=orjson.OPT_INDENT_2))
