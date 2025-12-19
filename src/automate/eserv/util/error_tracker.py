"""Pipeline error tracking and logging.

Tracks errors by pipeline stage for debugging and monitoring.
Errors are logged to JSON with timestamps and context.

Classes:
    PipelineStage: Enum of pipeline stages for error categorization.
    ErrorTracker: Error logging with stage-based categorization.
"""

from __future__ import annotations

import traceback
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, ClassVar, NoReturn, Self, Unpack, overload

import orjson

from setup_console import mode, mode_console

if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path

    from automate.eserv.errors.pipeline import PipelineError
    from automate.eserv.types import ErrorDict
    from automate.eserv.types.enums import PipelineStage
    from automate.eserv.types.results import IntermediaryResult
    from setup_console import *


def _path_factory():
    from automate.eserv._module import get_paths

    return get_paths().errors


@dataclass
class ErrorTracker:
    """Tracks pipeline errors with stage-based categorization.

    Maintains a JSON log of errors with timestamps, stages, and context.

    Attributes:
        path: Path to error log JSON path.
        _errors: In-memory error log.

    """

    _instance: ClassVar[Self]

    path: Path = field(default_factory=_path_factory)
    uid: str | None = field(init=False, default=None)

    _print: ModeConsole = field(init=False, repr=False)
    _prev_map: dict[str | None, int] = field(init=False, repr=False)

    @classmethod
    def set(cls, *, uid: str | None = None, path: Path | None = None) -> None:
        if path is not None or not hasattr(cls, '_instance'):
            cls._setup(path or cls.get_path() or _path_factory())

        cls._instance.uid = uid

    @classmethod
    def get(cls) -> ErrorTracker:
        return cls._instance

    @classmethod
    @contextmanager
    def track(cls, uid: str, *, path: Path | None = None) -> Generator[ErrorTracker]:
        cls.set(uid=uid, path=path)
        try:
            yield cls.get()
        finally:
            cls.set(uid=None)

    @classmethod
    def get_path(cls) -> Path | None:
        return getattr(getattr(cls, '_instance', None), 'path', None)

    @property
    def prev_error(self) -> ErrorDict | None:
        """Get the most recent error logged for the current UID."""
        if index := self._prev_map.get(self.uid):
            return self._errors[index]
        return None

    _errors: list[ErrorDict] = field(init=False, repr=False)

    def __new__(cls, path: Path) -> Self:
        return getattr(cls, '_instance', cls._setup(path))

    @classmethod
    def _setup(cls, path: Path) -> Self:
        """Load existing error log from disk."""
        self = super().__new__(cls)
        # Initialize mutable state BEFORE calling __init__ to prevent re-initialization
        object.__setattr__(self, '_print', mode_console(mode.VERBOSE)())
        object.__setattr__(self, '_prev_map', {})
        object.__setattr__(self, '_errors', [])
        self.__init__(path)
        cls._instance = self

        console = self._print.unwrap().bind(path=str(self.path))

        if not self.path.exists():
            self._save_errors()
            self._print.info('Created error log')
            return self

        try:
            self._errors = orjson.loads(self.path.read_bytes())

        except orjson.JSONDecodeError:
            console.exception('Failed to load error log')
            self._save_errors()

        else:
            if errors := self._errors:
                self._print.info('Parsed error entries', count=len(errors))

        console.info('Loaded error log')
        return self

    def _save_errors(self) -> None:
        """Save current error log to JSON path."""
        self.path.write_bytes(orjson.dumps(self._errors, option=orjson.OPT_INDENT_2))

    def _save_entry(self, **entry: Unpack[ErrorDict]) -> None:
        index = len(self._errors)
        self._errors.insert(index, entry)
        self._prev_map[self.uid] = index
        self._save_errors()

    if TYPE_CHECKING:

        @overload
        def error(
            self,
            event: str | None = None,
            *,
            exception: PipelineError,
            context: dict[str, Any] | None = None,
        ) -> IntermediaryResult: ...
        @overload
        def error(
            self,
            event: str | None = None,
            *,
            exception: Exception,
            context: dict[str, Any] | None = None,
            stage: PipelineStage = PipelineStage.UNKNOWN,
        ) -> IntermediaryResult: ...
        @overload
        def error(
            self,
            event: str | None = None,
            *,
            result: IntermediaryResult,
            context: dict[str, Any] | None = None,
            stage: PipelineStage = PipelineStage.UNKNOWN,
        ) -> NoReturn:
            """Log a pipeline error.

            Args:
                event (str | None):
                    Human-readable error description.
                stage (PipelineStage):
                    Pipeline stage where error occurred.
                result (IntermediaryResult | None):
                    An `IntermediaryResult` with an `ERROR` status.
                context (dict[str, Any] | None):
                    Additional context (e.g., path paths, API responses).

            Raises:
                The `PipelineError` created from the non-result arguments.

            """

        @overload
        def error(
            self,
            event: str,
            *,
            context: dict[str, Any] | None = None,
            stage: PipelineStage = PipelineStage.UNKNOWN,
        ) -> IntermediaryResult: ...

    def error(  # noqa: D417
        self,
        event=None,
        *,
        stage=None,
        exception=None,
        context=None,
        **kwds: IntermediaryResult,
    ) -> IntermediaryResult:
        """Log a pipeline error.

        Args:
            event (str | None):
                Human-readable error description.
            stage (PipelineStage):
                Pipeline stage where error occurred.
            exception (Exception | None):
                Exception to wrap in `PipelineError`.
            context (dict[str, Any] | None):
                Additional context (e.g., path paths, API responses).

        Returns:
            out (IntermediaryResult):
                The result created from the provided information.

        """
        from automate.eserv.errors.types import PipelineError
        from automate.eserv.types import IntermediaryResult, UploadStatus

        context = context or {}

        if isinstance(result := kwds.get('result'), IntermediaryResult):
            context['folder_path'] = result.folder_path
            context['uploaded_files'] = result.uploaded_files
            context['match'] = result.match

        if isinstance(exception, PipelineError):
            err = exception
        elif isinstance(exception, Exception):
            err = PipelineError.from_exc(exception, stage=stage, message=event)
        else:
            err = PipelineError.from_stage(stage, message=event)

        err.update(context, uid=self.uid)
        err.print(event)

        entry = err.entry()

        if 'context' in entry and 'traceback' not in entry['context']:
            entry['context']['traceback'] = traceback.format_tb(err.__traceback__)

        self._save_entry(**entry)

        if result and exception:
            raise err from exception
        if result:
            raise err

        return IntermediaryResult(status=UploadStatus.ERROR, error=err.message)

    @property
    def exception(self):
        return self.error

    def warning(
        self,
        message: str,
        *,
        stage: PipelineStage,
        context: dict[str, str] | None = None,
        **kwds: Any,
    ) -> None:
        """Log a pipeline error.

        Args:
            message: Human-readable error description.
            stage: Pipeline stage where error occurred.
            context: Optional additional context (e.g., path paths, API responses).
            **kwds: Additional keyword arguments to include in context.

        """
        context = context or {}
        context.update(kwds)

        self._save_entry(
            uid=self.uid,
            message=message,
            timestamp=datetime.now(UTC).isoformat(),
            category=stage.value,
            context=context,
        )

        console = self._print.unwrap()
        console.warning(f'Pipeline warning: {message}', uid=self.uid, stage=stage.value)

    def get_unidentified_errors(self) -> list[ErrorDict]:
        """Get all errors that are not associated with a specific email.

        Returns:
            List of unidentified error entries.

        """
        return [e for e in self._errors if 'uid' not in e or e['uid'] is None]

    def get_errors_for_email(self, uid: str) -> list[ErrorDict]:
        """Get all errors for a specific email.

        Args:
            uid: Identifier for this email record.

        Returns:
            List of error entries for this email.

        """
        return [e for e in self._errors if e.get('uid') == uid]

    def get_errors_by_stage(self, stage: PipelineStage) -> list[ErrorDict]:
        """Get all errors for a specific pipeline stage.

        Args:
            stage: Pipeline stage to filter by.

        Returns:
            List of error entries for this stage.

        """
        return [e for e in self._errors if e['category'] == stage.value]

    def clear_old_errors(self, days: int = 30) -> None:
        """Remove errors older than specified days.

        Args:
            days: Number of days to retain errors.

        """
        count = len(self._errors)
        cutoff = datetime.now(UTC).timestamp() - (days * 86400)

        self._errors = [
            e for e in self._errors if datetime.fromisoformat(e['timestamp']).timestamp() > cutoff
        ]
        self._save_errors()

        if removed := count - len(self._errors):
            self._print.info('Cleared old errors', removed=f'{removed} entries', max_age=f'{days} days')


if TYPE_CHECKING:

    @contextmanager
    def error_tracking(uid: str, *, path: Path | None = None) -> Generator[ErrorTracker]:
        """Context manager to temporarily track errors for a specific email.

        Args:
            uid: Identifier for the email record to track.
            path: Path to the error json log.
                Only required on the first call when specifying a path that differs from the default.

        Yields:
            Self: The ErrorTracker instance with updated uid.

        """
        ...


error_tracking = ErrorTracker.track
