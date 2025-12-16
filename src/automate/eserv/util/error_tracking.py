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
from typing import TYPE_CHECKING, Any, NoReturn, Unpack, overload

import orjson
from rampy.util import make_factory

from setup_console import console

if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path

    from automate.eserv.errors.pipeline import PipelineError
    from automate.eserv.types import ErrorDict
    from automate.eserv.types.enums import PipelineStage
    from automate.eserv.types.results import IntermediaryResult


@dataclass
class ErrorTracker:
    """Tracks pipeline errors with stage-based categorization.

    Maintains a JSON log of errors with timestamps, stages, and context.

    Attributes:
        path: Path to error log JSON path.
        _errors: In-memory error log.

    """

    path: Path
    uid: str | None = field(default=None)

    @contextmanager
    def track(self, uid: str) -> Generator[ErrorTracker]:
        """Context manager to temporarily track errors for a specific email.

        Args:
            uid: Identifier for the email record to track.

        Yields:
            Self: The ErrorTracker instance with updated uid.

        """
        yield ErrorTracker(self.path, uid=uid)

    @property
    def prev_error(self) -> ErrorDict | None:
        """Get the most recent error logged for the current UID."""
        for error in reversed(self._errors):
            if error.get('uid') == self.uid:
                return error
        return None

    _errors: list[ErrorDict] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        """Load existing error log from disk."""
        self._load_errors()

    def _load_errors(self) -> None:
        """Load error log from JSON path, creating if missing."""
        cons = console.bind(path=self.path.as_posix())

        if not self.path.exists():
            self._errors = []
            self._save_errors()

            cons.info('Created new error log path')
            return

        try:
            with self.path.open('rb') as f:
                self._errors = orjson.loads(f.read())
        except orjson.JSONDecodeError:
            cons.exception('Failed to load error log')

            self._errors = []
            self._save_errors()
        else:
            cons.info('Loaded error log', error_count=len(self._errors))

    def _save_errors(self) -> None:
        """Save current error log to JSON path."""
        with self.path.open('wb') as f:
            f.write(orjson.dumps(self._errors, option=orjson.OPT_INDENT_2))

    def _save_entry(self, **entry: Unpack[ErrorDict]) -> None:
        self._errors.append(entry)
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
            traceback_str = '\n'.join(traceback.format_tb(err.__traceback__))
            entry['context']['traceback'] = traceback_str

        self._errors.append(entry)
        self._save_errors()

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

        cons = console.bind(uid=self.uid, stage=stage.value)
        cons.warning(f'Pipeline warning: {message}')

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
        cutoff = datetime.now(UTC).timestamp() - (days * 86400)

        self._errors = [
            e for e in self._errors if datetime.fromisoformat(e['timestamp']).timestamp() > cutoff
        ]
        self._save_errors()

        console.bind(cutoff_days=days).info('Cleared old errors')


get_error_tracker = make_factory(ErrorTracker)
