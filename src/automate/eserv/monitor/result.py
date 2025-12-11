from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, overload

if TYPE_CHECKING:
    from automate.eserv.types import (
        EmailInfo,
        ErrorDict,
        PipelineError,
        ProcessedResult,
        ProcessedResultDict,
    )


@overload
def process_pipeline_result(
    *,
    record: EmailInfo | None,
    error: PipelineError | ErrorDict | None = None,
) -> ProcessedResult: ...
@overload
def process_pipeline_result(entry: ProcessedResultDict, /) -> ProcessedResult: ...
def process_pipeline_result(
    entry: ProcessedResultDict | None = None,
    *,
    record: EmailInfo | None = None,
    error: PipelineError | ErrorDict | None = None,
) -> ProcessedResult:
    """Create a ProcessedResult instance."""
    from automate.eserv.types import ProcessedResult
    from automate.eserv.util.email_record import make_email_record

    if entry is not None:
        return ProcessedResult(
            record=make_email_record(
                uid=entry['uid'],
                sender=entry['sender'],
                subject=entry['subject'],
            ),
            error=entry['error'],
            processed_at=datetime.fromisoformat(entry['processed_at']),
        )

    if isinstance(error, Exception):
        error = error.entry()

    return ProcessedResult(record=record, error=error)
