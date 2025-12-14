from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from rampy import make_factory
from requests import HTTPError

from setup_console import console

from .flags import status_flag_factory

if TYPE_CHECKING:
    from automate.eserv.core import Pipeline
    from automate.eserv.types import (
        BatchResult,
        EmailState,
        GraphClient,
        ProcessedResult,
        StatusFlag,
    )


@dataclass
class EmailProcessor:
    """Orchestrates email monitoring and processing."""

    pipeline: Pipeline
    client: GraphClient = field(init=False)
    state: EmailState = field(init=False)

    def __post_init__(self) -> None:
        """Initialize state from pipeline after dataclass initialization."""
        from .client import GraphClient

        self.client = GraphClient(self.pipeline.config)
        self.state = self.pipeline.state

    async def process_batch(self, num_days: int) -> BatchResult:
        """Process all unprocessed emails from monitoring folder."""
        from automate.eserv.types import BatchResult

        try:
            batch = await self.client.fetch_unprocessed_emails(self.state.processed)
        except HTTPError as e:
            from automate.eserv import error_factory, process_pipeline_result, stage

            processed_result = process_pipeline_result(
                record=None,
                error=error_factory(
                    stage=stage.INITIALIZATION,
                    message='Failed to fetch unprocessed emails.',
                    context={'http_error': str(e), 'lookback': num_days},
                ),
            )

            return BatchResult([processed_result])

        results: list[ProcessedResult] = []

        for record in batch:
            result = self.pipeline.execute(record)
            results.append(result)

            # Apply flag (auto-retry on transient failure)
            try:
                flag = self._result_to_flag(result)
                await self.client.apply_flag(record.uid, flag)
            except Exception:
                console.exception('Batch processing')

            self.state.record(result)

        return BatchResult(results=results)

    @staticmethod
    def _result_to_flag(result: ProcessedResult) -> StatusFlag:
        """Convert result to MAPI flag."""
        if not result.error:
            return status_flag_factory(success=True)

        return status_flag_factory(result.error)


get_record_processor = make_factory(EmailProcessor)
