from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import cached_property
from typing import TYPE_CHECKING

from msgraph.graph_service_client import GraphServiceClient
from rampy import make_factory
from requests import HTTPError

from setup_console import console

from .flags import status_flag_factory

if TYPE_CHECKING:
    from msgraph.generated.models.message import Message

    from automate.eserv.core import Pipeline
    from automate.eserv.types import BatchResult, ProcessedResult


@dataclass
class EmailProcessor:
    """Orchestrates email monitoring and processing."""

    pipe: Pipeline
    max_age: int = field(init=False, default=1, doc='maximum age of records to include, in days')

    @cached_property
    def graph(self) -> GraphServiceClient:
        return GraphServiceClient(self.pipe.config.creds.msal)

    def __post_init__(self) -> None:
        self.max_age = self.pipe.config.monitor_num_days

    async def process_batch(self) -> BatchResult:
        """Process all unprocessed emails from monitoring folder."""
        from automate.eserv.monitor.collect import collect_unprocessed_emails
        from automate.eserv.types import BatchResult

        results: list[ProcessedResult] = []

        try:
            batch = await collect_unprocessed_emails(
                app=self.graph,
                received_after=datetime.now(UTC) - timedelta(days=self.max_age),
                path_segments=self.pipe.config.monitor_mail_folder_path,
                processed_uids=self.pipe.state.processed,
            )

        except HTTPError as e:
            from automate.eserv import error_from_stage, process_pipeline_result, stage

            return BatchResult([
                process_pipeline_result(
                    record=None,
                    error=error_from_stage(
                        stage=stage.INITIALIZATION,
                        message='Failed to fetch unprocessed emails.',
                        context={'http_error': str(e), 'lookback': self.max_age},
                    ),
                )
            ])

        for record in batch:
            results.append(result := self.pipe.execute(record))
            try:
                body = self._result_to_patch_body(result)
                await self.graph.me.messages.by_message_id(record.uid).patch(body)
            except Exception:
                console.exception('Batch processing')

            self.pipe.state.record(result)

        return BatchResult(results=results)

    @staticmethod
    def _result_to_patch_body(result: ProcessedResult) -> Message:
        """Convert result to MAPI flag."""
        from msgraph.generated.models.message import Message
        from msgraph.generated.models.single_value_legacy_extended_property import (
            SingleValueLegacyExtendedProperty,
        )

        if not result.error:
            flag = status_flag_factory(success=True)
        else:
            flag = status_flag_factory(result.error)

        return Message(single_value_extended_properties=[SingleValueLegacyExtendedProperty(**flag)])


get_record_processor = make_factory(EmailProcessor)
