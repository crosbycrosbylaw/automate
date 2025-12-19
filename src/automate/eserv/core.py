# ruff: noqa: BLE001
from __future__ import annotations

import contextvars
from datetime import UTC, datetime
from types import FunctionType
from typing import TYPE_CHECKING, Any

from bs4 import BeautifulSoup
from rampy.util import make_factory

from automate.eserv import (
    ErrorTracker,
    StateTracker,
    configure,
    download_documents,
    extract_upload_info,
    get_record_processor,
    process_pipeline_result,
    stage,
    status,
    upload_documents,
)
from automate.eserv.types import *
from setup_console import console

if TYPE_CHECKING:
    from os import PathLike
    from pathlib import Path

    from automate.eserv.types import BatchResult, EmailRecord, ProcessedResult

from rampy import mode

tracker = contextvars.ContextVar[ErrorTracker]('tracker')


def _confirm[T: FunctionType](func: T, **info: str) -> T:
    if not bool(mode.DEBUG):
        return func

    info['request'] = func.__name__.replace('_', ' ').strip()
    console.info(event := 'Request confirmation', **info)

    if not input('proceed? Y/n: ').lower().startswith('n'):
        info['status'] = 'confirmed'
        console.info(event, **info)
    else:
        info['status'] = 'rejected'
        console.warning(event, **info)

        import sys

        sys.exit()

    return func


def _parse(record: EmailRecord) -> BeautifulSoup | IntermediaryResult:

    context = {'html_body_length': len(record.html_body)}

    try:
        soup = BeautifulSoup(record.html_body, features='html.parser')
    except Exception as e:
        return tracker.get().error(
            event='BeautifulSoup initialization',
            stage=stage.EMAIL_PARSING,
            context={**context, 'exception': str(e)},
        )
    else:
        console.info(event='Parsed HTML body', uid=record.uid)

    return soup


def _download(soup: BeautifulSoup) -> IntermediaryResult | DownloadInfo:

    try:
        download_info = _confirm(download_documents)(soup)
    except PipelineError as e:
        return tracker.get().error(exception=e)
    except Exception as e:
        return tracker.get().error(exception=e, stage=stage.DOCUMENT_DOWNLOAD)
    else:
        console.info(event='Downloaded documents', **download_info.asdict())

    return download_info


def _extract(soup: BeautifulSoup, download_info: DownloadInfo) -> UploadInfo | IntermediaryResult:

    context: ... = {'store_path': download_info.store_path}

    try:
        upload_info = extract_upload_info(soup, download_info.store_path)
    except PipelineError as e:
        return tracker.get().error(
            event='UploadInfo extraction',
            exception=e,
            context=context,
        )
    except Exception as e:
        return tracker.get().error(
            event='UploadInfo extraction',
            exception=e,
            stage=stage.EMAIL_PARSING,
            context=context,
        )
    else:
        context.update(upload_info.asdict())
        console.info(event='Extracted upload info', **context)

    return upload_info


def _upload(config: Config, context: dict[str, Any]) -> IntermediaryResult:
    log = console.bind()

    documents: list[Path] = [*context['store_path'].glob('*.pdf')]
    log.info('Found documents', documents=[f.name for f in documents])

    result = _confirm(upload_documents)(
        documents=documents,
        case_name=context['case_name'],
        lead_name=context['lead_name'],
        config=config,
    )

    log = log.bind(status=result.status.value)
    log.info('Upload complete', uploaded_count=len(result.uploaded_files))

    match result.status:
        case status.SUCCESS:
            log.info(
                event='Upload successful',
                folder=result.folder_path,
                files=len(result.uploaded_files),
            )
        case status.MANUAL_REVIEW:
            context['folder_path'] = result.folder_path
            tracker.get().warning(
                message='No folder match found, sent to manual review',
                stage=stage.FOLDER_MATCHING,
                context=context,
            )
        case status.NO_WORK:
            tracker.get().warning(
                message='No PDF files found after download',
                stage=stage.DOCUMENT_DOWNLOAD,
                context=context,
            )
        case status.ERROR:
            tracker.get().error(
                result=result,
                stage=stage.DROPBOX_UPLOAD,
                context=context,
            )

    return result


class Pipeline:
    """Unified document processing pipeline."""

    stage: stage = PipelineStage.INITIALIZATION

    def __init__(self, dotenv_path: PathLike[str] | None = None) -> None:
        """Initialize pipeline with configuration."""
        self.config = configure(dotenv_path=dotenv_path)
        self.state = StateTracker(self.config.paths.state)
        self.tracker = ErrorTracker(self.config.paths.errors)

    def process(self, record: EmailRecord) -> IntermediaryResult:
        """Process HTML file through complete pipeline.

        Args:
            record (EmailRecord):
                The data for the email to be processed.

        Returns:
            IntermediaryResult with status and details.

        """
        if record.uid and self.state.is_processed(record.uid):
            console.info('Email already processed, skipping')
            return IntermediaryResult(status=status.NO_WORK)

        context: dict[str, Any] = {'uid': record.uid}

        with self.tracker.track(record.uid) as t:
            tracker.set(t)

            context['started_at'] = datetime.now(UTC).isoformat()

            self.stage = stage.EMAIL_PARSING

            soup = _parse(record)
            if isinstance(soup, IntermediaryResult):
                return soup

            self.stage = stage.DOCUMENT_DOWNLOAD

            info = _download(soup)
            if isinstance(info, IntermediaryResult):
                return info

            context['source'], context['lead_name'], context['store_path'] = info.unpack()

            self.stage = stage.EMAIL_PARSING

            meta = _extract(soup, info)
            if isinstance(meta, IntermediaryResult):
                return meta

            context['doc_count'], context['case_name'] = meta.unpack()

            self.stage = stage.DROPBOX_UPLOAD

            return _upload(self.config, context)

    async def monitor(self) -> BatchResult:
        """Monitor email inbox and process new messages.

        Args:
            num_days: Process emails from past N days.

        Returns:
            BatchResult with summary and per-email results.

        """
        self.tracker.clear_old_errors(days=30)

        batch_result = await get_record_processor(self).process_batch()
        batch_errors = [e for x in batch_result.summarize().get('error', []) if (e := x.get('error'))]

        for err in batch_errors:
            console.error(str(err.pop('message')), **err.pop('context', {}))

        console.info(
            event='Batch complete',
            failed=batch_result.failed,
            success=batch_result.succeeded,
            total=batch_result.total,
        )

        return batch_result

    def execute(self, rec: EmailRecord) -> ProcessedResult:
        """Execute pipeline for a single email record.

        Args:
            rec (EmailRecord):
                The email record to process.

        Returns:
            ProcessedResult with processing status and error information if applicable.

        """
        try:
            if self.process(rec).status != status.ERROR:
                return process_pipeline_result(record=rec)
        except PipelineError as exc:
            return process_pipeline_result(record=rec, error=exc.entry())
        except Exception as exc:
            error = PipelineError.from_exc(exc, uid=rec.uid, stage=self.stage)
        else:
            error = self.tracker.prev_error

        return process_pipeline_result(record=rec, error=error)


eserv_pipeline = make_factory(Pipeline)
