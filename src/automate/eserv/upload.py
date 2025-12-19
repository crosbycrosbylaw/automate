"""Document upload orchestration with Dropbox integration.

Handles the complete upload workflow:
1. Load/refresh Dropbox folder index
2. Match case name to folder using fuzzy matching
3. Upload document(s) to matched folder or manual review folder
4. Track state and errors

Classes:
    DocumentUploader: Main upload orchestration class.
"""

# pyright: reportUnknownMemberType=false
# pyright: reportAttributeAccessIssue=false

from __future__ import annotations

import inspect

__all__ = ['upload_documents']


from typing import TYPE_CHECKING

from dropbox.exceptions import ApiError

import setup_console
from automate.eserv._module import stage, status
from automate.eserv.types.results import IntermediaryResult
from automate.eserv.util import FolderMatcher, IndexCache, Notifier

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from automate.eserv.types import Config


def upload_documents(
    documents: Sequence[Path],
    case_name: str,
    lead_name: str,
    *,
    config: Config,
    min_score: int = 70,
) -> IntermediaryResult:
    """Process and upload document(s) to Dropbox.

    Args:
        documents (Sequence[Path]): A sequence of local PDF file paths to upload.
        case_name (str | None): The case name extracted from the email, if it exists.
        lead_name (str | None):  The filename for the lead document in the set, if it exists.
        config (Config): The pipeline configuration. Used to initialize the uploader.
        min_score (int): The minimum score of a match for it to be used as the target.

    Returns:
        Upload result with status and details.

    """
    console = setup_console.console.bind(event='Upload documents', case_name=case_name, lead_name=lead_name)

    if not documents:
        console.warning(cause='There are no documents to upload.')
        return IntermediaryResult(status=status.NO_WORK)

    dbx = config.creds.dropbox.manager
    cache = IndexCache(config.cache.index_file, ttl_hours=4)

    if cache.is_stale():
        try:
            cache.refresh(index := dbx.index())
            console.info('Dropbox index refreshed', folder_count=len(index))
        except ApiError as e:
            return IntermediaryResult(status.ERROR, error=f'Failed to refresh Dropbox index: {e!s}')

    notifier = Notifier(config.smtp())

    if (
        match := case_name.capitalize() != 'Unknown'
        and (matcher := FolderMatcher(cache.get_all_paths(), min_score))
        and matcher.find_best_match(case_name)
    ):
        target = match.folder_path
        state = status.SUCCESS
    else:
        target = config.paths.manual_review_folder
        state = status.MANUAL_REVIEW

    bound_args = inspect.signature(IntermediaryResult).bind_partial(
        status=state,
        folder_path=target,
        uploaded_files=dbx.uploaded,
    )

    try:
        name = lead_name.removesuffix('.pdf')
        count = len(documents) - 1
        for i, path in enumerate(documents):
            suffix = '.pdf' if not len(documents) <= 1 else f'_{i + 1}.pdf'
            dbx.upload(path, dest := f'{target}/{name}{suffix}')

            console.info(destination=dest, complete=i, remaining=count - i)

        if state == status.SUCCESS:
            notifier.notify_upload_success(case_name, target, len(dbx.uploaded))

        else:
            context = {'uploaded_to': target}
            notifier.notify_manual_review(case_name, 'No matching folder found', context)

        bound_args.kwargs.update(match=match or None)

    except Exception as e:  # noqa: BLE001
        notifier.notify_error(case_name, stage.DROPBOX_UPLOAD.value, str(e))

        bound_args.kwargs.update(status=status.ERROR, error=str(e))

    return IntermediaryResult(*bound_args.args, **bound_args.kwargs)
