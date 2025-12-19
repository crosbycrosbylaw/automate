"""Test suite for util/error_tracking.py pipeline error logging."""

from __future__ import annotations

from typing import TYPE_CHECKING, Unpack

from rampy import test

from automate.eserv import stage
from automate.eserv.util.email_record import make_email_record
from automate.eserv.util.error_tracker import ErrorTracker, error_tracking

if TYPE_CHECKING:
    from pathlib import Path
    from typing import TypedDict

    from automate.eserv.types import EmailRecord

    class Scenario(TypedDict):
        record: EmailRecord
        stage: stage
        error_message: str
        test_persistence: bool
        test_retrieval: bool


def scenario(**kwds: Unpack[Scenario]) -> Scenario:
    """Create test scenario for ErrorTracker."""
    kwds.setdefault('stage', stage.EMAIL_PARSING)
    kwds.setdefault('error_message', 'test error')
    kwds.setdefault('test_persistence', False)
    kwds.setdefault('test_retrieval', False)
    return kwds


def _make_record(uid: str, subject: str) -> EmailRecord:
    """Create test EmailRecord."""
    from datetime import UTC, datetime

    return make_email_record(
        uid=uid,
        sender='court@example.com',
        subject=subject,
        received_at=datetime.now(UTC),
        body='<html>test</html>',
    )


@test.scenarios(
    basic_logging=scenario(
        record=_make_record('test-basic-123', 'Basic Test'),
        stage=stage.EMAIL_PARSING,
        error_message='Test parse error',
        test_persistence=False,
        test_retrieval=False,
    ),
    persistence_across_instances=scenario(
        record=_make_record('test-persist-456', 'Persistence Test'),
        stage=stage.DOCUMENT_DOWNLOAD,
        error_message='Test download error',
        test_persistence=True,
        test_retrieval=False,
    ),
    error_retrieval_by_stage=scenario(
        record=_make_record('test-retrieval-789', 'Retrieval Test'),
        stage=stage.DROPBOX_UPLOAD,
        error_message='Test upload error',
        test_persistence=False,
        test_retrieval=True,
    ),
)
class TestErrorTracker:
    def test(
        self,
        /,
        record: EmailRecord,
        stage: stage,
        error_message: str,
        test_persistence: bool,
        test_retrieval: bool,
        directory: Path,
    ):
        ErrorTracker.set(path=(log_file := directory / 'errors.json'))

        if test_persistence:
            # Test persistence across instances
            with error_tracking(record.uid) as tracker1:
                tracker1.error(error_message, stage=stage)

            errors = ErrorTracker(log_file).get_errors_for_email(record.uid)

            assert len(errors) == 1
            assert errors[0]['message'] == error_message

            with ErrorTracker(log_file).track(record.uid) as tracker3:
                tracker3.error(error_message, stage=stage)

            errors = ErrorTracker(log_file).get_errors_for_email(record.uid)

            assert len(errors) > 1
            assert errors[1]['message'] == error_message

        elif test_retrieval:
            expected_count = 2

            # Test error retrieval by email and stage
            with ErrorTracker(log_file).track(record.uid) as tracker:
                tracker.error(error_message, stage=stage)
                tracker.error('parse error', stage=stage.EMAIL_PARSING)

            # Retrieve by email
            email_errors = tracker.get_errors_for_email(record.uid)
            assert len(email_errors) == expected_count

            # Retrieve by stage
            stage_errors = tracker.get_errors_by_stage(stage)
            assert len(stage_errors) >= 1

        else:
            # Test basic logging
            with error_tracking(record.uid) as tracker:
                tracker.error(error_message, stage=stage, context={'test': 'value'})

            errors = tracker.get_errors_for_email(record.uid)
            assert len(errors) == 1
            assert errors[0]['category'] == stage.value
            assert errors[0]['message'] == error_message
