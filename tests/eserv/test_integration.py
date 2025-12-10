"""Integration tests for eserv upload pipeline workflow.

Tests the complete pipeline workflow combining multiple components.
For individual component tests, see tests/eserv/util/test_*.py

Run with: pytest tests/test_integration.py -v
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rampy import test

from automate import eserv
from automate.eserv.util.target_finder import FolderMatcher

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Any

    from automate.eserv.types import EmailRecord


def workflow_scenario(
    *,
    case_name: str = 'Smith v. Jones',
    has_folder_match: bool = True,
    is_duplicate: bool = False,
) -> dict[str, Any]:
    """Create integration test scenario for full workflow."""
    folders = ['Smith v. Jones', 'Doe Corporation'] if has_folder_match else ['Different Case']

    return {
        'params': [case_name, folders, is_duplicate],
    }


@test.scenarios(**{
    'successful upload workflow': workflow_scenario(
        case_name='Smith v. Jones',
        has_folder_match=True,
    ),
    'manual review workflow': workflow_scenario(
        case_name='Unknown Case',
        has_folder_match=False,
    ),
    'duplicate email workflow': workflow_scenario(
        case_name='Smith v. Jones',
        has_folder_match=True,
        is_duplicate=True,
    ),
})
class TestUploadWorkflow:
    """Test complete upload workflow integrating multiple components."""

    def test(
        self,
        /,
        params: list[Any],
        record: EmailRecord,
        directory: Path,
    ):
        case_name, folders, is_duplicate = params[0]

        temp = directory / 'svc'

        # Initialize components
        state_file = temp / 'email_state.json'
        cache_file = temp / 'dbx_index.json'

        email_state = eserv.state_tracker_factory(state_file)
        index_cache = eserv.index_cache_factory(cache_file, ttl_hours=4)

        # Populate cache with folders
        index_cache.refresh({
            folder: {'id': f'id_{i}', 'name': folder} for i, folder in enumerate(folders)
        })

        # Simulate duplicate email if requested
        if is_duplicate:
            email_state.record(record, error=None)

        # Check if already processed (by UID, not case name)
        if email_state.is_processed(record.uid):
            # Should skip processing for duplicates
            assert is_duplicate
            return

        # Try to match folder
        matcher = FolderMatcher(folder_paths=folders, min_score=50.0)
        match = matcher.find_best_match(case_name)

        if match:
            # Success path - verify match found
            assert match.score >= 50.0
            assert match.folder_path in folders
            # Record successful processing (no error)
            email_state.record(record, error=None)
        else:
            # Manual review path - valid outcome, not an error
            # Verify no match was found
            assert match is None
            # In real workflow, would upload to manual review folder
            # Record as processed (manual review is not an error)
            email_state.record(record, error=None)


def test_config_initialization(tmp_path: Path):
    """Test config initialization with test environment."""
    # Create mock credentials file
    creds_file = tmp_path / 'credentials.json'
    creds_file.write_text(
        """[
        {
            "type": "dropbox",
            "account": "test",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "token_type": "bearer",
            "scope": "files.content.write",
            "access_token": "test_token_long_enough",
            "refresh_token": "refresh_token"
        },
        {
            "type": "microsoft-outlook",
            "account": "test",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "token_type": "bearer",
            "scope": "Mail.Read",
            "access_token": "test_token_long_enough",
            "refresh_token": "refresh_token"
        }
    ]""",
    )

    # Create .env file
    env_file = tmp_path / '.env'
    env_file.write_text(
        f"""CREDENTIALS_PATH={creds_file}
SMTP_SERVER=smtp.example.com
SMTP_PORT=587
SMTP_FROM_ADDR=from@example.com
SMTP_TO_ADDR=to@example.com
SMTP_USERNAME=user@example.com
SMTP_PASSWORD=password
SERVICE_DIR={tmp_path}
MANUAL_REVIEW_FOLDER=/Manual Review
""",
    )

    config = eserv.config_factory(env_file)

    # Verify all components are configured
    assert config.smtp.server
    assert config.credentials['dropbox']
    assert config.credentials['microsoft-outlook']
    assert config.paths.service_dir.exists()
    assert config.cache.ttl_hours > 0
