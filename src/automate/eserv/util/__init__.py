"""Utility modules for document processing pipeline."""

from __future__ import annotations

__all__ = [
    'get_dbx_folder_matcher',
    'get_dbx_index_cache',
    'get_doc_store',
    'get_error_tracker',
    'get_notifier',
    'get_state_tracker',
    'make_email_record',
    'make_oauth_credential',
]

from .doc_store import get_doc_store
from .email_record import make_email_record
from .email_state import get_state_tracker
from .error_tracking import get_error_tracker
from .index_cache import get_dbx_index_cache
from .notifications import get_notifier
from .oauth_manager import make_oauth_credential
from .target_finder import get_dbx_folder_matcher
