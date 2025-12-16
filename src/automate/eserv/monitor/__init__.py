"""Monitor module for eserv package."""

__all__ = [
    'build_request',
    'collect_unprocessed_emails',
    'get_record_processor',
    'process_pipeline_result',
    'status_flag_factory',
]

from .collect import collect_unprocessed_emails
from .flags import status_flag_factory
from .processor import get_record_processor
from .request import build_request
from .result import process_pipeline_result
