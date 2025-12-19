"""A file handling automation pipeline for internal use."""

__all__ = [
    'ErrorTracker',
    'FolderMatcher',
    'IndexCache',
    'Notifier',
    'StateTracker',
    'build_request',
    'configure',
    'download_documents',
    'error_from_stage',
    'error_tracking',
    'extract_aspnet_form_data',
    'extract_download_info',
    'extract_filename_from_disposition',
    'extract_links_from_response_html',
    'extract_names_from_documents',
    'extract_post_request_url',
    'extract_upload_info',
    'get_doc_store',
    'get_record_processor',
    'make_email_record',
    'new_dropbox_credential',
    'new_msal_credential',
    'parse_credential_json',
    'process_pipeline_result',
    'raise_from_auth_response',
    'stage',
    'status',
    'status_flag_factory',
    'upload_documents',
]

from ._module import *
from .config import *
from .download import *
from .errors import *
from .extract import *
from .monitor import *
from .upload import *
from .util import *
