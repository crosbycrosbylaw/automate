"""A file handling automation pipeline for internal use."""

__all__ = [
    'configure',
    'download_documents',
    'error_factory',
    'extract_aspnet_form_data',
    'extract_download_info',
    'extract_filename_from_disposition',
    'extract_links_from_response_html',
    'extract_names_from_documents',
    'extract_post_request_url',
    'extract_upload_info',
    'get_dbx_folder_matcher',
    'get_dbx_index_cache',
    'get_doc_store',
    'get_error_tracker',
    'get_notifier',
    'get_record_processor',
    'get_state_tracker',
    'make_email_record',
    'make_graph_client',
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
