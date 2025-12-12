__all__ = [
    'CaseMatch',
    'DropboxCredential',
    'DropboxManager',
    'EmailState',
    'ErrorTracker',
    'FolderMatcher',
    'IndexCache',
    'MSALCredential',
    'MSALManager',
    'Notifier',
    'OAuthCredential',
    'PartyExtractor',
]


from .dbx_manager import DropboxManager
from .email_state import EmailState
from .error_tracking import ErrorTracker
from .index_cache import IndexCache
from .msal_manager import MSALManager
from .notifications import Notifier
from .oauth_manager import OAuthCredential
from .target_finder import CaseMatch, FolderMatcher, PartyExtractor

type MSALCredential = OAuthCredential[MSALManager]
type DropboxCredential = OAuthCredential[DropboxManager]
