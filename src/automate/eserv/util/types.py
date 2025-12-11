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
    'NotificationConfig',
    'Notifier',
    'OAuthCredential',
    'PartyExtractor',
]


from .dbx_manager import DropboxManager
from .email_state import EmailState
from .error_tracking import ErrorTracker
from .index_cache import IndexCache
from .msal_manager import MSALManager
from .notifications import NotificationConfig, Notifier
from .oauth_manager import OAuthCredential
from .target_finder import CaseMatch, FolderMatcher, PartyExtractor

type MSALCredential = OAuthCredential[MSALManager]
type DropboxCredential = OAuthCredential[DropboxManager]
