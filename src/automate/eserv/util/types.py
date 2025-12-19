__all__ = [
    'BaseCredential',
    'CaseMatch',
    'DropboxCredential',
    'DropboxManager',
    'ErrorTracker',
    'FolderMatcher',
    'IndexCache',
    'MSALCredential',
    'MSALManager',
    'Notifier',
    'OAuthCredential',
    'PartyExtractor',
    'StateTracker',
]


from dataclasses import dataclass

from .dbx_manager import DropboxManager
from .email_state import StateTracker
from .error_tracker import ErrorTracker
from .index_cache import IndexCache
from .msal_manager import MSALManager
from .notifications import Notifier
from .oauth_credential import OAuthCredential
from .target_finder import CaseMatch, FolderMatcher, PartyExtractor

type MSALCredential = OAuthCredential[MSALManager]
type DropboxCredential = OAuthCredential[DropboxManager]


@dataclass
class BaseCredential:
    type: str
    client_id: str
    client_secret: str
    token_type: str
    scope: str
    access_token: str
    refresh_token: str
