from __future__ import annotations

__all__ = [
    'DropboxCredential',
    'MSALCredential',
    'get_config',
    'get_creds',
    'get_error_tracker',
    'get_paths',
    'get_state_tracker',
    'stage',
    'status',
]


from functools import partial
from importlib import import_module
from typing import TYPE_CHECKING, Any

from automate.eserv.types.enums import PipelineStage, UploadStatus
from automate.eserv.util.dbx_manager import DropboxManager
from automate.eserv.util.msal_manager import MSALManager
from automate.eserv.util.oauth_credential import OAuthCredential

if TYPE_CHECKING:
    from automate.eserv.types import Config, CredentialsConfig, ErrorTracker, PathsConfig, StateTracker


def _setdefault(name: str, module: str, attr: str, /, *args: ..., **kwds: ...) -> Any:
    if name in globals():
        return globals()[name]

    cls = getattr(import_module(module), attr)
    return globals().setdefault(name, cls(*args, **kwds))


def get_config() -> Config:
    return _setdefault('CONFIG', 'automate.eserv.config.main', 'Config')


def get_paths() -> PathsConfig:
    return get_config().paths


def get_creds() -> CredentialsConfig:
    return get_config().creds


def get_state_tracker() -> StateTracker:
    return _setdefault('STATE_TRACKER', 'automate.eserv.util.state_tracker', 'StateTracker')


def get_error_tracker() -> ErrorTracker:
    return _setdefault('ERROR_TRACKER', 'automate.eserv.util.error_tracker', 'StateTracker')


DropboxCredential = partial(OAuthCredential[DropboxManager], factory=DropboxManager, type='dropbox')
MSALCredential = partial(OAuthCredential[MSALManager], factory=MSALManager, type='msal')


stage = PipelineStage
status = UploadStatus
