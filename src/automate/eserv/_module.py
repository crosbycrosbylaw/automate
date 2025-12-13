from __future__ import annotations

__all__ = ['new_dropbox_credential', 'new_msal_credential', 'stage', 'status']

from functools import partial

from rampy import make_factory

from automate.eserv.types.enums import PipelineStage, UploadStatus
from automate.eserv.util.dbx_manager import DropboxManager
from automate.eserv.util.msal_manager import MSALManager
from automate.eserv.util.oauth_credential import OAuthCredential

DropboxCredential = partial(OAuthCredential[DropboxManager], factory=DropboxManager, type='dropbox')
MSALCredential = partial(OAuthCredential[MSALManager], factory=MSALManager, type='msal')

new_dropbox_credential = make_factory(DropboxCredential)
new_msal_credential = make_factory(MSALCredential)

stage = PipelineStage
status = UploadStatus
