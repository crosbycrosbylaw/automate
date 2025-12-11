from __future__ import annotations

__all__ = ['make_dbx_cred', 'make_ms_cred', 'stage', 'status']

from functools import partial

from rampy import create_field_factory

from automate.eserv.types.enums import PipelineStage, UploadStatus
from automate.eserv.util.dbx_manager import DropboxManager
from automate.eserv.util.msal_manager import MSALManager
from automate.eserv.util.oauth_manager import OAuthCredential

DropboxCredential = partial(OAuthCredential[DropboxManager], factory=DropboxManager, type='dropbox')
MSALCredential = partial(OAuthCredential[MSALManager], factory=MSALManager, type='msal')

make_dbx_cred = create_field_factory(DropboxCredential)
make_ms_cred = create_field_factory(MSALCredential)

stage = PipelineStage
status = UploadStatus
