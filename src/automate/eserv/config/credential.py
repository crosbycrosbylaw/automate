from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from automate.eserv.util.dbx_manager import DropboxManager
from automate.eserv.util.msal_manager import MSALManager
from automate.eserv.util.oauth_credential import OAuthCredential

if TYPE_CHECKING:
    from automate.eserv.types import DropboxCredential, MSALCredential


dropbox: partial[DropboxCredential] = partial(OAuthCredential[DropboxManager], factory=DropboxManager)
msal: partial[MSALCredential] = partial(OAuthCredential[MSALManager], factory=MSALManager)
