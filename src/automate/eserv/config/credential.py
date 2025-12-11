from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from automate.eserv.util.dbx_manager import DropboxManager
from automate.eserv.util.msal_manager import msauth_manager_factory
from automate.eserv.util.oauth_manager import credential_factory

if TYPE_CHECKING:
    from automate.eserv.types import DropboxCredential, MSALCredential


dropbox: partial[DropboxCredential] = partial(credential_factory, factory=DropboxManager)
msal: partial[MSALCredential] = partial(credential_factory, factory=msauth_manager_factory)
