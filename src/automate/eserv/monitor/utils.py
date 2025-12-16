from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from automate.eserv.types import Config


def get_token(config: Config):
    ms_cred = config.creds.msal
    msal_manager = ms_cred.manager
    ms_app = msal_manager.client

    try:
        token = msal_manager.get_token()
    except Exception:
        from setup_console import console

        console.exception('Failed to obtain access token; attempting with username/password')

        result = ms_app.acquire_token_by_username_password(
            username=os.getenv('MSAL_USERNAME', ms_cred.account),
            password=os.environ['MSAL_PASSWORD'],
            scopes=msal_manager.scopes,
        )

        if not isinstance(result, dict) or 'access_token' not in result:
            print(f'{k}={v!s}' for k, v in result.items() if k.startswith('error'))

        expires_at = datetime.now(UTC) + timedelta(seconds=int(result.pop('expires_in', 3600)))
        result['expires_at'] = expires_at
        ms_cred = ms_cred.reconstruct(result)

        config.creds.persist(msal=ms_cred)

        return ms_cred.get_token()

    else:
        return token
