from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from automate.eserv.types import Config


def get_token_with_login(username: str = '', password: str = ''):
    from automate.eserv.config.main import configure
    from setup_console import console

    config = configure()
    ms_app = (ms_manager := (ms_cred := config.creds.msal).manager).client

    if 'MSAL_USERNAME' not in os.environ:
        os.environ['MSAL_USERNAME'] = username or input('username: ')
    if 'MSAL_PASSWORD' not in os.environ:
        os.environ['MSAL_PASSWORD'] = password or input('password: ')

    if response := ms_app.acquire_token_by_username_password(
        username=os.getenv('MSAL_USERNAME', ms_cred.account),
        password=os.environ['MSAL_PASSWORD'],
        scopes=ms_manager.scopes,
    ):
        ms_cred = ms_cred.reconstruct(response)
        config.creds.persist(msal=ms_cred)

        console.info(
            event='Token acquired',
            expiration=ms_cred.expiration.strftime('%d/%m/%Y, %H:%M:%S'),
        )

    else:
        console.error(
            event='Failed to acquire token',
            response=response,
            username=os.environ['MSAL_USERNAME'],
            password=os.environ['MSAL_PASSWORD'],
        )


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
