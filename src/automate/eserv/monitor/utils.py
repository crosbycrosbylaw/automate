from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from msgraph.generated.models.mail_folder import MailFolder

if TYPE_CHECKING:
    from .client import GraphClient


def get_token(graph_client: GraphClient):
    ms_cred = graph_client.cred
    ms_app = ms_cred.manager.client

    try:
        token = ms_cred.manager.get_token()
    except Exception:
        from setup_console import console

        console.exception('Failed to obtain access token; attempting with username/password')

        result = ms_app.acquire_token_by_username_password(
            username=os.getenv('MSAL_USERNAME', ms_cred.account),
            password=os.environ['MSAL_PASSWORD'],
            scopes=ms_cred.manager.scopes,
        )

        if not isinstance(result, dict) or 'access_token' not in result:
            print(f'{k}={v!s}' for k, v in result.items() if k.startswith('error'))

        expires_at = datetime.now(UTC) + timedelta(seconds=int(result.pop('expires_in', 3600)))
        result['expires_at'] = expires_at
        ms_cred = ms_cred.reconstruct(result)

        graph_client.config.credentials.persist({'microsoft-outlook': ms_cred})

        return ms_cred.token

    else:
        return token


def verify_folder(item: object) -> tuple[str, MailFolder]:
    if not isinstance(item, MailFolder):
        raise TypeError

    if not item.id:
        raise ValueError

    return item.id, item
