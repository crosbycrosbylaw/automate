from __future__ import annotations

import os
from contextvars import ContextVar
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from msgraph.generated.models.mail_folder import MailFolder

if TYPE_CHECKING:
    from contextvars import Token

    from msgraph.graph_service_client import GraphServiceClient

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

        config.creds.persist({'msal': ms_cred})

        return ms_cred.get_token()

    else:
        return token


def verify_folder(item: object) -> tuple[str, MailFolder]:
    if not isinstance(item, MailFolder):
        raise TypeError

    if not item.id:
        raise ValueError

    return item.id, item


async def resolve_mail_folders(
    service: GraphServiceClient,
    segments: list[str],
    folders: list[MailFolder],
) -> str:
    s0 = segments.pop(0)
    target_name = ContextVar[str]('target_name', default=s0)

    async def get_child_folders(fid: str):
        request = service.me.mail_folders.by_mail_folder_id(fid).child_folders
        qs = request.ChildFoldersRequestBuilderGetQueryParameters(
            filter=f"startswith(displayName, '{target_name.get()}')"
        )
        rc = request.ChildFoldersRequestBuilderGetRequestConfiguration(query_parameters=qs)
        return await request.get(rc)

    mapping: dict[str, str] = dict.fromkeys(segments, '')

    def advance(id: str) -> Token[str] | None:
        mapping[target_name.get()] = id
        try:
            tkn = target_name.set(segments.pop(0))
        except IndexError:
            return None
        else:
            return tkn

    def get_target_folder_id(f: MailFolder | None) -> str | None:
        if f and f.id and f.display_name == target_name.get():
            return f.id
        return None

    async def recurse_folder_id_resolution(
        folders: list[MailFolder],
    ) -> None:
        for f in folders:
            if curr_id := get_target_folder_id(f):
                if advance(curr_id) is None:
                    break
                if f.child_folders:
                    return await recurse_folder_id_resolution(f.child_folders)
                if (
                    f.child_folder_count
                    and (response := await get_child_folders(curr_id))
                    and response.value
                ):
                    return await recurse_folder_id_resolution(response.value)

        if not all(mapping.values()):
            raise ValueError(target_name.get())

    await recurse_folder_id_resolution(folders)

    return mapping[target_name.get()]
