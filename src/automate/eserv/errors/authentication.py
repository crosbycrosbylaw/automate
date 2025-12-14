from __future__ import annotations

from typing import Any, NoReturn


class AuthError(Exception):
    def __init__(self, data: dict[str, str], *args: object) -> None:
        code = data.get('error', 'unknown')
        desc = data.get('error_description', 'Authentication failed')
        super().__init__(f'\n\n{code=}\n{desc=}', *args)


def raise_from_auth_response(data: dict[str, Any]) -> NoReturn:
    raise AuthError(data)
