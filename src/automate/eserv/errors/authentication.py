from __future__ import annotations

from typing import Any, NoReturn


class AuthError(Exception):
    __slots__ = ()

    code: str
    desc: str

    def __init__(self, data: dict[str, str] | None = None, *args: object) -> None:
        data = data or {}
        self.code = data.get('error', 'unknown')
        self.desc = data.get('error_description', 'no information')
        super().__init__(*args)

    def __str__(self):
        return f'{self.code}: {self.desc}' + super().__str__()


def raise_from_auth_response(data: dict[str, Any]) -> NoReturn:
    raise AuthError(data)
