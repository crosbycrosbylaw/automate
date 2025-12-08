from __future__ import annotations

import typing

if typing.TYPE_CHECKING:
    __all__ = [
        'CredentialType',
        'CredentialsJSON',
        'ErrorDict',
        'ProcessStatus',
        'ProcessedResultDict',
    ]

    from typing import Any, Literal, NotRequired, ReadOnly, Required, TypedDict, type_check_only

    type CredentialType = Literal['dropbox', 'microsoft-outlook']
    type ProcessStatus = Literal['success', 'error']

    @type_check_only
    class ErrorDict(TypedDict):
        """Typed-dict for error information.

        Attributes:
            category: The error category. Defaults to `unknown` if unspecified.
            message: The error message, if any.

        """

        uid: NotRequired[str | None]
        message: Required[str | None]
        category: Required[str]
        timestamp: Required[str]
        context: NotRequired[dict[str, Any]]

    @type_check_only
    class ProcessedResultDict(TypedDict):
        """Typed-dict for the keyword arguments used in email-state record creation."""

        status: ReadOnly[ProcessStatus]
        error: ReadOnly[ErrorDict | None]

        uid: ReadOnly[str]
        sender: ReadOnly[str]
        subject: ReadOnly[str]

        processed_at: ReadOnly[str]

    @type_check_only
    class CredentialsJSON(TypedDict):
        type: CredentialType
        account: NotRequired[str | None]
        authority: NotRequired[str | None]
        client_id: str
        client_secret: str
        token_type: str
        scope: str
        access_token: str
        refresh_token: str
        issued_at: NotRequired[str | None]
        expires_at: NotRequired[str | None]
        expires_in: NotRequired[int | None]
