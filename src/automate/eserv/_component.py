"""Provides a high-level interface for automating file-stamped document uploads."""

__all__ = ['component']

# ruff: noqa: RUF013
# pyright: reportArgumentType=false

import contextvars
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

from automate.eserv.core import eserv_pipeline
from automate.eserv.util.email_record import make_email_record

if TYPE_CHECKING:
    from types import FunctionType
    from typing import Any

dotenv_path = contextvars.ContextVar[str | None]('dotenv', default=None)


def eserv():
    return eserv_pipeline(None if not (path := dotenv_path.get()) else Path(path))


def process(
    body,
    dotenv: str = None,
    uid: str = None,
    received: str = None,
    subject: str = '',
    sender: str = 'unknown',
):
    """Execute pipeline for a single email record.

    Args:
        body (str):
            The body of an email record to process.

    Kwargs:
        dotenv (str | None):
            Path to a file containing the necessary environment variables.
        uid (str | None):
            Unique identifier for the email record.
        received (datetime | None):
            Timestamp when the email was received.
        subject (str):
            The subject line of the email.
        sender (str):
            The sender's email address or name.

    Returns:
        ProcessedResult with processing status and error information if applicable.

    """
    dotenv_path.set(dotenv)

    kwds: dict[str, Any] = {
        'uid': uid,
        'subject': subject,
        'sender': sender,
        'received_at': None,
    }

    if received:
        kwds['received_at'] = datetime.fromisoformat(received)

    eserv().execute(make_email_record(body, **kwds))


def monitor(dotenv: str = None, lookback: int = 1):
    """Monitor email inbox and process new messages.

    Args:
        dotenv (str):
            Path to a file containing the necessary environment variables.
        lookback (int):
            Process emails from past N days.

    Returns:
        BatchResult with summary and per-email results.

    """
    import asyncio

    dotenv_path.set(dotenv)
    app = eserv()
    object.__setattr__(app.config, 'monitor_num_days', lookback)
    asyncio.run(app.monitor())


def verify(
    query: str = None,
    dotenv: str = None,
    properties: list[str] = None,
    insecure: bool = False,
):
    """Verify the `Dropbox` and/or `Microsoft Outlook` OAuth2 credential data.

    Args:
        dotenv (str | None):
            Path to a file containing the necessary environment variables.
        query (str | None):
            A string to filter included credentials by.
        properties (list[str] | None):
            A list of properties to include in the output.
        insecure (bool):
            Whether to include sensitive information in the console output. \
                Does nothing if `properties` are provided.

    """
    dotenv_path.set(dotenv)
    for key in 'msal', 'dropbox':
        if not query or query in key:
            eserv().config.creds[key].print(insecure=insecure, select=properties)


component: Final[dict[str, FunctionType]] = {'process': process, 'monitor': monitor, 'verify': verify}
