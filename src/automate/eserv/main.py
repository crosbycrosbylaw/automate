"""Provides a high-level interface for automating file-stamped document uploads."""

# ruff: noqa: RUF013
# pyright: reportArgumentType=false


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
    from typing import TYPE_CHECKING

    from automate.eserv.core import setup_eserv
    from automate.eserv.util.email_record import make_email_record

    if TYPE_CHECKING:
        from typing import Any

    dotenv_path = None

    if dotenv:
        from pathlib import Path

        dotenv_path = Path(dotenv)

    kwds: dict[str, Any] = {
        'uid': uid,
        'subject': subject,
        'sender': sender,
        'received_at': None,
    }

    if received:
        from datetime import datetime

        kwds['received_at'] = datetime.fromisoformat(received)

    setup_eserv(dotenv_path).execute(make_email_record(body, **kwds))


async def monitor(dotenv: str = None, lookback: int = 1):
    """Monitor email inbox and process new messages.

    Args:
        dotenv (str):
            Path to a file containing the necessary environment variables.
        lookback (int):
            Process emails from past N days.

    Returns:
        BatchResult with summary and per-email results.

    """
    from automate.eserv.core import setup_eserv

    dotenv_path = None

    if dotenv:
        from pathlib import Path

        dotenv_path = Path(dotenv)

    await setup_eserv(dotenv_path).monitor(num_days=lookback)


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
    from automate.eserv.core import setup_eserv

    dotenv_path = None

    if dotenv:
        from pathlib import Path

        dotenv_path = Path(dotenv)

    eserv = setup_eserv(dotenv_path)

    for key in 'msal', 'dropbox':
        if not query or query in key:
            eserv.config.creds[key].print(insecure=insecure, select=properties)
