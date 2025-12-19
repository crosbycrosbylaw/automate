from __future__ import annotations

__all__ = ['SAMPLE_EMAIL', 'create_sample_email', 'sample_path']

import typing
from pathlib import Path
from typing import Any, TypedDict

if typing.TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from typing import Literal

    type _FormatKey = Literal[
        'court',
        'case_name',
        'case_number',
        'filing_attorney',
        'filename',
        'download_link',
        'page_count',
    ]

    class TemplateFormatMapping(TypedDict, total=False):
        court: str
        case_number: str
        case_name: str
        filing_attorney: str
        filename: str
        page_count: int | str
        download_link: str


_FMT_TEMPLATE = """<!DOCTYPE html>
    <html>
      <head>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
        <style>
        <!--
        body
            {{font-family:Arial,Helvetica,sans-serif;
            font-size:12pt}}
        .header
            {{padding:10 auto;
            top:0;
            display:block}}
        .content
            {{padding:10px 0;
            margin:0 auto;
            height:auto}}
        h1
            {{color:#12428A;
            padding:0 0;
            margin:0 0}}
        th
            {{background-color:#12428A;
            color:#FFFFFF;
            font-weight:bold}}
        .footer
            {{color:darkslategrey;
            height:100px;
            bottom:0;
            left:0;
            width:100%}}
        -->
        </style>
      </head>
      <body>
        <div class="header">
          <table width="100%">
            <tbody>
              <tr>
                <td width="50%" align="left">
                  <img src="https://illinois.tylertech.cloud/ClientBin/logos/Illogo.png" alt="EFile State Logo">
                </td>
                <td width="50%" align="right">
                  <h1>Filing Accepted</h1>
                  <p style="margin:0px">Envelope Number: 35289318<br>Case Number: 2025DC000131<br>Case Name: {case_name}</p>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="content">
          <p>
            The filing below was reviewed and has been accepted by the clerk's office. You may access the file stamped copy of the document filed by clicking on the below link.
          </p>
          <table width="100%" border="1" cellpadding="3" cellspacing="0">
            <tbody>
              <tr>
                <th colspan="2">Filing Details</th>
              </tr>
              <tr>
                <td width="30%"><b>Court</b></td>
                <td>{court}</td>
              </tr>
              <tr>
                <td width="30%"><b>Case Number</b></td>
                <td>{case_number}</td>
              </tr>
              <tr>
                <td width="30%"><b>Case Name</b></td>
                <td>{case_name}</td>
              </tr>
              <tr>
                <td width="30%"><b>Date/Time Submitted</b></td>
                <td>11/10/2025 11:54 AM CST</td>
              </tr>
              <tr>
                <td width="30%"><b>Date/Time Accepted</b></td>
                <td>11/10/2025 12:08 PM CST</td>
              </tr>
              <tr>
                <td width="30%"><b>Accepted Comments</b></td>
                <td></td>
              </tr>
              <tr>
                <td width="30%"><b>Filing Type</b></td>
                <td>EFile</td>
              </tr>
              <tr>
                <td width="30%"><b>Filing Description</b></td>
                <td></td>
              </tr>
              <tr>
                <td width="30%"><b>Filing Code</b></td>
                <td>Appearance (No Fee: fee previously paid on behalf of party)</td>
              </tr>
              <tr>
                <td width="30%"><b>Filed By</b></td>
                <td>{filing_attorney}</td>
              </tr>
              <tr>
                <td width="30%"><b>Filing Attorney</b></td>
                <td>{filing_attorney}</td>
              </tr>
            </tbody>
          </table>
            <br>
          <table width="100%" border="1" cellpadding="3" cellspacing="0">
            <tbody>
              <tr>
                <th colspan="2">Document Details</th>
              </tr>
              <tr>
                <td width="30%"><b>Lead Document</b></td>
                <td>{filename}</td>
              </tr>
              <tr>
                <td width="30%"><b>Lead Document Page Count</b></td>
                <td>{page_count}</td>
              </tr>
              <tr>
                <td width="30%"><b>File Stamped Copy</b></td>
                <td>
                  <a href="{download_link}">Download Document</a>
                </td>
                </tr>
                <tr>
                  <td colspan="2" align="center">
                    This link is active for 548 days. To access this document, you will be required to enter your email address. Click <a href="https://content.tylerhost.net/docs/Filer_Information.pdf" target="_blank" rel="noopener">here</a> for more information.
                  </td>
                </tr>
              </tbody>
            </table>
            <p>If the link above is not accessible, copy this URL into your browser's address bar to view the document: <br>{download_link}</p>
            <p>If you are not represented by a lawyer, we want to improve your e-filing experience. Please <a href="https://docs.google.com/forms/d/e/1FAIpQLScTqDkGzBQm25gaSWw8pPmfInrdkfkXBuAIS1G2Wi-MM4pqWA/viewform">click here</a> to fill out a short survey.</p>
            <p><b>Please Note:</b> If you have not already done so, be sure to add yourself as a service contact on this case in order to receive eService.</p>
          </div>
          <div class="footer">
            <p width="100" align="center">For technical assistance, contact your service provider<br></p>
            <div id="contactname">Odyssey File &amp; Serve</div>
              <br>
            <div id="contactphone">(800) 297-5377</div>
              <br>
            <p>Please do not reply to this email. It was automatically generated.</p>
          </div>
        </body>
      </html>"""


_FMT_KEYS: set[_FormatKey] = {
    'court',
    'case_name',
    'case_number',
    'filing_attorney',
    'filename',
    'download_link',
    'page_count',
}

_FMT_DEFAULT: TemplateFormatMapping = {
    'court': 'DeKalb County',
    'case_name': 'DAILEY EMILY vs. DAILEY DERRICK',
    'case_number': '2025DC000131',
    'filing_attorney': 'Mason Crosby',
    'filename': 'Entry of Appearance 00072025.pdf',
    'download_link': 'https://illinois.tylertech.cloud/ViewDocuments.aspx?FID=7ff2fb72-7baa-4770-8a7c-70c1dd1cd3d7',
    'page_count': 1,
}


def create_sample_email[T: TemplateFormatMapping | Mapping[str, str] = TemplateFormatMapping](
    mapping: T | None = None,
    *,
    include: Sequence[_FormatKey] = (*_FMT_KEYS,),
    exclude: Sequence[_FormatKey] = (),
    **kwds: str,
) -> str:
    """Return sample html content formatted with the provided arguments."""
    fmt_dict: dict[str, Any] = {}

    for k in set(include).difference(exclude):
        if value := _FMT_DEFAULT.get(k):
            fmt_dict[k] = value

    fmt_dict.update(**(mapping or {}), **kwds)

    return _FMT_TEMPLATE.format_map(fmt_dict)


SAMPLE_EMAIL = create_sample_email()


def sample_path(mock: bool = False):
    return Path(__file__).parent.joinpath(f'{"sample" if not mock else "mock"}.html').resolve(strict=True)
