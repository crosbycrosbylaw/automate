from __future__ import annotations

from typing import TYPE_CHECKING

from bs4 import BeautifulSoup
from rampy import test

from automate.eserv.extract import extract_upload_info
from tests.eserv.lib import create_sample_email

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Any


def scenario(
    count: int,
    cname: str = (CASE_NAME := 'DAILEY EMILY vs. DAILEY DERRICK'),
    /,
    **expect: object,
) -> dict[str, Any]:
    expect.setdefault('case_name', CASE_NAME)
    expect.setdefault('doc_count', count)
    return {
        'soup': BeautifulSoup(create_sample_email(case_name=cname), features='html.parser'),
        'store_name': f'test_store_{count}',
        'documents': [f'doc_{i}.pdf' for i in range(count)],
        'expect': expect,
    }


@test.scenarios(**{
    'valid case with docs': scenario(3),
    'empty document store': scenario(0),
    'confidential case': scenario(1, 'CONFIDENTIAL', case_name=None),
})
class TestExtractUploadInfo:
    """Test extract_upload_info function.

    Validates:
    - Document counting from store directory
    - Case name extraction from HTML
    - Filtering of confidential cases
    """

    def test(
        self,
        /,
        soup: BeautifulSoup,
        store_name: Path,
        documents: list[str],
        expect: dict[str, Any],
        directory: Path,
    ) -> None:

        store_path = directory / store_name
        store_path.mkdir(parents=True, exist_ok=True)

        for fname in documents:
            doc_path = store_path / fname
            doc_path.touch(exist_ok=True)

        result = extract_upload_info(soup, store_path)

        expect_doc_count = expect['doc_count']
        assert result.doc_count == expect_doc_count, \
            f'Count mismatch: {result.doc_count} != {expect_doc_count}'  # fmt: skip

        expect_case_name = expect['case_name']
        assert result.case_name == expect_case_name, \
            f"Case name mismatch: {result.case_name} != {expect_case_name}"  # fmt: skip
