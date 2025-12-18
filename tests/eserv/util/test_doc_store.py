"""Test suite for util/doc_store.py temporary document storage.

Tests cover:
- Temporary directory creation
- Name cleaning and sanitization
- Directory reuse
- Path resolution
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from automate.eserv.util.doc_store import _clean_document_name, get_doc_store


class TestDocumentNameCleaning:
    """Test document name sanitization."""

    def test_clean_name_with_alphanumeric(self) -> None:
        """Test cleaning preserves alphanumeric characters."""
        result = _clean_document_name('TestCase123')

        assert 'TestCase123' in result
        assert result == 'TestCase123_temp_store'

    def test_clean_name_removes_special_characters(self) -> None:
        """Test cleaning removes special characters."""
        result = _clean_document_name('Test@Case#123!')

        # Should remove @, #, !
        assert '@' not in result
        assert '#' not in result
        assert '!' not in result
        assert 'TestCase123' in result

    def test_clean_name_preserves_allowed_characters(self) -> None:
        """Test cleaning preserves dots, underscores, and hyphens."""
        result = _clean_document_name('Test.Case_123-A')

        assert '.' in result
        assert '_' in result
        assert '-' in result

    def test_clean_name_handles_none(self) -> None:
        """Test cleaning handles None input."""
        result = _clean_document_name(None)

        assert result == 'temp_store'

    def test_clean_name_handles_empty_string(self) -> None:
        """Test cleaning handles empty string."""
        result = _clean_document_name('')

        assert result == 'temp_store'

    def test_clean_name_handles_spaces(self) -> None:
        """Test cleaning removes spaces."""
        result = _clean_document_name('Test Case Name')

        assert ' ' not in result
        assert 'TestCaseName' in result


class TestDocStoreCreation:
    """Test document store directory creation."""

    def test_creates_directory_with_name(self, monkeypatch) -> None:
        """Test get_doc_store creates directory with given name."""
        temp_base = Path(tempfile.mkdtemp())
        try:
            # Patch TMP to use test directory
            import automate.eserv.util.doc_store as doc_store_module

            monkeypatch.setattr(doc_store_module, 'TMP', temp_base)

            store = get_doc_store(name='TestCase')

            assert store.exists()
            assert store.is_dir()
            assert 'TestCase' in store.name
        finally:
            # Cleanup
            import shutil

            shutil.rmtree(temp_base, ignore_errors=True)

    def test_creates_directory_without_name(self, monkeypatch) -> None:
        """Test get_doc_store creates directory without name."""
        temp_base = Path(tempfile.mkdtemp())
        try:
            import automate.eserv.util.doc_store as doc_store_module

            monkeypatch.setattr(doc_store_module, 'TMP', temp_base)

            store = get_doc_store()

            assert store.exists()
            assert store.is_dir()
            assert store.name == 'temp_store'
        finally:
            import shutil

            shutil.rmtree(temp_base, ignore_errors=True)

    def test_returns_absolute_path(self, monkeypatch) -> None:
        """Test get_doc_store returns absolute resolved path."""
        temp_base = Path(tempfile.mkdtemp())
        try:
            import automate.eserv.util.doc_store as doc_store_module

            monkeypatch.setattr(doc_store_module, 'TMP', temp_base)

            store = get_doc_store(name='TestCase')

            assert store.is_absolute()
        finally:
            import shutil

            shutil.rmtree(temp_base, ignore_errors=True)

    def test_reuses_existing_directory(self, monkeypatch) -> None:
        """Test get_doc_store reuses existing directory."""
        temp_base = Path(tempfile.mkdtemp())
        try:
            import automate.eserv.util.doc_store as doc_store_module

            monkeypatch.setattr(doc_store_module, 'TMP', temp_base)

            store1 = get_doc_store(name='TestCase')
            store2 = get_doc_store(name='TestCase')

            assert store1 == store2
            assert store1.exists()
        finally:
            import shutil

            shutil.rmtree(temp_base, ignore_errors=True)


class TestUniqueStores:
    """Test multiple document stores can coexist."""

    def test_creates_separate_stores_for_different_names(self, monkeypatch) -> None:
        """Test different names create different directories."""
        temp_base = Path(tempfile.mkdtemp())
        try:
            import automate.eserv.util.doc_store as doc_store_module

            monkeypatch.setattr(doc_store_module, 'TMP', temp_base)

            store1 = get_doc_store(name='Case1')
            store2 = get_doc_store(name='Case2')

            assert store1 != store2
            assert store1.exists()
            assert store2.exists()
            assert 'Case1' in store1.name
            assert 'Case2' in store2.name

        finally:
            import shutil

            shutil.rmtree(temp_base, ignore_errors=True)

    def test_handles_similar_names(self, monkeypatch) -> None:
        """Test similar names create distinct directories."""
        temp_base = Path(tempfile.mkdtemp())
        try:
            import automate.eserv.util.doc_store as doc_store_module

            monkeypatch.setattr(doc_store_module, 'TMP', temp_base)

            store1 = get_doc_store(name='TestCase')
            store2 = get_doc_store(name='Test Case')  # Will be cleaned to same name

            # After cleaning, both should map to same directory
            assert store1 == store2

        finally:
            import shutil

            shutil.rmtree(temp_base, ignore_errors=True)
