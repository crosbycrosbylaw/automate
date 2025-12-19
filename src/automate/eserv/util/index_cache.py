"""Dropbox folder index caching with TTL-based refresh.

Caches the Dropbox folder structure to minimize API calls.
Automatically refreshes when TTL expires or on demand.

Classes:
    IndexCache: Dropbox folder index with TTL-based caching.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import orjson

from setup_console import console

if TYPE_CHECKING:
    from pathlib import Path


def datetime_min_utc() -> datetime:
    """Return the smallest representable datetime with `tzinfo` set to `datetime.UTC`."""
    return datetime.min.replace(tzinfo=UTC)


@dataclass
class IndexCache:
    """Caches Dropbox folder index with TTL-based refresh.

    Stores folder paths and metadata in JSON with expiration tracking.
    Automatically refreshes from Dropbox when cache expires.

    Attributes:
        cache_file: Path to cache JSON file.
        ttl_hours: Cache time-to-live in hours.
        _index: In-memory folder index.
        _prev_refresh: Timestamp of last cache refresh.

    """

    cache_file: Path
    ttl_hours: int

    _index: dict[str, dict[str, str]] = field(default_factory=dict, init=False)
    _prev_refresh: datetime = field(default_factory=datetime_min_utc, init=False)

    def __post_init__(self) -> None:
        """Load existing cache from disk."""
        self._load_cache()

    def _load_cache(self) -> None:
        """Load cache from JSON file, creating if missing."""
        if not self.cache_file.exists():
            self._index = {}
            self._prev_refresh = datetime_min_utc()
            self._save_cache()

            console.info('Created new index cache file', path=self.cache_file.as_posix())

            return

        try:
            with self.cache_file.open('rb') as f:
                data = orjson.loads(f.read())
            self._index = data.get('index', {})

            prev_refresh = data.get('prev_refresh', datetime_min_utc().isoformat())
            self._prev_refresh = datetime.fromisoformat(prev_refresh)

            console.info('Loaded index cache', folder_count=len(self._index))

        except Exception:
            console.exception('IndexCache loading')

            self._index = {}
            self._prev_refresh = datetime_min_utc()
            self._save_cache()

    def _save_cache(self) -> None:
        """Save current cache to JSON file."""
        # Ensure parent directory exists
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)

        data = {
            'prev_refresh': self._prev_refresh.isoformat(),
            'index': self._index,
        }
        with self.cache_file.open('wb') as f:
            f.write(orjson.dumps(data, option=orjson.OPT_INDENT_2))

    def is_stale(self) -> bool:
        """Check if cache has exceeded TTL.

        Returns:
            True if cache needs refresh, False otherwise.

        """
        return (datetime.now(UTC) - self._prev_refresh) > timedelta(hours=self.ttl_hours)

    def refresh(self, folder_index: dict[str, dict[str, str]]) -> None:
        """Update cache with fresh Dropbox folder index.

        Args:
            folder_index: New folder index from Dropbox API.

        """
        self._index = folder_index
        self._prev_refresh = datetime.now(UTC)
        self._save_cache()

        console.info(
            event='Refreshed index cache',
            folder_count=len(self._index),
            ttl_hours=self.ttl_hours,
        )

    def get_index(self) -> dict[str, dict[str, str]]:
        """Get current folder index.

        Returns:
            Folder index dictionary.

        """
        return self._index

    def find_folder(self, path: str) -> dict[str, str] | None:
        """Find a specific folder in the index.

        Args:
            path: Dropbox folder path.

        Returns:
            Folder metadata if found, None otherwise.

        """
        return self._index.get(path)

    def get_all_paths(self) -> list[str]:
        """Get list of all folder paths in the index.

        Returns:
            List of folder paths.

        """
        return [*self._index.keys()]
