"""Fuzzy name matching for Dropbox folder resolution.

Extracts party names from case names and matches them to Dropbox folders
using fuzzy string matching. Handles various case name formats.

Classes:
    CaseMatch: Result of a case name match with confidence score.
    PartyExtractor: Extracts party names from case name strings.
    FolderMatcher: Matches extracted parties to Dropbox folders.

Functions:
    extract_case_names_from_pdf: Extract case names from PDF text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from rampy.util import create_field_factory
from rapidfuzz import fuzz, process

from setup_console import console


@dataclass(slots=True, frozen=True)
class CaseMatch:
    """Result of a case name match.

    Attributes:
        folder_path: Matched Dropbox folder path.
        score: Confidence score (0-100).
        matched_on: Which party name produced the match.

    """

    folder_path: str
    score: float
    matched_on: str


class PartyExtractor:
    """Extracts party names from case name strings.

    Handles various case name formats:
    - "Plaintiff v. Defendant"
    - "Plaintiff vs Defendant"
    - "In re: Party Name"
    - "Matter of Party Name"
    """

    # Common legal separators
    VS_PATTERN = re.compile(r'\s+v\.?\s+|\s+vs\.?\s+', re.IGNORECASE)
    IN_RE_PATTERN = re.compile(r'^in\s+re:?\s+', re.IGNORECASE)
    MATTER_OF_PATTERN = re.compile(r'^matter\s+of:?\s+', re.IGNORECASE)

    # Noise words to filter out
    NOISE_WORDS: Final[set[str]] = {
        'the',
        'of',
        'and',
        'or',
        'inc',
        'llc',
        'corp',
        'ltd',
        'co',
        'estate',
        'trust',
        'case',
        'matter',
        'proceeding',
    }

    @classmethod
    def extract_parties(cls, case_name: str) -> list[str]:
        """Extract party names from a case name string.

        Args:
            case_name: Raw case name string.

        Returns:
            List of extracted party names (typically 1-2).

        """
        # Normalize whitespace
        case_name = ' '.join(case_name.split())

        parties: list[str] = []

        # Check for "In re:" or "Matter of:" format
        if cls.IN_RE_PATTERN.match(case_name):
            party = cls.IN_RE_PATTERN.sub('', case_name).strip()
            parties.append(cls._clean_party_name(party))
            return parties

        if cls.MATTER_OF_PATTERN.match(case_name):
            party = cls.MATTER_OF_PATTERN.sub('', case_name).strip()
            parties.append(cls._clean_party_name(party))
            return parties

        # Check for "v." or "vs" format
        if cls.VS_PATTERN.search(case_name):
            split_parties = cls.VS_PATTERN.split(case_name, maxsplit=1)
            for party in split_parties:
                cleaned = cls._clean_party_name(party.strip())
                if cleaned:
                    parties.append(cleaned)
            return parties

        # Fallback: treat entire string as single party
        cleaned = cls._clean_party_name(case_name)
        if cleaned:
            parties.append(cleaned)

        return parties

    @classmethod
    def _clean_party_name(cls, party: str) -> str:
        """Clean a party name by removing noise words and normalizing.

        Args:
            party: Raw party name.

        Returns:
            Cleaned party name.

        """
        # Remove common suffixes (Inc., LLC, etc.)
        party = re.sub(
            r',?\s+(Inc\.?|LLC\.?|Corp\.?|Ltd\.?|Co\.?)$',
            '',
            party,
            flags=re.IGNORECASE,
        )

        # Split into words and filter noise
        words = party.split()
        filtered = [w for w in words if w.lower() not in cls.NOISE_WORDS and len(w) > 1]

        return ' '.join(filtered)


class FolderMatcher:
    """Matches extracted party names to Dropbox folders using fuzzy matching.

    Attributes:
        folder_paths: List of available Dropbox folder paths.
        min_score: Minimum confidence score to consider a match (0-100).

    """

    def __init__(self, folder_paths: list[str], min_score: float = 70.0) -> None:
        """Initialize a folder matcher.

        Args:
            folder_paths: List of Dropbox folder paths to search.
            min_score: Minimum confidence score (default 70.0).

        """
        self.folder_paths = folder_paths
        self.min_score = min_score

    def find_best_match(self, case_name: str) -> CaseMatch | None:
        """Find best matching folder for a case name.

        Args:
            case_name: Case name to match.

        Returns:
            Best match if score exceeds threshold, None otherwise.

        """
        parties = PartyExtractor.extract_parties(case_name)

        if not parties:
            console.warning('No parties extracted from case name', case_name=case_name)
            return None

        best_match = None
        best_score = 0.0
        matched_party = ''

        for party in parties:
            # Try fuzzy matching against all folder paths
            matches = process.extract(
                party,
                self.folder_paths,
                scorer=fuzz.token_sort_ratio,
                limit=1,
            )

            if matches:
                folder, score, _ = matches[0]
                if score > best_score:
                    best_score = score
                    best_match = folder
                    matched_party = party

        if best_match and best_score >= self.min_score:
            console.info(
                event='Found folder match',
                score=best_score,
                matched_folder=best_match,
                matched_on=matched_party,
            )

            return CaseMatch(
                folder_path=best_match,
                score=best_score,
                matched_on=matched_party,
            )

        console.warning(
            event='No folder match found',
            case_name=case_name,
            best_score=best_score,
            min_score=self.min_score,
        )

        return None


get_dbx_folder_matcher = create_field_factory(FolderMatcher)
