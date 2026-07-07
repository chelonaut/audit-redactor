"""Curated client company name matcher (PLAN.md 2.3, 2.10).

The list is maintained as a standalone data file, confirmed via web search
when adding new names, and never web-searched during redaction itself (2.10).
"""

from __future__ import annotations

import re
import unicodedata
from importlib import resources
from pathlib import Path

from audit_redactor.detectors.base import EntityType, Span

_DEFAULT_NAMES_RESOURCE = resources.files("audit_redactor").joinpath("data", "company_names.txt")


def _parse_names(raw_text: str) -> list[str]:
    names = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        names.append(line)
    return names


def _fold_diacritics(text: str) -> tuple[str, list[int]]:
    """Strip combining diacritical marks (e.g. "e" for "é") so matching
    doesn't depend on accents being typed correctly, either in the curated
    list or in the document.

    Returns the folded text plus a per-character map back to `text`'s
    original indices, so matches found in the folded text can still be
    reported at their true offsets in the original (accented) text.
    """
    folded_chars: list[str] = []
    index_map: list[int] = []
    for i, ch in enumerate(text):
        for dch in unicodedata.normalize("NFKD", ch):
            if unicodedata.combining(dch):
                continue
            folded_chars.append(dch)
            index_map.append(i)
    return "".join(folded_chars), index_map


def _build_pattern(names: list[str]) -> re.Pattern[str] | None:
    if not names:
        return None
    # Longest-first so a longer curated name (e.g. "M&S Foods") would match
    # before a shorter one it contains (e.g. "M&S") could shadow it.
    folded_names = [_fold_diacritics(n)[0] for n in names]
    escaped = sorted((re.escape(n) for n in folded_names), key=len, reverse=True)
    return re.compile(r"(?<!\w)(?:" + "|".join(escaped) + r")(?!\w)", re.IGNORECASE)


class CompanyListDetector:
    """Matches a curated list of client company names, loaded from a text file.

    Defaults to the bundled starter list at `audit_redactor/data/company_names.txt`.
    Pass `data_path` to point at a separate, private, real curated list instead.
    """

    def __init__(self, data_path: Path | str | None = None) -> None:
        if data_path is not None:
            raw_text = Path(data_path).read_text(encoding="utf-8")
        else:
            raw_text = _DEFAULT_NAMES_RESOURCE.read_text(encoding="utf-8")
        self.names = _parse_names(raw_text)
        self._pattern = _build_pattern(self.names)

    def detect(self, text: str) -> list[Span]:
        if self._pattern is None:
            return []
        folded_text, index_map = _fold_diacritics(text)
        spans = []
        for m in self._pattern.finditer(folded_text):
            if m.start() == m.end():
                continue
            start = index_map[m.start()]
            end = index_map[m.end() - 1] + 1
            spans.append(
                Span(
                    text=text[start:end],
                    entity_type=EntityType.COMPANY_NAME,
                    confidence=1.0,
                    source="company_list",
                    start=start,
                    end=end,
                )
            )
        return spans
