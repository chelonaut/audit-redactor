"""Shared data model that every detector (regex, NER, Claude) produces.

Per PLAN.md 2.8: detection and application are fully decoupled. Every
detector emits a list of `Span` objects with the same shape; the one
deterministic applier per file type consumes them without caring which
detector produced them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

# "regex" and "company_list" are always full-confidence and applied
# immediately. "ner" spans carry the model's own confidence and may be
# downgraded to hints. "claude" spans come from the augmentation pass and
# must pass the grounding check before being applied.
Source = Literal["regex", "company_list", "ner", "claude"]


@dataclass(frozen=True)
class Span:
    """A single detected sensitive-data occurrence in a document's text.

    `start`/`end` are character offsets into the text the detector was run
    against (UTF-8 codepoint offsets, not byte offsets). They are the
    handler's responsibility to map back to a PDF bbox / DOM node / JSON
    path / pixel region.
    """

    text: str
    entity_type: str
    confidence: float
    source: Source
    start: int
    end: int

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence}")
        if self.start < 0 or self.end < self.start:
            raise ValueError(f"invalid span offsets: start={self.start}, end={self.end}")


class Detector(Protocol):
    """Anything that scans text and returns spans to redact or hint at."""

    def detect(self, text: str) -> list[Span]: ...
