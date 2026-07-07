"""Text-level span application, shared by every handler that redacts spans
directly in a string (Markdown, JSON string leaves; HTML/DOM text nodes in
phase 6 reuse this too).

Per PLAN.md 2.3, the replacement is not a single uniform placeholder --
different entity types are masked differently (e.g. an AWS account ID keeps
its last 4 digits, a company name is fully replaced). This module is the one
place that encodes that mapping so every handler applies it identically.
"""

from __future__ import annotations

from audit_redactor.detectors.base import EntityType, Span

# `(...)`/`x` rather than `[...]`/`*` -- picked so the output is never
# ambiguous with Markdown syntax (`[...]` can start a link, `*` is emphasis)
# once the Markdown handler (phase 6) converts already-redacted Markdown to
# HTML. Applies uniformly across every format for consistency, not just
# Markdown -- there's no benefit to a different convention per format, and
# one fewer thing to keep in sync.
PLACEHOLDER = "(REDACTED)"
_MASK_CHAR = "x"

# Entity types masked with a flat placeholder -- PLAN.md 2.3 calls these out
# as "full redaction" rather than a partial/format-preserving mask.
_FULL_REDACTION_TYPES = {
    EntityType.EMAIL,
    EntityType.USERNAME_MENTION,
    EntityType.URL,
    EntityType.COMPANY_NAME,
}


def _contiguous_ranges(flags: list[bool]) -> list[tuple[int, int]]:
    """Turn a per-character boolean list into a list of (start, end) runs of True."""
    ranges = []
    start: int | None = None
    for i, flag in enumerate(flags):
        if flag and start is None:
            start = i
        elif not flag and start is not None:
            ranges.append((start, i))
            start = None
    if start is not None:
        ranges.append((start, len(flags)))
    return ranges


def redact_char_ranges(span: Span) -> list[tuple[int, int]]:
    """Return the (start, end) character ranges *within `span.text`* that must
    be hidden, per PLAN.md 2.3's per-entity masking rules.

    This is the single source of truth for "which characters are sensitive
    within a matched span" -- `apply_span_text` below uses it to build a
    masked replacement string, and the PDF handler (phase 4) uses it directly
    to know which character bboxes to redact, so the two can never disagree
    about what's actually hidden.
    """
    text = span.text
    if span.entity_type == EntityType.AWS_ACCOUNT_ID:
        # Keep the last 4 digits; separators are never redacted themselves.
        digit_count = sum(1 for ch in text if ch.isdigit())
        keep_from = digit_count - 4
        seen = 0
        flags = []
        for ch in text:
            if ch.isdigit():
                flags.append(seen < keep_from)
                seen += 1
            else:
                flags.append(False)
        return _contiguous_ranges(flags)
    if span.entity_type == EntityType.PHONE_NUMBER:
        # Every digit is redacted completely; separators are left visible.
        return _contiguous_ranges([ch.isdigit() for ch in text])
    if span.entity_type == EntityType.PERSON_NAME:
        # Keep the first 4 characters.
        if len(text) <= 4:
            return []
        return [(4, len(text))]
    if span.entity_type in _FULL_REDACTION_TYPES:
        return [(0, len(text))]
    raise ValueError(f"no redaction rule registered for entity type {span.entity_type!r}")


def apply_span_text(span: Span) -> str:
    """Return the masked replacement text for a single span, per PLAN.md 2.3."""
    if span.entity_type in _FULL_REDACTION_TYPES:
        return PLACEHOLDER
    ranges = redact_char_ranges(span)
    hidden = [False] * len(span.text)
    for start, end in ranges:
        for i in range(start, end):
            hidden[i] = True
    return "".join(_MASK_CHAR if is_hidden else ch for ch, is_hidden in zip(span.text, hidden))


def merge_spans(spans: list[Span]) -> list[Span]:
    """Resolve overlapping spans into a non-overlapping, start-ascending list.

    Sorts by start ascending, longest-first as a tie-break, then keeps a span
    only if it starts at or after the end of the last kept span -- so a
    longer match (e.g. a curated company name) wins over a shorter one it
    contains, and a span fully inside an already-kept span is dropped.
    """
    ordered = sorted(spans, key=lambda s: (s.start, s.start - s.end))
    merged: list[Span] = []
    cursor = -1
    for span in ordered:
        if span.start >= cursor:
            merged.append(span)
            cursor = span.end
    return merged


def redact_text(text: str, spans: list[Span]) -> str:
    """Apply detected spans to raw text, replacing each per its entity type."""
    merged = merge_spans(spans)
    pieces = []
    cursor = 0
    for span in merged:
        pieces.append(text[cursor : span.start])
        pieces.append(apply_span_text(span))
        cursor = span.end
    pieces.append(text[cursor:])
    return "".join(pieces)
