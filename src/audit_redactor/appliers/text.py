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

_PLACEHOLDER = "[REDACTED]"

# Entity types masked with a flat placeholder -- PLAN.md 2.3 calls these out
# as "full redaction" rather than a partial/format-preserving mask.
_FULL_REDACTION_TYPES = {
    EntityType.EMAIL,
    EntityType.USERNAME_MENTION,
    EntityType.URL,
    EntityType.COMPANY_NAME,
}


def _mask_aws_account_id(matched: str) -> str:
    """Mask all but the last 4 digits, preserving any separators.

    Handles both forms the detector emits: a bare 12-digit run
    (`123456789012` -> `********9012`) and AWS console's 4-4-4 hyphenated
    display format (`1234-5678-9012` -> `****-****-9012`).
    """
    digit_count = sum(1 for ch in matched if ch.isdigit())
    keep_from = digit_count - 4
    out = []
    seen = 0
    for ch in matched:
        if ch.isdigit():
            out.append(ch if seen >= keep_from else "*")
            seen += 1
        else:
            out.append(ch)
    return "".join(out)


def _mask_phone_number(matched: str) -> str:
    """Redact every digit completely, preserving separators/punctuation."""
    return "".join("*" if ch.isdigit() else ch for ch in matched)


def _mask_person_name(matched: str) -> str:
    """Obscure all but the first 4 characters."""
    if len(matched) <= 4:
        return matched
    return matched[:4] + "*" * (len(matched) - 4)


def apply_span_text(span: Span) -> str:
    """Return the masked replacement text for a single span, per PLAN.md 2.3."""
    if span.entity_type == EntityType.AWS_ACCOUNT_ID:
        return _mask_aws_account_id(span.text)
    if span.entity_type == EntityType.PHONE_NUMBER:
        return _mask_phone_number(span.text)
    if span.entity_type == EntityType.PERSON_NAME:
        return _mask_person_name(span.text)
    if span.entity_type in _FULL_REDACTION_TYPES:
        return _PLACEHOLDER
    raise ValueError(f"no text applier registered for entity type {span.entity_type!r}")


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
