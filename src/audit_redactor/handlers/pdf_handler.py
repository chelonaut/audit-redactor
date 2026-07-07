"""PDF handler (PLAN.md 2.4, 2.5, build phase 4).

True redaction: underlying content is deleted via PyMuPDF's
`apply_redactions()`, never an overlay rectangle. After redacting, the file
is fully rewritten (`garbage=4, deflate=True, clean=True`) so no earlier
incremental-save revision can leak the pre-redaction content. A post-save
verification pass re-extracts text from the saved file and fails loudly if
any matched span is still recoverable verbatim.

Hidden OC (optional content / layer) groups are neutralized *before* any text
is extracted for detection: MuPDF's text extraction honors OCG visibility,
so content sitting in a hidden layer would otherwise never be seen by the
detectors at all -- not merely left un-redacted, but invisible to the
pipeline. Nulling the catalog's `/OCProperties` makes MuPDF treat all
content as visible for both extraction and redaction, and permanently
removes the layer-toggle mechanism from the output.
"""

from __future__ import annotations

from pathlib import Path

import fitz

from audit_redactor.appliers.pdf import strip_pdf_metadata, verify_pdf_redacted
from audit_redactor.appliers.text import redact_char_ranges
from audit_redactor.detectors import detect_text
from audit_redactor.detectors.base import Span
from audit_redactor.pipeline import register

_REDACT_FILL = (0, 0, 0)


def _page_text_and_char_map(page: "fitz.Page") -> tuple[str, list[fitz.Rect]]:
    """Build the page's plain text plus a parallel list mapping each text
    offset to the bbox of the character at that offset.

    Concatenates characters within each line directly (their own glyphs
    already include inter-word spaces) and inserts a bare `\\n` between
    lines/blocks with no corresponding bbox entry -- matching what
    `page.get_text()` would produce closely enough for the regex/company-list
    detectors, which don't need cross-line matches.
    """
    raw = page.get_text("rawdict")
    text_parts: list[str] = []
    char_bboxes: list[fitz.Rect] = []
    for block in raw.get("blocks", []):
        for line in block.get("lines", []):
            for span in line.get("spans", []):
                for ch in span.get("chars", []):
                    text_parts.append(ch["c"])
                    char_bboxes.append(fitz.Rect(ch["bbox"]))
            text_parts.append("\n")
            char_bboxes.append(None)
    return "".join(text_parts), char_bboxes


def _redact_rects_for_span(span: Span, char_bboxes: list[fitz.Rect]) -> list[fitz.Rect]:
    """Map a span's redact-char-ranges (PLAN.md 2.3) onto page-space rects."""
    rects = []
    for start, end in redact_char_ranges(span):
        bboxes = [b for b in char_bboxes[span.start + start : span.start + end] if b is not None]
        if not bboxes:
            continue
        rect = bboxes[0]
        for b in bboxes[1:]:
            rect |= b
        rects.append(rect)
    return rects


@register(".pdf")
def redact_pdf(input_path: Path, output_path: Path, offline: bool) -> Path:
    doc = fitz.open(input_path)
    try:
        # Must happen before any per-page text extraction below, so hidden
        # OCG content is visible to (and therefore redactable by) detection.
        cat = doc.pdf_catalog()
        doc.xref_set_key(cat, "OCProperties", "null")

        spans_by_page: list[list[Span]] = []
        for page in doc:
            text, char_bboxes = _page_text_and_char_map(page)
            spans = detect_text(text)
            spans_by_page.append(spans)
            for span in spans:
                for rect in _redact_rects_for_span(span, char_bboxes):
                    page.add_redact_annot(rect, fill=_REDACT_FILL)
            if spans:
                page.apply_redactions()

        strip_pdf_metadata(doc)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        doc.save(output_path, garbage=4, deflate=True, clean=True)
    finally:
        doc.close()

    all_spans = [span for page_spans in spans_by_page for span in page_spans]
    try:
        verify_pdf_redacted(output_path, all_spans)
    except Exception:
        # Don't leave a file flagged as possibly-unsafe sitting at the
        # redacted-output path.
        output_path.unlink(missing_ok=True)
        raise
    return output_path
