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

from audit_redactor.appliers.text import redact_char_ranges
from audit_redactor.detectors import detect_text
from audit_redactor.detectors.base import Span
from audit_redactor.pipeline import register

_REDACT_FILL = (0, 0, 0)

# Regex/key names the PDF verification pass and metadata scrub key off of.
# Kept narrow and specific to the catalog keys PLAN.md 2.5 calls out.
_CATALOG_KEYS_TO_STRIP = ("Names", "OpenAction", "OCProperties")


class PdfRedactionVerificationError(RuntimeError):
    """Raised when a matched span is still recoverable after redaction."""


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


def _strip_metadata(doc: "fitz.Document") -> None:
    doc.set_metadata({})
    doc.del_xml_metadata()
    while doc.embfile_count() > 0:
        doc.embfile_del(0)
    for page in doc:
        for widget in list(page.widgets() or []):
            page.delete_widget(widget)
    cat = doc.pdf_catalog()
    for key in _CATALOG_KEYS_TO_STRIP:
        doc.xref_set_key(cat, key, "null")


def _verify_redacted(doc_path: Path, spans_by_page: list[list[Span]]) -> None:
    """Fail loudly if any matched span text is still recoverable, either via
    normal text extraction or as raw bytes anywhere in the saved file (the
    latter guards against the shared XObject/Form-stream leakage caveat in
    PLAN.md 2.4, which `apply_redactions()` is not guaranteed to fully clear).
    """
    raw_bytes = doc_path.read_bytes()
    verify_doc = fitz.open(doc_path)
    try:
        for page_index, spans in enumerate(spans_by_page):
            page_text = verify_doc[page_index].get_text()
            for span in spans:
                if span.text in page_text:
                    raise PdfRedactionVerificationError(
                        f"redaction verification failed: {span.entity_type} span "
                        f"{span.text!r} still recoverable via text extraction on "
                        f"page {page_index}"
                    )
                if span.text.encode("utf-8") in raw_bytes:
                    raise PdfRedactionVerificationError(
                        f"redaction verification failed: {span.entity_type} span "
                        f"{span.text!r} still present in raw saved file bytes "
                        f"(page {page_index})"
                    )
    finally:
        verify_doc.close()


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

        _strip_metadata(doc)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        doc.save(output_path, garbage=4, deflate=True, clean=True)
    finally:
        doc.close()

    _verify_redacted(output_path, spans_by_page)
    return output_path
