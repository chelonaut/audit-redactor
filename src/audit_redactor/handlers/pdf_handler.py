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

A page with negligible extractable text but at least one embedded image is
treated as "scanned" and redacted via the OCR pipeline instead (see
`_is_scanned_page`/`_redact_scanned_page` below) -- found via a real
end-to-end validation run against a genuinely screenshotted PDF where the
native text-based path found nothing to act on and left an account ID
sitting in the page's pixels, completely unredacted, with the post-save
verification pass reporting a false pass since it had no span text to check
the raw bytes against in the first place.
"""

from __future__ import annotations

import io
from pathlib import Path

import fitz
from PIL import Image

from audit_redactor.appliers.image_ocr import ocr_redact_image
from audit_redactor.appliers.output_guard import ensure_output_does_not_exist
from audit_redactor.appliers.pdf import strip_pdf_metadata, verify_pdf_redacted
from audit_redactor.appliers.text import redact_char_ranges
from audit_redactor.detectors import detect_text, detect_text_with_claude
from audit_redactor.detectors.base import EntityType, Span
from audit_redactor.pipeline import register

_REDACT_FILL = (0, 0, 0)
_SCAN_RENDER_ZOOM = 2.0
_SCANNED_PAGE_TEXT_THRESHOLD = 20  # chars; well below any real body paragraph


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


def _strip_sensitive_links(page: "fitz.Page") -> None:
    """Delete any hyperlink whose target URI leaks sensitive data.

    `apply_redactions()` only touches the page's visible content stream --
    link annotations are a separate PDF object entirely. Found via a real
    end-to-end validation run: a browser-exported AWS console page had its
    bucket name (embedding the full account ID) correctly blacked out as
    visible text, but the same URL was also the target of a hyperlink on
    that text, and the link's URI -- untouched by `apply_redactions()` --
    still carried the account ID as a literal string in the saved file.
    Local-only detection (not Claude) deliberately: URIs are short,
    isolated strings, not document prose, and checking each one via the API
    would multiply per-document Claude calls for no real benefit. A link is
    removed entirely rather than partially masked -- there's no sensible way
    to redact part of a URL without breaking it.

    Spans of type URL are excluded from the check: the URI detector always
    classifies the *whole* URI string as a URL (it is one), which would
    otherwise flag and delete every single external link regardless of
    whether it actually leaks anything. What matters is any *other* entity
    type found embedded within it (an account ID, email, phone number,
    username, or curated company name in the path/query).
    """
    for link in list(page.get_links()):
        uri = link.get("uri")
        if not uri:
            continue
        if any(span.entity_type != EntityType.URL for span in detect_text(uri)):
            page.delete_link(link)


def _is_scanned_page(page: "fitz.Page", text: str) -> bool:
    """A page with negligible extractable text but at least one embedded
    image is "scanned": its actual content is a picture, not real text, so
    `apply_redactions()` has nothing to act on and would silently leave the
    page entirely unredacted.
    """
    return len(text.strip()) < _SCANNED_PAGE_TEXT_THRESHOLD and bool(page.get_images(full=True))


def _redact_scanned_page(doc: "fitz.Document", page_index: int, offline: bool) -> list[Span]:
    """Render a scanned page to a raster, redact it via the same OCR
    pipeline the standalone image handler uses, then replace the page
    entirely with the redacted raster.

    Drawing a black box *on top of* the existing embedded image would leave
    the original, unredacted image bytes still present and recoverable
    underneath it -- the same "no overlay redaction" requirement native text
    redaction already follows (PLAN.md 2.4). Deleting the page and inserting
    a fresh one containing only the redacted raster ensures the original
    image is no longer referenced by the document at all;
    `doc.save(..., garbage=4)` then purges the now-orphaned original image
    object from the saved file. Any links on the original page are lost
    along with it -- an accepted trade-off, since a link's safety can't be
    verified on an image-only page beyond the OCR text check already applied
    to the visible content.
    """
    page = doc[page_index]
    rect = page.rect
    pix = page.get_pixmap(matrix=fitz.Matrix(_SCAN_RENDER_ZOOM, _SCAN_RENDER_ZOOM))
    image = Image.open(io.BytesIO(pix.tobytes("png"))).convert("RGB")

    redacted_image, spans = ocr_redact_image(image, offline)

    buf = io.BytesIO()
    redacted_image.save(buf, format="PNG")

    doc.delete_page(page_index)
    new_page = doc.new_page(pno=page_index, width=rect.width, height=rect.height)
    new_page.insert_image(new_page.rect, stream=buf.getvalue())
    return spans


@register(".pdf")
def redact_pdf(input_path: Path, output_path: Path, offline: bool) -> Path:
    ensure_output_does_not_exist(output_path)
    doc = fitz.open(input_path)
    try:
        # Must happen before any per-page text extraction below, so hidden
        # OCG content is visible to (and therefore redactable by) detection.
        cat = doc.pdf_catalog()
        doc.xref_set_key(cat, "OCProperties", "null")

        spans_by_page: list[list[Span]] = []
        # Fixed upfront: a scanned-page replacement deletes and re-inserts a
        # page at the same index, leaving the total page count (and every
        # other page's index) unchanged, so iterating a pre-computed range
        # stays valid throughout.
        for page_index in range(len(doc)):
            page = doc[page_index]
            text, char_bboxes = _page_text_and_char_map(page)
            if _is_scanned_page(page, text):
                spans = _redact_scanned_page(doc, page_index, offline)
                spans_by_page.append(spans)
                continue
            spans = detect_text_with_claude(text, offline)
            spans_by_page.append(spans)
            for span in spans:
                for rect in _redact_rects_for_span(span, char_bboxes):
                    page.add_redact_annot(rect, fill=_REDACT_FILL)
            if spans:
                page.apply_redactions()
            _strip_sensitive_links(page)

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
