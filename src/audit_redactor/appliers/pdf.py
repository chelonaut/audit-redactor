"""Shared PDF-output finishing steps: metadata stripping and the post-save
verification pass (PLAN.md 2.4, 2.5).

Used by both the native PDF handler (phase 4) and the HTML/Markdown-to-PDF
pipeline (phase 6) -- both ultimately produce a real PDF file that must be
scrubbed and verified identically regardless of how its content was
produced.
"""

from __future__ import annotations

from pathlib import Path

import fitz

from audit_redactor.detectors.base import Span

# Catalog keys the metadata scrub strips outright (PLAN.md 2.5): Names (may
# carry a JavaScript dict), OpenAction (may launch a JS action), OCProperties
# (hidden-layer toggle mechanism).
_CATALOG_KEYS_TO_STRIP = ("Names", "OpenAction", "OCProperties")


class PdfRedactionVerificationError(RuntimeError):
    """Raised when a matched span is still recoverable after redaction."""


def strip_pdf_metadata(doc: "fitz.Document") -> None:
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


def verify_pdf_redacted(doc_path: Path, spans: list[Span]) -> None:
    """Fail loudly if any matched span text is still recoverable, either via
    normal text extraction (checked across every page) or as raw bytes
    anywhere in the saved file (guards against the shared XObject/Form-stream
    leakage caveat in PLAN.md 2.4, which `apply_redactions()` is not
    guaranteed to fully clear).
    """
    raw_bytes = doc_path.read_bytes()
    verify_doc = fitz.open(doc_path)
    try:
        full_text = "".join(page.get_text() for page in verify_doc)
        for span in spans:
            if span.text in full_text:
                raise PdfRedactionVerificationError(
                    f"redaction verification failed: {span.entity_type} span "
                    f"{span.text!r} still recoverable via text extraction"
                )
            if span.text.encode("utf-8") in raw_bytes:
                raise PdfRedactionVerificationError(
                    f"redaction verification failed: {span.entity_type} span "
                    f"{span.text!r} still present in raw saved file bytes"
                )
    finally:
        verify_doc.close()
