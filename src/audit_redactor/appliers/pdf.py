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

from audit_redactor.detectors.base import EntityType, Span

# Catalog keys the metadata scrub strips outright (PLAN.md 2.5): Names (may
# carry a JavaScript dict), OpenAction (may launch a JS action), OCProperties
# (hidden-layer toggle mechanism).
_CATALOG_KEYS_TO_STRIP = ("Names", "OpenAction", "OCProperties")


class PdfRedactionVerificationError(RuntimeError):
    """Raised when a matched span is still recoverable after redaction."""


def _is_word_char(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _recoverable(needle: str, haystack: str) -> bool:
    """Whether `needle` still occurs in `haystack` as a whole, word-bounded
    match -- not merely as a substring of some other, unrelated word.

    Plain substring containment (`needle in haystack`) false-positives
    whenever the same literal text also happens to be a prefix/suffix/infix
    of a different word that was never a detected match in the first place
    -- found via a real document where a redacted "mode" span failed
    verification only because the document separately (and correctly, since
    it was never a match) contains "model"/"modelling", and a redacted
    "Sainsbury" span failed only because the document elsewhere has the
    plural "Sainsburys" -- which company_list.py's own word-boundary rule
    (needed so "Mode" doesn't match inside "Model") also never turns into a
    match by itself. `company_list.py` additionally swallows a trailing "s"
    into the match itself precisely so a real plural doesn't slip through
    unredacted -- this boundary check exists for every other case where the
    leftover text genuinely is a different word, not the same name in
    another inflection.
    """
    if not needle:
        return False
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx == -1:
            return False
        end = idx + len(needle)
        before_ok = idx == 0 or not _is_word_char(haystack[idx - 1])
        after_ok = end == len(haystack) or not _is_word_char(haystack[end])
        if before_ok and after_ok:
            return True
        start = idx + 1


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

    Both checks are word-boundary-aware (`_recoverable`, not plain substring
    containment) so a span's literal text merely occurring inside a longer,
    different, never-matched word doesn't get treated as a leak of that
    span.

    The raw-bytes check is skipped for `URL` spans specifically: the PDF
    handler's `_strip_sensitive_links` deliberately *keeps* a hyperlink whose
    URI is nothing more than a URL (no account ID/email/company name/etc.
    embedded in it) -- otherwise every ordinary external link in a document
    would get deleted. Found via a real Jira-exported PDF where the same
    plain URL appeared as blacked-out visible text *and* as an unrelated,
    legitimately-kept link elsewhere on the page (e.g. site branding) --
    correct behavior by that design, but this blanket "must not exist
    anywhere in the file" check flagged it as leaked anyway. The
    text-extraction check above already guarantees no *visible* occurrence
    of a URL span survives on any page, which is what actually matters for a
    "fully redacted" URL; a copy of the same literal string surviving only
    inside a kept link's own URI is the intended outcome, not a leak.
    """
    raw_bytes = doc_path.read_bytes()
    # Decoding as latin-1 (never fails: every byte maps 1:1 to a codepoint
    # 0-255) lets the same word-boundary-aware string search run over the
    # raw bytes as over extracted text, rather than a separate bytes-only
    # implementation of `_recoverable`.
    raw_as_text = raw_bytes.decode("latin-1")
    verify_doc = fitz.open(doc_path)
    try:
        full_text = "".join(page.get_text() for page in verify_doc)
        for span in spans:
            if _recoverable(span.text, full_text):
                raise PdfRedactionVerificationError(
                    f"redaction verification failed: {span.entity_type} span "
                    f"{span.text!r} still recoverable via text extraction"
                )
            if span.entity_type == EntityType.URL:
                continue
            if _recoverable(span.text.encode("utf-8").decode("latin-1"), raw_as_text):
                raise PdfRedactionVerificationError(
                    f"redaction verification failed: {span.entity_type} span "
                    f"{span.text!r} still present in raw saved file bytes"
                )
    finally:
        verify_doc.close()
