"""Headless-Chromium HTML-to-PDF rendering, shared by the HTML and Markdown
handlers (PLAN.md 2.7, build phase 6). Both redact their source text/markup
first and only ever hand this function already-redacted HTML.

All outbound network requests are blocked unconditionally during rendering.
Real HTML can reference external stylesheets, fonts, images, or iframes, and
a browser engine will actually fetch them -- including e.g. a tracking pixel
already present in the *original*, not-yet-redacted document, whose query
string could itself carry PII. Firing that request during our own redaction
pass would make this tool the one leaking it, regardless of whether the
resource is otherwise unrelated to the entities we detect. This mirrors
PLAN.md's non-goal that no external network calls happen during the
redaction pass itself (2.10, 6) and the "no external stylesheets or fonts"
requirement for the Markdown template (2.7 step 2), generalized to any input
HTML.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import fitz
from playwright.sync_api import sync_playwright

from audit_redactor.appliers.pdf import strip_pdf_metadata, verify_pdf_redacted
from audit_redactor.detectors.base import Span


def render_html_to_pdf(html: str, output_path: Path) -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            page = browser.new_page()
            page.route("**/*", lambda route: route.abort())
            page.set_content(html)
            page.pdf(path=str(output_path))
        finally:
            browser.close()


def render_and_finish_pdf(html: str, spans: list[Span], output_path: Path) -> None:
    """Render already-redacted `html` to `output_path` as a scrubbed,
    verified PDF -- shared by the HTML and Markdown handlers (PLAN.md 2.7).

    Playwright can only write a fresh PDF to a new path, and PyMuPDF can't
    re-save metadata-stripping changes back over the same path it opened
    from (only a true incremental save, which isn't what we want here since
    we need the full `garbage=4` rewrite) -- so the render step writes to a
    temp path first, and the real output only exists after the metadata
    scrub + full rewrite have both happened. The intermediate raw-rendered
    PDF is cleaned up automatically (even on error) since it lives inside a
    `TemporaryDirectory`; if the post-write verification pass itself fails,
    the already-written `output_path` is deleted too, rather than leaving a
    file flagged as possibly-unsafe sitting at the redacted-output path.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp_dir:
        raw_pdf_path = Path(tmp_dir) / "rendered.pdf"
        render_html_to_pdf(html, raw_pdf_path)

        doc = fitz.open(raw_pdf_path)
        try:
            strip_pdf_metadata(doc)
            doc.save(output_path, garbage=4, deflate=True, clean=True)
        finally:
            doc.close()

    try:
        verify_pdf_redacted(output_path, spans)
    except Exception:
        output_path.unlink(missing_ok=True)
        raise
