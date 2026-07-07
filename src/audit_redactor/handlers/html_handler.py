"""HTML handler (PLAN.md 2.7, build phase 6).

Redacts the HTML source before any rendering happens: strips `<script>`
tags, HTML comments, `data-*` attributes, and `<meta>` tags outright
(PLAN.md 2.7 step 1 -- these can carry hidden PII or tracking IDs invisible
in the rendered page), then walks every remaining text node -- including
`<title>`, which Chrome uses as the rendered PDF's metadata title -- through
the same detector set every other format uses. Only the already-redacted
HTML is ever handed to Playwright for rendering (appliers/html_render.py);
the original, unredacted markup never reaches the browser engine.

The redacted HTML is then handed to `appliers/html_render.py`'s shared
render-and-finish pipeline (also used by the Markdown handler), which
renders via Playwright, strips PDF metadata, and runs the post-render
verification pass.
"""

from __future__ import annotations

from pathlib import Path

from bs4 import BeautifulSoup, Comment

from audit_redactor.appliers.html_render import render_and_finish_pdf
from audit_redactor.appliers.text import redact_text
from audit_redactor.detectors import detect_text_with_claude
from audit_redactor.detectors.base import Span
from audit_redactor.pipeline import register

# CSS/JS aren't prose text -- redacting inside them risks corrupting syntax
# for no benefit (there's no sensitive-data-in-source-code target in scope).
_SKIP_TEXT_PARENTS = {"script", "style"}


def redact_html_source(html: str, offline: bool = True) -> tuple[str, list[Span]]:
    """Redact an HTML document's source, returning the redacted markup and
    every span found across all text nodes (for the post-render verification
    pass).

    `offline` defaults to `True` so callers that don't care about Claude
    augmentation (unit tests) get local-only detection with no risk of an
    unexpected network call.
    """
    soup = BeautifulSoup(html, "html.parser")

    for tag in soup.find_all("script"):
        tag.decompose()
    for tag in soup.find_all("meta"):
        tag.decompose()
    for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
        comment.extract()
    for tag in soup.find_all(True):
        for attr in list(tag.attrs):
            if attr.startswith("data-"):
                del tag.attrs[attr]

    all_spans: list[Span] = []
    for node in soup.find_all(string=True):
        if node.parent and node.parent.name in _SKIP_TEXT_PARENTS:
            continue
        text = str(node)
        spans = detect_text_with_claude(text, offline)
        if spans:
            all_spans.extend(spans)
            node.replace_with(redact_text(text, spans))

    return str(soup), all_spans


@register(".html", ".htm")
def redact_html(input_path: Path, output_path: Path, offline: bool) -> Path:
    html = input_path.read_text(encoding="utf-8")
    redacted_html, spans = redact_html_source(html, offline)

    pdf_output_path = output_path.with_suffix(".pdf")
    render_and_finish_pdf(redacted_html, spans, pdf_output_path)
    return pdf_output_path
