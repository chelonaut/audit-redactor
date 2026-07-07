"""Markdown handler (PLAN.md 2.2, 2.7, build phases 3 and 6).

Redacts the raw Markdown text directly (same detector set as every other
format), *before* any HTML conversion -- so the Markdown-to-HTML converter
never sees an unredacted source. The already-redacted Markdown is then
converted to HTML and wrapped in a plain, minimal template with no external
stylesheets or fonts (nothing that could phone out over the network when
rendered), and handed to the same Playwright render-and-finish pipeline the
HTML handler uses. The intermediate redacted Markdown/HTML exists only in
memory and is never written to persistent output.
"""

from __future__ import annotations

from pathlib import Path

import markdown

from audit_redactor.appliers.html_render import render_and_finish_pdf
from audit_redactor.appliers.text import redact_text
from audit_redactor.detectors import detect_text
from audit_redactor.pipeline import register

_HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Redacted Document</title>
<style>
body {{ font-family: sans-serif; max-width: 800px; margin: 2em auto; line-height: 1.5; }}
code, pre {{ background: #f0f0f0; padding: 0.2em 0.4em; }}
</style>
</head>
<body>
{body}
</body>
</html>"""


@register(".md", ".markdown")
def redact_markdown(input_path: Path, output_path: Path, offline: bool) -> Path:
    text = input_path.read_text(encoding="utf-8")
    spans = detect_text(text)
    redacted_markdown = redact_text(text, spans)

    body_html = markdown.markdown(redacted_markdown)
    full_html = _HTML_TEMPLATE.format(body=body_html)

    pdf_output_path = output_path.with_suffix(".pdf")
    render_and_finish_pdf(full_html, spans, pdf_output_path)
    return pdf_output_path
