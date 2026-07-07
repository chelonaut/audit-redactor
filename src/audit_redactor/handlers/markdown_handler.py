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

import re
from pathlib import Path

import markdown

from audit_redactor.appliers.html_render import render_and_finish_pdf
from audit_redactor.appliers.output_guard import ensure_output_does_not_exist
from audit_redactor.appliers.text import redact_text
from audit_redactor.detectors import KnownIdentityDetector, detect_text_with_claude, find_identity_usernames
from audit_redactor.pipeline import register

_HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Redacted Document</title>
<style>
body {{ font-family: sans-serif; max-width: 800px; margin: 2em auto; line-height: 1.5; }}
code, pre {{ background: #f0f0f0; padding: 0.2em 0.4em; }}
table {{ border-collapse: collapse; }}
th, td {{ border: 1px solid #ccc; padding: 0.3em 0.6em; }}
</style>
</head>
<body>
{body}
</body>
</html>"""

# python-markdown has no built-in GFM task-list support (would need a new
# third-party dependency to get real "- [ ]"/"- [x]" checkbox rendering), so
# this swaps the bracket marker for a raw, disabled <input type="checkbox">
# on the redacted Markdown *string* before handing it to the converter --
# inline HTML inside a list item passes through python-markdown untouched,
# same as any other inline HTML. Deliberately runs after `redact_text`, not
# before: `spans`' character offsets are computed against the original,
# unmodified source text, so inserting HTML here first would shift every
# offset after it and corrupt redaction.
_TASK_LIST_ITEM_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<bullet>[-*+])\s\[(?P<mark>[ xX])\]\s+(?P<item>.*)$", re.MULTILINE
)


def _render_task_list_checkboxes(text: str) -> str:
    def _replace(m: re.Match[str]) -> str:
        checked = " checked" if m.group("mark").lower() == "x" else ""
        return f'{m.group("indent")}{m.group("bullet")} <input type="checkbox"{checked} disabled> {m.group("item")}'

    return _TASK_LIST_ITEM_RE.sub(_replace, text)


@register(".md", ".markdown")
def redact_markdown(input_path: Path, output_path: Path, offline: bool) -> Path:
    pdf_output_path = output_path.with_suffix(".pdf")
    ensure_output_does_not_exist(pdf_output_path)

    text = input_path.read_text(encoding="utf-8")
    # A markdown link's URL is literal text in the source (unlike HTML's
    # separate href attribute), so a single scan of `text` covers both
    # discovery and redaction -- no second pass needed.
    identity_detector = KnownIdentityDetector(find_identity_usernames([text]))
    spans = detect_text_with_claude(text, offline, identity_detector=identity_detector)
    redacted_markdown = redact_text(text, spans)
    redacted_markdown = _render_task_list_checkboxes(redacted_markdown)

    # Without "fenced_code"/"tables", python-markdown's core parser doesn't
    # understand ``` fences or GFM pipe tables at all: a fenced block gets
    # misread as a single inline <code> span with the language hint leaking
    # in as literal text and every line collapsed onto one (a bare <code>
    # tag doesn't preserve whitespace the way <pre> does), and a pipe table
    # is left as literal "| a | b |" text instead of being parsed at all.
    body_html = markdown.markdown(redacted_markdown, extensions=["fenced_code", "tables"])
    full_html = _HTML_TEMPLATE.format(body=body_html)

    render_and_finish_pdf(full_html, spans, pdf_output_path)
    return pdf_output_path
