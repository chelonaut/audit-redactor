"""Markdown handler (PLAN.md build phase 3).

Redacts the raw Markdown text via the deterministic detector set. Rendering
the redacted Markdown to PDF (PLAN.md 2.2, 2.7) is deferred to phase 6, since
it shares the HTML->PDF pipeline -- this phase writes redacted Markdown back
out as Markdown.
"""

from __future__ import annotations

from pathlib import Path

from audit_redactor.appliers.text import redact_text
from audit_redactor.detectors import detect_text
from audit_redactor.pipeline import register


@register(".md", ".markdown")
def redact_markdown(input_path: Path, output_path: Path, offline: bool) -> Path:
    text = input_path.read_text(encoding="utf-8")
    spans = detect_text(text)
    redacted = redact_text(text, spans)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(redacted, encoding="utf-8")
    return output_path
