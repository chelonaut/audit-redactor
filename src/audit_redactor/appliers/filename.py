"""Filename redaction (PLAN.md 2.5, build phase 7).

A file's name is as much a leak vector as its contents -- e.g. an AWS
account number or client company name embedded directly in a filename would
survive even a perfectly redacted file body. Runs the same detector set
(regex + curated company list) against the filename's stem, leaving the
extension untouched. Applied once, at the pipeline dispatch chokepoint every
redaction call passes through (`pipeline.redact_file`), so it's automatic
regardless of file type or how the output path was constructed.
"""

from __future__ import annotations

from pathlib import Path

from audit_redactor.appliers.text import redact_text
from audit_redactor.detectors import detect_text


def redact_filename(path: Path) -> Path:
    """Return `path` with its stem's sensitive content redacted.

    Only the final path component's stem is touched -- the extension and
    every parent directory are left exactly as given.
    """
    spans = detect_text(path.stem)
    if not spans:
        return path
    redacted_stem = redact_text(path.stem, spans)
    return path.with_name(redacted_stem + path.suffix)
