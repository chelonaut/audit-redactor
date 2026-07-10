"""Shared "never clobber an existing file" check, called by every handler
immediately before it writes its final output. Also hosts the run-wide
--ignore-verify-failure toggle (below), since every handler with a
post-write verification pass already imports this module.

Checked per-handler (on the handler's actual final write path) rather than
once upstream in `pipeline.redact_file`, because some handlers change the
final path after dispatch -- e.g. Markdown/HTML always render to `.pdf`
regardless of the requested output extension -- and it's that final path
that matters.

This single "output must not already exist" rule also covers the
input-equals-output accident: if a misconfigured invocation points
OUTPUT_PATH at the very file being redacted, that path already exists (it's
the input being read), so the check trips before any write happens and the
original is never touched.
"""

from __future__ import annotations

from pathlib import Path


def ensure_output_does_not_exist(output_path: Path) -> None:
    if output_path.exists():
        raise FileExistsError(
            f"output file already exists, refusing to overwrite: {output_path}"
        )


# Module-level singleton, same rationale as detectors/text.py's
# `configure_default_company_list` and claude_augment.py's usage
# totals/circuit breaker: this is a single-process, run-once CLI, not a
# server, so a run-wide toggle set once at startup and read deep in the call
# stack is simpler than threading a new parameter through every handler's
# dispatch signature (`pipeline.HandlerFn`) for something that only 3 of
# them (pdf_handler.py, html_render.py, image_ocr.py) ever check.
_ignore_verify_failure = False


def configure_ignore_verify_failure(ignore: bool) -> None:
    """Set whether a post-redaction verification failure should be treated
    as non-fatal (--ignore-verify-failure): the output file is kept instead
    of deleted, and a warning is printed instead of raising. For genuine
    emergencies where losing an expensive Claude-augmented redaction pass to
    one verification failure is worse than shipping output that needs manual
    review -- never the default, since it defeats the whole safety net this
    project's verification passes exist for.
    """
    global _ignore_verify_failure
    _ignore_verify_failure = ignore


def should_ignore_verify_failure() -> bool:
    return _ignore_verify_failure
