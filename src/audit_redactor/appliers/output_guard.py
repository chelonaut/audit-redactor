"""Shared "never clobber an existing file" check, called by every handler
immediately before it writes its final output.

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
