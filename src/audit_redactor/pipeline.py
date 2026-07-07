"""Per-format dispatch, per PLAN.md section 3.

Each handler is added in its own build phase (Markdown/JSON in phase 3, PDF in
phase 4, images in phase 5, HTML in phase 6). This module only wires the
dispatch table together; format-specific logic lives under `handlers/`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

# A handler redacts input_path, writes to (at or near) output_path, and returns
# the actual path written -- which may differ from output_path when a handler
# changes the file extension (e.g. Markdown/HTML rendered to PDF, phase 6).
HandlerFn = Callable[[Path, Path, bool], Path]

_HANDLERS: dict[str, HandlerFn] = {}


def register(*extensions: str) -> Callable[[HandlerFn], HandlerFn]:
    """Decorator: register a handler function for one or more file extensions."""

    def wrap(fn: HandlerFn) -> HandlerFn:
        for ext in extensions:
            _HANDLERS[ext.lower()] = fn
        return fn

    return wrap


def redact_file(input_path: Path, output_path: Path, offline: bool) -> Path:
    ext = input_path.suffix.lower()
    handler = _HANDLERS.get(ext)
    if handler is None:
        supported = ", ".join(sorted(_HANDLERS)) or "(none registered yet)"
        raise ValueError(f"unsupported file format '{ext}'. Supported: {supported}")
    return handler(input_path, output_path, offline)


# Side-effecting import: populates _HANDLERS via each submodule's @register
# decorator. Kept at the bottom of the module so `register`/`_HANDLERS` are
# already defined by the time handlers import them back from here.
from audit_redactor import handlers  # noqa: E402,F401
