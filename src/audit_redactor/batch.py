"""Resolve a CLI input argument (file / directory / glob pattern) into a list
of files, and run the redaction pipeline over all of them without stopping on
the first error -- collecting a per-file result so the caller can report a
final success/failure summary.
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass
from pathlib import Path

from audit_redactor.pipeline import redact_file

_GLOB_CHARS = set("*?[")


def is_glob_pattern(spec: str) -> bool:
    return any(c in spec for c in _GLOB_CHARS)


@dataclass(frozen=True)
class ResolvedInputs:
    files: list[Path]
    base_dir: Path
    is_batch: bool


def resolve_inputs(input_spec: str) -> ResolvedInputs:
    """Turn a file path, directory path, or glob pattern into a sorted file list.

    `base_dir` is the common ancestor used to compute each file's relative
    path under the output directory in batch mode.
    """
    if is_glob_pattern(input_spec):
        matches = sorted(Path(m) for m in glob.glob(input_spec, recursive=True))
        files = [m for m in matches if m.is_file()]
        if files:
            base_dir = Path(os.path.commonpath([str(f.parent) for f in files]))
        else:
            base_dir = Path(".")
        return ResolvedInputs(files=files, base_dir=base_dir, is_batch=True)

    path = Path(input_spec)
    if path.is_dir():
        files = sorted(f for f in path.rglob("*") if f.is_file())
        return ResolvedInputs(files=files, base_dir=path, is_batch=True)

    if path.is_file():
        return ResolvedInputs(files=[path], base_dir=path.parent, is_batch=False)

    raise FileNotFoundError(f"input path not found: {input_spec}")


@dataclass(frozen=True)
class BatchResult:
    succeeded: list[tuple[Path, Path]]  # (input, actual output written)
    failed: list[tuple[Path, str]]  # (input, reason)

    @property
    def total(self) -> int:
        return len(self.succeeded) + len(self.failed)


def run_batch(resolved: ResolvedInputs, output_dir: Path, offline: bool) -> BatchResult:
    output_dir.mkdir(parents=True, exist_ok=True)
    succeeded: list[tuple[Path, Path]] = []
    failed: list[tuple[Path, str]] = []
    total = len(resolved.files)

    for index, input_path in enumerate(resolved.files, start=1):
        # File-count-based, not size-based -- a deliberately rough estimate
        # (PLAN.md doesn't need per-byte progress, just a sense of how far
        # through a large batch the run has gotten), printed as each file
        # starts so it's visible immediately rather than only after slow
        # per-file work (Claude calls in particular) completes.
        pct = round(100 * index / total)
        print(f"Processing file {index}/{total} ({pct}%) - {input_path.name}...", flush=True)

        try:
            rel = input_path.relative_to(resolved.base_dir)
        except ValueError:
            rel = Path(input_path.name)
        dest = output_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)

        try:
            actual = redact_file(input_path, dest, offline)
            succeeded.append((input_path, actual))
        except Exception as exc:  # noqa: BLE001 - collected, not raised, so one bad file can't abort the batch
            failed.append((input_path, str(exc)))

    return BatchResult(succeeded=succeeded, failed=failed)
