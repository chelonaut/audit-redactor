from __future__ import annotations

import sys
from pathlib import Path

import click

from audit_redactor import __version__
from audit_redactor.batch import resolve_inputs, run_batch
from audit_redactor.detectors.claude_augment import claude_api_key_available
from audit_redactor.pipeline import redact_file


@click.group()
@click.version_option(version=__version__)
def main() -> None:
    """Redact sensitive data from documents before sharing with auditors."""


@main.command()
@click.argument("input_spec", type=str)
@click.argument("output_path", type=click.Path(path_type=Path))
@click.option(
    "--offline",
    is_flag=True,
    default=False,
    help="Disable all network calls; rely solely on the local deterministic + ML layers.",
)
def redact(input_spec: str, output_path: Path, offline: bool) -> None:
    """Redact INPUT_SPEC and write the result to OUTPUT_PATH.

    INPUT_SPEC may be a single file, a directory (recursed), or a glob
    pattern (e.g. "docs/**/*.pdf"). For a directory or glob, OUTPUT_PATH is
    treated as a directory and the input's relative structure is mirrored
    into it. Original files are never modified.

    Batch runs never stop on a single file's error -- every matched file is
    attempted, and a summary of successes/failures is printed at the end.
    """
    try:
        resolved = resolve_inputs(input_spec)
    except FileNotFoundError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)

    if not resolved.files:
        click.echo(f"error: no files matched '{input_spec}'", err=True)
        sys.exit(1)

    # Same condition claude_augment.run_claude_augmentation gates on -- surfaced
    # here too so the user sees it once, up front, regardless of single-file or
    # batch mode, rather than discovering it only after redaction is done.
    if offline or not claude_api_key_available():
        click.secho(
            "⚠️  WARNING: running with local-only detection (no Claude "
            "augmentation pass) -- either --offline was set or no Claude API key "
            "is available. Redaction is more likely to be incomplete in this mode. "
            "Always review redacted output before sharing it; this applies doubly here.",
            err=True,
            fg="yellow",
            bold=True,
        )

    # Single-file mode: OUTPUT_PATH is the exact destination, unless it's
    # already an existing directory (then behave like batch mode into it).
    if not resolved.is_batch and not output_path.is_dir():
        try:
            actual = redact_file(resolved.files[0], output_path, offline)
        except Exception as exc:  # noqa: BLE001 - surfaced to the user as a CLI error
            click.echo(f"error: {exc}", err=True)
            sys.exit(1)
        click.echo(f"redacted: {resolved.files[0]} -> {actual}")
        return

    result = run_batch(resolved, output_path, offline)

    click.echo(f"\n{len(result.succeeded)}/{result.total} files redacted successfully.")
    if result.failed:
        click.echo(f"{len(result.failed)}/{result.total} files failed:")
        for path, reason in result.failed:
            click.echo(f"  {path}: {reason}")
        sys.exit(1)


if __name__ == "__main__":
    main()
