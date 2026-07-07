# audit-redactor

Hybrid, auditable tool that redacts sensitive data (AWS account numbers, person
names, usernames/emails, phone numbers, client company names, URLs) from
documents before they're shared with auditors. See `PLAN.md` for the full
design and build phases.

## Development setup

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
playwright install chromium
```

## Usage

```bash
audit-redactor redact input.pdf output.pdf
audit-redactor redact input.pdf output.pdf --offline
```

## Docker

```bash
docker build -t audit-redactor .
docker run --rm -v "$PWD:/data" audit-redactor redact /data/input.pdf /data/output.pdf
```

### Keeping the Playwright version pin in sync

`pyproject.toml`'s `playwright==X.Y.Z` dependency and the Dockerfile's
`FROM mcr.microsoft.com/playwright/python:vX.Y.Z-noble` base image tag **must
always match exactly** — the Docker image's pre-installed Chromium build is
tied to that specific Python package version, and a mismatch causes
Playwright to fail at runtime. Before bumping either one, confirm the target
version is actually published on PyPI (`pip index versions playwright`) —
the Docker base image tag has been observed to exist before the matching
PyPI package was published, which is what caused this to drift out of sync
once already.
