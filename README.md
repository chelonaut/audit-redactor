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
