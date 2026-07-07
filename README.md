# audit-redactor

Hybrid, auditable tool that redacts sensitive data (AWS account numbers, AWS
access key IDs, person names, usernames/emails, phone numbers, client company
names, URLs) from documents before they're shared with auditors. Dates and
times are preserved on purpose — see below. See `PLAN.md` for the full design
and build phases.

**Originals are never modified.** Every run reads from the input path and
writes to a separate output path.

## Development setup

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
playwright install chromium
```

## Usage

```bash
# Single file
audit-redactor redact input.pdf output.pdf

# Directory (recursed) or glob pattern -- OUTPUT_PATH is treated as a
# directory and the input's relative structure is mirrored into it
audit-redactor redact ./docs ./redacted-docs
audit-redactor redact "./docs/**/*.pdf" ./redacted-docs

# Disable the Claude augmentation pass entirely (see below)
audit-redactor redact input.pdf output.pdf --offline
```

Batch runs never stop on a single file's error — every matched file is
attempted, and a summary of successes/failures is printed at the end.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Fatal — bad input path, no files matched, or (in batch mode) every file failed |
| `2` | Partial — batch mode only: at least one file succeeded and at least one failed (check the printed summary for which) |

### Claude augmentation (on by default)

After the local, deterministic pass (regex + a curated company-name list),
the tool sends the *already-redacted* text to Claude and asks it to find any
person or company names that were missed — see PLAN.md 2.8 for the full
detection-pipeline design. This step is strictly additive: the document is
already materially redacted before it ever runs, so a missing API key, a
network failure, or `--offline` never blocks redaction, only reduces recall.

- Requires `ANTHROPIC_API_KEY` in the environment. Without it (or with
  `--offline`), the tool runs local-only and prints a bold warning saying so.
- Default model is `claude-sonnet-5`, chosen for cost given this is a
  bulk/per-document extraction task, not Opus's usual default — not yet
  configurable via a CLI flag.
- **Always review redacted output before sharing it — doubly so when running
  local-only**, since local-only mode is more likely to miss things.

## What gets redacted, and how

| Data type | Detection | Redaction method |
|---|---|---|
| AWS account numbers | Regex | Mask all but last 4 digits |
| AWS access key IDs (AKIA/ASIA/etc.) | Regex | Mask all but last 4 characters |
| Phone numbers | Regex | Redact all digits completely |
| Emails / usernames | Regex | Full redaction |
| Platform usernames identified from a profile/repo URL (e.g. `github.com/<user>`) | Cross-reference — see PLAN.md 2.3 | Full redaction |
| URLs | Regex | Redact entire URL incl. scheme |
| Person names | Curated regex/company-list pass + Claude augmentation | Obscure all but first 4 characters |
| Client company names | Curated list (web-search-confirmed) + Claude augmentation | Full redaction |

**Dates and times are never redacted, on purpose** — knowing *when* evidence
is from matters for auditability. A date/time shape (`2026-07-06`, `17.55.28`,
an AWS CloudTrail export's `20260516T1805Z`) is recognized by checking its
year/month/day/etc. components against plausible ranges, and the phone-number
detector skips anything that overlaps one.

**Images (PNG/JPEG, and PDF pages that are just a raster image with no real
text layer) are an exception**: every entity type redacts the *entire* OCR
word(s) a match overlaps rather than doing the partial masking above.
Tesseract's word bounding box is an estimate that can be measurably wrong on
low-contrast source images, and slicing it by character index for a "last 4
digits" reveal risked leaving a still-legible fragment behind — see PLAN.md
2.3 for how this was verified.

| Format | Handling |
|---|---|
| PDF | Native text redacted via PyMuPDF `apply_redactions()` (true deletion, not an overlay). Pages with no real text layer — a scanned or screenshotted page — are detected automatically and redacted via OCR instead, then the page is replaced with the redacted raster. Hyperlink URIs are checked too: a link whose target leaks sensitive data (not just being a URL) is deleted outright. |
| PNG / JPEG | OCR (Tesseract) → pixel-level black-box overwrite → re-encoded fresh (no metadata, no layers). |
| Markdown / HTML | Redacted source, then rendered to PDF via headless Chromium (audit-tool consistency; some tools reject HTML/Markdown uploads). Outbound network requests during rendering are blocked. |
| JSON | Structural tree walk, redacts string leaf values only, re-serializes as valid JSON. **Does not get the Claude augmentation pass** — it runs per string leaf, and one Claude call per leaf doesn't scale or have document-level context. |

Filenames are redacted too (basename only, not parent directories) using the
same regex/company-list detectors, applied automatically regardless of format.

## Known limitations

- **OCR can miss text.** Very low-contrast text, or text small/dense enough
  for Tesseract to mis-segment into garbled fragments, can go completely
  undetected even though the tool's own preprocessing (contrast enhancement,
  upscaling) is applied. Confirmed against a real screenshot where a small
  UI badge OCR'd into nonsense instead of the digits it actually contained.
- **JSON gets no Claude augmentation** (see table above) — only the local
  regex/company-list pass applies.
- **Date/time protection isn't a full date parser.** It only recognizes the
  ISO-ish and common separator-based shapes described above, validated by
  plausible year/month/day/etc. ranges rather than a real calendar parser —
  a genuinely unusual date format not covered by those shapes could still be
  misread as a phone number. Given the shapes it does cover, this is
  intentionally biased toward preserving legibility over redacting an
  ambiguous digit run.
- **Local NER (`ab-ai/pii_model`) is not implemented.** An earlier design
  included a local NER model between the regex pass and Claude augmentation;
  it was dropped as a possible future extension, not near-term work — see
  PLAN.md 2.8 for why (mainly: multi-gigabyte dependency for a detector
  Claude's own review already covers).

## Docker

```bash
docker build -t audit-redactor .
docker run --rm -v "$PWD:/data" audit-redactor redact /data/input.pdf /data/output.pdf
```

Pass `ANTHROPIC_API_KEY` through if you want Claude augmentation inside the
container: `docker run --rm -e ANTHROPIC_API_KEY -v "$PWD:/data" ...`.

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
