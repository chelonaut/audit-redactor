# Document Redaction Tool — Build Plan

## 1. Purpose

A deterministic, auditable tool that redacts sensitive data (AWS account numbers, person names,
usernames/emails, phone numbers, client company names, URLs) from documents before they're shared
with auditors. Runs as a Dockerized Python CLI, portable between a local Mac and CI/CD.

**Note on scope:** this is a standalone pipeline, distinct from the existing Claude Code skill at
`plugins/chelonaut/skills/redact/SKILL.md` in the `chelonaut/claude-skills` repo. That skill redacts
by having Claude reason over file contents live, in-session, with no local ML and no web search (to
avoid leaking content mid-redaction). This new tool takes a different approach — a deterministic
core that runs first and does most of the work locally, with Claude used only as an optional,
bounded, post-hoc augmentation step — specifically to solve the old skill's speed/token-cost
problem. **This tool lives in its own repo, `chelonaut/audit-redactor`**, separate from the skills
marketplace repo.

---

## 2. Key Design Decisions

### 2.1 Deployment & residency
- Dockerized Python, runs identically on local Mac (M1, 16GB) and in CI/CD.
- Cloud (Claude API) redaction augmentation is **on by default**; a `--offline` flag disables all
  network calls and relies solely on the local deterministic + ML layers.
- **Originals are never modified.** All processing reads from the input path and writes to a
  separate output path; nothing is written back over the source file.

### 2.2 Input formats & required transforms

| Format | Handling |
|---|---|
| PDF | True redaction (delete underlying content objects, not overlay) |
| PNG / JPEG | Pixel-level black-box overwrite, re-encoded fresh (no layers) |
| Markdown | Regex/NER text substitution → `[REDACTED]`, output stays Markdown |
| JSON | Structural walk + redact string leaf values, re-serialize as valid JSON |
| HTML | Redact source, then **render to PDF by default** via headless Chromium (some audit tools reject HTML uploads) |

### 2.3 Redaction targets & methods

| Data type | Detection | Redaction method |
|---|---|---|
| AWS account numbers | Regex | Mask all but last 4 digits |
| Phone numbers | Regex | Redact all digits completely |
| Emails / usernames (GitHub, Jira, Notion, etc.) | Regex | Full redaction |
| URLs | Regex | Redact entire URL incl. scheme |
| Person names | Local NER (ab-ai/pii_model) + Claude augmentation | Obscure all but first 4 characters |
| Client company names | Curated list (web-search-confirmed) + Claude augmentation | Full redaction |

### 2.4 True redaction requirements (non-negotiable, from original constraints)

- **PDF:** use PyMuPDF `apply_redactions()` to delete underlying content, never an overlay rectangle.
  After redacting, do a **full rewrite** (`garbage=4, deflate=True, clean=True`) — this is required
  because PDFs can carry incremental-save revision history; without a full flatten, pre-redaction
  content can still be recovered from an earlier revision even after "successful" redaction.
  Known caveat to test for: `apply_redactions()` may not fully clear shared XObject/Form streams —
  add a post-save verification pass (re-extract text/search for the redacted string) and fail loudly
  if any target string is still recoverable.
- **Images (PNG/JPEG):** draw solid rectangles directly on the pixel buffer (Pillow `ImageDraw`),
  then re-encode as a brand-new file. No image ever has "layers" to begin with, but re-encoding
  fresh guarantees no auxiliary chunk (e.g. an EXIF thumbnail generated pre-redaction) survives.

### 2.5 Metadata & filename scrubbing (in scope, applies to every output regardless of file type)

- **PDF:** strip Info dictionary, XMP metadata, embedded attachments, JavaScript, form fields, and
  hidden OCG layers, in addition to the revision-flattening above.
- **Images:** strip EXIF/IPTC/XMP/PNG text chunks, explicitly including any embedded EXIF thumbnail.
- **All formats:** run `exiftool -all=` as a final belt-and-suspenders pass on top of
  PyMuPDF/Pillow's own stripping, since it catches metadata blocks those libraries sometimes miss.
- **Filenames:** run the same detector set (regex + curated list) against the filename string itself
  and produce a safe output name — a file's name is as much a leak vector as its contents (e.g. an
  AWS account number embedded directly in a filename).

### 2.6 JSON structural redaction

- Parse with `json.loads`, recursively walk the tree, apply detectors **only to string leaf
  values**, and re-serialize with `json.dumps(indent=2)`. This guarantees valid JSON output by
  construction — never regex the raw file text directly.
- Known-sensitive **keys** (e.g. `accountId`) are redacted by key name regardless of value type, as
  a supplementary check.
- Numeric PII values are left untouched by default (converting a JSON number to a redacted string
  would silently change its type, which could break an auditor's schema validation) — flagged as an
  explicit decision, revisit if a real document surfaces numeric PII that needs handling.

### 2.7 HTML → PDF pipeline

1. Redact the HTML **source** first: text nodes via regex/NER substitution, plus strip
   `<script>` tags, HTML comments, `data-*` attributes, and meta tags (these can carry hidden PII or
   tracking IDs invisible in the rendered page).
2. Render the already-redacted HTML to PDF via a headless Chromium instance — **Playwright for
   Python**, using Microsoft's official `mcr.microsoft.com/playwright/python` base image (bundles
   all required Linux dependencies, avoids a mixed Node/Python container).
3. Run the standard PDF metadata-scrub pass on the output (Chrome embeds generator/timestamp
   metadata by default).
4. The intermediate redacted HTML exists only in memory/temp and is never written to persistent
   output.

Markdown is **not** included in this HTML→PDF conversion by default (only HTML was requested) —
flagged as an open question below.

### 2.8 Detection architecture — hybrid local + Claude

**Principle:** detection and application are fully decoupled. Every detector (regex, local NER
model, Claude) produces the same output shape — `(matched text, entity type, confidence, source)` —
which feeds the one deterministic applier per file type. Adding Claude never touches the PDF/image/
JSON/HTML redaction logic; it's just one more producer of the same span list.

**Order of operations (local-first, for safety and graceful degradation):**

1. Regex core catches AWS numbers, phones, emails, URLs, and curated company names — applied
   immediately regardless of anything downstream.
2. **ab-ai/pii_model** (fine-tuned `bert-base-cased`, 33 PII entity types, Apache 2.0) runs as a
   local NER pass for person/company names, using its per-token confidence score as a threshold:
   - High-confidence hits (tune threshold empirically — do not trust the model's own 95-97%
     self-reported number, which is in-distribution on its own synthetic training data split, not
     independently verified) are redacted immediately, no Claude round-trip needed.
   - Low/medium-confidence hits become **hints**, not decisions.
3. **At this point, if no Claude API key is present or `--offline` is set, processing stops here.**
   The document is already materially redacted — Claude is strictly additive, never a dependency for
   baseline safety.
4. If a Claude API key is available: send the full (already partially-redacted) document text, with
   the local model's low-confidence hints marked inline, and ask Claude to return **only a compact
   JSON list of corrections and additions** — spans it believes were missed, or hinted spans it
   disagrees with — never a full rewritten document. This keeps output tokens small and roughly
   constant regardless of document length, while not capping recall at whatever the local model
   happened to propose (the failure mode of a candidate-only design: a true local miss is invisible
   to Claude if Claude only ever reviews pre-selected candidates).
5. **Grounding check:** validate every span Claude returns literally appears verbatim in the source
   text before redacting it (via structured output / strict JSON schema). Reject anything that
   doesn't match exactly — guards against hallucinated or paraphrased spans that wouldn't map to a
   real bounding box / JSON path / DOM node anyway.
6. Apply the corrected/additional spans through the same deterministic appliers as step 1.

**Why ab-ai/pii_model despite its lack of independent backing:** its role in this design is
downgraded from "sole detector" (where its unverified numbers were the whole risk) to "confidence
pre-filter and hint generator that Claude can override" — its weaknesses matter far less when
Claude is reviewing the underlying text anyway. It only becomes the sole line of defense in
`--offline` mode, where the accuracy trade-off is already understood and explicit.

### 2.9 Cost & throughput levers
- Claude Message Batches API (50% cost discount, async) for bulk/offline runs — e.g. the "redact
  1000 documents overnight before sending to auditors" scenario doesn't need real-time responses.
- Rough cost estimate from research: ~$5–14 per 1000 documents at Haiku/Sonnet pricing for the
  augmentation pass (full document text in, compact JSON out) — cheap enough that Option 3's
  full-document-review design is affordable by default; only reconsider a cheaper
  candidate-only-to-Claude mode if a real pilot shows otherwise.

### 2.10 Client company name list
- Curated list, confirmed via web search when adding new names, maintained as a standalone file
  (separate from redacted-document processing — **never web-search during redaction itself**, to
  avoid the existing skill's constraint of leaking content mid-run via search queries).

---

## 3. Pipeline flow (per document)

```
input file (untouched)
      │
      ▼
format-specific extractor  ──── PDF: PyMuPDF word/bbox map
                            ──── Image: OCR (Tesseract) word/bbox map
                            ──── JSON: recursive tree walk (string leaves)
                            ──── HTML: redact source → Playwright → PDF
                            ──── Markdown: raw text
      │
      ▼
regex core (AWS #s, phones, emails, URLs, curated company names)
   → redact immediately (highest confidence, always applied)
      │
      ▼
ab-ai/pii_model NER pass (person/company names)
   → high confidence: redact immediately
   → low/medium confidence: mark as hint, carry forward
      │
      ▼
  ┌─── no API key / --offline ───────────────┐
  │                                            │
  ▼                                            ▼
apply filename + metadata scrub          Claude augmentation pass
      │                                   (full text + hints in,
      │                                    compact span-list JSON out)
      │                                            │
      │                                    grounding check
      │                                    (reject non-verbatim spans)
      │                                            │
      │                                    apply additional spans
      │                                            │
      └──────────────────► apply filename + metadata scrub
                                    │
                                    ▼
                            final redacted output
                         (original file untouched)
```

---

## 4. Build phases

1. **Repo & scaffolding** — repo already created (`chelonaut/audit-redactor`); add Dockerfile
   (Python base + Playwright/Chromium + Tesseract + exiftool + `transformers`); CLI entrypoint
   skeleton.
2. **Regex core** — AWS account numbers, phone numbers, emails/usernames, URLs; curated company-name
   matcher; unit tests with synthetic fixtures for each pattern.
3. **Text-format handlers (simplest first)** — Markdown (regex substitution), JSON (tree walk +
   re-serialize). Validate JSON output stays parseable after redaction.
4. **PDF handler** — PyMuPDF extraction (word/bbox map) → `apply_redactions()` → metadata strip →
   full rewrite/flatten → post-save verification pass (confirm redacted strings are unrecoverable,
   including a specific check for shared XObject/Form-stream leakage).
5. **Image handler** — OCR (Tesseract) → bbox map → Pillow pixel overwrite → re-encode → metadata
   strip (EXIF/IPTC/XMP/text chunks, including embedded thumbnails).
6. **HTML → PDF pipeline** — BeautifulSoup source redaction → Playwright headless render → PDF
   metadata scrub.
7. **Filename redaction module** — applies to every output regardless of type.
8. **Local ML integration** — load `ab-ai/pii_model` via `transformers`, wire up confidence
   thresholding, **validate its actual precision/recall against a held-out sample of realistic
   (synthetic, not real customer) documents** before trusting any threshold value — do not rely on
   the model card's self-reported numbers.
9. **Claude API integration** — structured-output span-list contract, grounding/verbatim validation,
   `--offline` flag wiring, Message Batches API path for bulk runs.
10. **CLI & Docker packaging** — single entrypoint, works identically on Mac and in CI, exit codes
    for warn-vs-fail (e.g. PDF verification pass failure).
11. **Test suite & validation pass** — synthetic fixture documents per format covering every
    redaction target; end-to-end run against the real `~/Downloads/Example` sample folder (or
    similar) to sanity-check before any production use.
12. **Documentation** — usage, flags, what's redacted vs. not, and the two open questions below
    resolved and recorded.

---

## 5. Open questions to resolve before / during implementation

1. Should Markdown also get the HTML-style "render to PDF" treatment for audit-tool consistency, or
   stay Markdown → Markdown? (Currently scoped to HTML only.)
2. Confidence threshold value(s) for ab-ai/pii_model — to be set empirically in Phase 8, not
   guessed up front.

## 6. Non-goals
- This tool does not replace the existing `plugins/chelonaut/skills/redact` Claude Code skill
  outright (that decision is the user's to make once this tool is working) — it is a separate,
  faster-by-design alternative.
- No web search or external network calls during the redaction pass itself outside the bounded
  Claude augmentation step — company-list maintenance is a separate, offline-from-redaction activity.
