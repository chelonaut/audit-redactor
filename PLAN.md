# Document Redaction Tool — Build Plan

## 1. Purpose

A hybrid, auditable tool that redacts sensitive data (AWS account numbers, person names,
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
| Markdown | Regex/NER text substitution → `[REDACTED]`, then **render to PDF by default** via headless Chromium (same rationale as HTML — audit-tool consistency) |
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

**Images are an exception to the partial-mask methods above (AWS/phone/person name):** phase 5
found, empirically, that Tesseract's word-level bbox is an *estimate* that can be off by more than a
character's width on low-contrast source images (e.g. a simulated low-contrast AWS-console-style
account ID) — attempting to proportionally slice a word's bbox by character index to implement
"keep last 4 digits" left a partially-redacted, still-legible digit fragment even after a generous
safety pad. Given this project's standing priority that missed PII is far costlier than
over-redaction, the image handler always redacts the *entire* OCR word(s) a match overlaps,
sacrificing the partial-reveal convenience specifically for screenshots/images. PDF, Markdown, and
JSON are unaffected — they have exact character positions (real glyph objects or literal string
offsets), not an OCR estimate, so the partial-mask methods above still apply there.

### 2.4 True redaction requirements (non-negotiable, from original constraints)

- **PDF:** use PyMuPDF `apply_redactions()` to delete underlying content, never an overlay rectangle.
  After redacting, do a **full rewrite** (`garbage=4, deflate=True, clean=True`) — this is required
  because PDFs can carry incremental-save revision history; without a full flatten, pre-redaction
  content can still be recovered from an earlier revision even after "successful" redaction.
  Known caveat to test for: `apply_redactions()` may not fully clear shared XObject/Form streams —
  add a post-save verification pass (re-extract text/search for the redacted string) and fail loudly
  if any target string is still recoverable.
  - **Confirmed via phase 11's real end-to-end validation run, both now fixed:** (1) `apply_redactions()`
    only touches the page's visible content stream — a hyperlink's URI is a separate PDF object and can
    carry sensitive data (an AWS account ID embedded in a console URL) that never appears as blacked-out
    page text at all; any link whose URI contains a non-URL entity type is now deleted outright. (2) A
    page whose content is entirely a raster image with no real text layer (a "scanned"/screenshotted
    PDF) gives `apply_redactions()` nothing to act on — text extraction finds nothing, so detection finds
    zero spans, and the verification pass reports a false pass since it has no span text to check the
    raw bytes against. Such pages are now detected (negligible extractable text + at least one embedded
    image) and redacted via the same OCR pipeline the standalone image handler uses, then the page is
    replaced entirely with the redacted raster (overlaying a box on the existing image would leave the
    original unredacted bytes recoverable underneath).
- **Images (PNG/JPEG):** draw solid rectangles directly on the pixel buffer (Pillow `ImageDraw`),
  then re-encode as a brand-new file. No image ever has "layers" to begin with, but re-encoding
  fresh guarantees no auxiliary chunk (e.g. an EXIF thumbnail generated pre-redaction) survives.

### 2.5 Metadata & filename scrubbing (in scope, applies to every output regardless of file type)

- **PDF:** strip Info dictionary, XMP metadata, embedded attachments, JavaScript, form fields, and
  hidden OCG layers, in addition to the revision-flattening above. PyMuPDF's own API is the sole
  mechanism (see 2.4) — no external tool needed.
- **Images:** strip EXIF/IPTC/XMP/PNG text chunks, explicitly including any embedded EXIF thumbnail,
  by reconstructing the output image from a raw pixel buffer (`Image.frombytes(mode, size, ...)`)
  rather than resaving the loaded `Image` object. Verified empirically (phase 5) against a
  deliberately "polluted" JPEG/PNG carrying EXIF+GPS+embedded-thumbnail, IPTC, XMP, and an ICC
  profile: Pillow's encoders are opt-in, not copy-forward — they only emit a metadata
  segment/chunk if it's explicitly passed to `save()`. A pixel-only-sourced `Image` object has an
  empty `.info` dict, so there is nothing to carry forward and nothing for the encoder to
  (re-)embed. No external tool is required or used — a prior version of this plan called for a final
  `exiftool -all=` pass as a "belt-and-suspenders" safety net, but that was speculative and turned
  out to be unnecessary once tested: unlike PDF, an image file's on-disk bytes are wholly determined
  by what's passed to Pillow's encoder, so there's no comparable "hidden/miscellaneous location" for
  metadata to survive in.
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

### 2.7 HTML/Markdown → PDF pipeline

1. Redact the **source text** first:
   - HTML: text nodes via regex/NER substitution, plus strip `<script>` tags, HTML comments,
     `data-*` attributes, and meta tags (these can carry hidden PII or tracking IDs invisible in the
     rendered page).
   - Markdown: regex/NER substitution directly on the raw Markdown text (same detector set as every
     other format), *before* any HTML conversion.
2. Markdown only: convert the already-redacted Markdown to HTML (e.g. `markdown`/`mistune`) using a
   plain, minimal template — no external stylesheets or fonts that could phone out over the network.
3. Render the already-redacted HTML to PDF via a headless Chromium instance — **Playwright for
   Python**, using Microsoft's official `mcr.microsoft.com/playwright/python` base image (bundles
   all required Linux dependencies, avoids a mixed Node/Python container).
4. Run the standard PDF metadata-scrub pass on the output (Chrome embeds generator/timestamp
   metadata by default).
5. The intermediate redacted HTML/Markdown exists only in memory/temp and is never written to
   persistent output.

### 2.8 Detection architecture — local + Claude

**Principle:** detection and application are fully decoupled. Every detector (regex, Claude, and
any local NER model added later) produces the same output shape — `(matched text, entity type,
confidence, source)` — which feeds the one deterministic applier per file type. Adding a new
detector never touches the PDF/image/JSON/HTML redaction logic; it's just one more producer of the
same span list.

**Order of operations (local-first, for safety and graceful degradation):**

1. Regex core catches AWS numbers, phones, emails, URLs, and curated company names — applied
   immediately regardless of anything downstream.
2. **At this point, if no Claude API key is present or `--offline` is set, processing stops here.**
   The document is already materially redacted with the regex/company-list pass — Claude is
   strictly additive, never a dependency for baseline safety.
3. If a Claude API key is available: send the full (already partially-redacted) document text and
   ask Claude to return **only a compact JSON list of missed spans** — person/company names it
   believes the regex/company-list pass missed — never a full rewritten document. This keeps
   output tokens small and roughly constant regardless of document length.
4. **Grounding check:** validate every span Claude returns literally appears verbatim in the source
   text before redacting it (via a strict tool-call schema plus a literal, word-bounded substring
   search against the original text — Claude never reports character offsets itself, since that's
   arithmetic LLMs are unreliable at). Reject anything that doesn't match exactly — guards against
   hallucinated or paraphrased spans that wouldn't map to a real bounding box / JSON path / DOM node
   anyway.
5. Apply the additional spans through the same deterministic appliers as step 1.

**Local NER (deferred, possible future extension — not currently planned near-term):** an earlier
draft of this design included a local NER pass (`ab-ai/pii_model`, fine-tuned `bert-base-cased`)
between steps 1 and 2, using its per-token confidence as a threshold to decide between immediate
redaction and Claude-reviewed "hints." Dropped for now: `transformers`/`torch` added ~5.4GB to the
Docker image (an unpinned `torch` install defaults to the CUDA-enabled Linux wheel, useless for a
small CPU-inference model) and made the build unreliable over a slow network, for a detector this
project doesn't currently need — Claude's own recall on the reviewed text covers the same ground
without a multi-gigabyte dependency or an empirical-threshold-tuning exercise up front. Revisit only
if a real case shows the deterministic + Claude combination missing names Claude itself can't catch
(e.g. a genuinely offline-only deployment with no Claude access at all) — and if revisited, pin
`torch` to the CPU-only wheel index (`--extra-index-url https://download.pytorch.org/whl/cpu`).

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
                            ──── Markdown: redact source → convert to HTML → Playwright → PDF
      │
      ▼
regex core (AWS #s, phones, emails, URLs, curated company names)
   → redact immediately (highest confidence, always applied)
      │
      ▼
  ┌─── no API key / --offline ───────────────┐
  │                                            │
  ▼                                            ▼
apply filename + metadata scrub          Claude augmentation pass
      │                                   (full already-redacted text in,
      │                                    compact span-list tool call out)
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

(A local NER pass was drafted between the regex core and the offline/Claude branch above, but is
deferred — see 2.8's "Local NER" note.)

---

## 4. Build phases

1. **Repo & scaffolding** — repo already created (`chelonaut/audit-redactor`); add Dockerfile
   (Python base + Playwright/Chromium + Tesseract); CLI entrypoint skeleton.
2. **Regex core** — AWS account numbers, phone numbers, emails/usernames, URLs; curated company-name
   matcher; unit tests with synthetic fixtures for each pattern.
3. **Text-format handlers (simplest first)** — Markdown (regex substitution; PDF rendering deferred
   to phase 6 since it shares the HTML→PDF pipeline), JSON (tree walk + re-serialize). Validate JSON
   output stays parseable after redaction.
4. **PDF handler** — PyMuPDF extraction (word/bbox map) → `apply_redactions()` → metadata strip →
   full rewrite/flatten → post-save verification pass (confirm redacted strings are unrecoverable,
   including a specific check for shared XObject/Form-stream leakage).
5. **Image handler** — OCR (Tesseract) → bbox map → Pillow pixel overwrite → re-encode → metadata
   strip (EXIF/IPTC/XMP/text chunks, including embedded thumbnails).
6. **HTML/Markdown → PDF pipeline** — BeautifulSoup source redaction (HTML) or regex/NER redaction
   then Markdown→HTML conversion (Markdown) → Playwright headless render → PDF metadata scrub.
7. **Filename redaction module** — applies to every output regardless of type.
8. ~~**Local ML integration**~~ — deferred, possible future extension, not currently planned
   near-term (see 2.8's "Local NER" note). Skipped in favor of going straight to phase 9.
9. **Claude API integration** — structured-output span-list contract, grounding/verbatim validation,
   `--offline` flag wiring. (Message Batches API path for bulk runs not yet built — still a
   candidate follow-up for the "redact 1000 documents overnight" scenario, not implemented yet.)
10. **CLI & Docker packaging** — single entrypoint, works identically on Mac and in CI, exit codes
    for warn-vs-fail (e.g. PDF verification pass failure).
11. **Test suite & validation pass** — unit coverage per format is solid (106 tests, synthetic
    content built inline rather than static fixture files). The real end-to-end run against
    `~/Downloads/Example` has happened once and found two genuine, now-fixed bugs neither the unit
    suite nor pytest's own import order caught: a circular import that crashed the actual CLI
    entrypoint outright, and the two PDF gaps documented in 2.4 (sensitive link URIs, image-only
    "scanned" pages). Still open from that same run, not yet fixed: OCR can fail to read
    small/tightly-kerned UI text even when contrast is otherwise fine (confirmed, not just
    theorized — see 2.3's image-handler note), and filename redaction can over-match a date/time
    as a phone number (benign given the recall-over-precision bias, just worth knowing). Re-run
    this validation pass again after any detector or PDF/image-handling change, not just once.
12. **Documentation** — usage, flags, what's redacted vs. not, and the two open questions below
    resolved and recorded.

---

## 5. Open questions

1. ~~Should Markdown also get the HTML-style "render to PDF" treatment?~~ **Resolved: yes.** Markdown
   gets the same redact-source → render-to-PDF treatment as HTML, for audit-tool consistency (see
   §2.2, §2.7).
2. ~~Confidence threshold value(s) for ab-ai/pii_model~~ **Moot for now:** the local NER phase this
   applied to is deferred (see 2.8) — revisit only if that phase is picked back up.

## 6. Non-goals
- This tool does not replace the existing `plugins/chelonaut/skills/redact` Claude Code skill
  outright (that decision is the user's to make once this tool is working) — it is a separate,
  faster-by-design alternative.
- No web search or external network calls during the redaction pass itself outside the bounded
  Claude augmentation step — company-list maintenance is a separate, offline-from-redaction activity.
