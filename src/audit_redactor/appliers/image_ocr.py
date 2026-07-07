"""Shared OCR-based image redaction core (PLAN.md 2.4, 2.5).

Used by both the standalone image handler (PNG/JPEG, build phase 5) and the
PDF handler's scanned-page path (a PDF page with no real text layer, only an
embedded raster image -- found via a real end-to-end validation run against
a genuinely scanned/screenshotted PDF, where the page's own text extraction
returned almost nothing and the account ID visible in the image itself sailed
through completely unredacted). Both ultimately need to OCR a raster image,
detect sensitive text via the same detector set as every other format, and
redact pixels in place -- this is the one place that logic lives so the two
callers can't drift out of sync on what "safely redacted" means.

Detects sensitive text via Tesseract OCR (`pytesseract`), then performs true
pixel-level redaction: solid rectangles are drawn directly on the pixel
buffer (never a transparent overlay), and the result is rebuilt from a raw
pixel buffer via `Image.frombytes` before saving -- never by resaving the
loaded `Image` object -- so its `.info` dict starts empty and no EXIF/IPTC/
XMP/ICC/PNG-text metadata (including an embedded EXIF thumbnail) can survive
into the output. See PLAN.md 2.5 for why this is sufficient without any
external metadata-stripping tool.

OCR runs against a *separate*, preprocessed copy of the image (grayscale +
autocontrast + upscale) purely to improve detection recall on low-contrast
text -- e.g. a screenshot's dark account-info header, where foreground and
background differ by only a few grey levels. Word bounding boxes are scaled
back into the original image's pixel coordinates before anything is drawn on
the real output buffer, so redaction precision matches the image's actual
resolution regardless of the OCR upscale factor.

Tesseract only reports word-level bounding boxes, not per-character ones, and
unlike the PDF handler's native text path (phase 4, which redacts real glyph
objects with exact positions), that bbox is an estimate that can be
measurably wrong -- verified empirically against a simulated low-contrast
AWS-console-style account ID, where attempting to proportionally slice a
word's bbox by character index (to implement the partial-mask entity types'
"keep last 4 digits" rule from PLAN.md 2.3) left a partially-redacted, still-
legible fragment of a digit that should have been fully hidden, even after
adding a generous safety pad. Given this project's standing priority that
missed PII is far costlier than over-redaction, OCR-based redaction
deliberately does not attempt sub-word partial masking at all: every entity
type redacts the *entire* OCR word (or words) its span overlaps. This
sacrifices the "last 4 digits stay visible" audit convenience specifically
for OCR'd content, in exchange for eliminating the partial-glyph leak risk
entirely.

Known limitation: text whose foreground/background contrast is extremely
low (roughly under ~15 grey levels apart in informal testing), or that is
small/tightly kerned enough for Tesseract to mis-segment into garbled
fragments (confirmed via a real screenshot with small badge text that OCR'd
into nonsense rather than the actual digits), can defeat OCR entirely
despite the contrast-enhancement preprocessing, and won't be detected or
redacted. Such text isn't visibly leaking to a casual viewer, but remains
programmatically recoverable by anyone who applies similar contrast
enhancement or re-runs OCR themselves -- flagged here rather than silently
claimed as covered.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytesseract
from PIL import Image, ImageDraw, ImageOps

from audit_redactor.detectors import detect_text_with_claude
from audit_redactor.detectors.base import Detector, Span

_OCR_UPSCALE = 3
_AUTOCONTRAST_CUTOFF = 1
_WORD_LEVEL = 5
_REDACT_FILL = (0, 0, 0)
_HORIZONTAL_PAD_FACTOR = 0.75  # fraction of word height, per side
_VERTICAL_PAD_PX = 1.5


class ImageRedactionVerificationError(RuntimeError):
    """Raised when a matched span is still OCR-recoverable after redaction."""


@dataclass(frozen=True)
class _Word:
    text: str
    left: float
    top: float
    width: float
    height: float


@dataclass(frozen=True)
class _WordSpan:
    start: int
    end: int
    word: _Word


def _ocr_words(image: Image.Image) -> list[_Word]:
    """Run Tesseract on a contrast-enhanced, upscaled copy of `image` and
    return word-level results with bboxes scaled back to `image`'s own
    pixel coordinates.
    """
    gray = ImageOps.autocontrast(image.convert("L"), cutoff=_AUTOCONTRAST_CUTOFF)
    w, h = gray.size
    upscaled = gray.resize((w * _OCR_UPSCALE, h * _OCR_UPSCALE), Image.LANCZOS)

    data = pytesseract.image_to_data(upscaled, output_type=pytesseract.Output.DICT)
    words: list[_Word] = []
    for i in range(len(data["text"])):
        if data["level"][i] != _WORD_LEVEL:
            continue
        text = data["text"][i]
        if not text.strip():
            continue
        words.append(
            _Word(
                text=text,
                left=data["left"][i] / _OCR_UPSCALE,
                top=data["top"][i] / _OCR_UPSCALE,
                width=data["width"][i] / _OCR_UPSCALE,
                height=data["height"][i] / _OCR_UPSCALE,
            )
        )
    return words


def reconstruct_text_and_word_map(image: Image.Image) -> tuple[str, list[_WordSpan]]:
    """Build the image's plain text (words joined by spaces) plus a parallel
    list mapping each text offset range back to the OCR word that produced
    it, mirroring the PDF handler's native char-to-bbox map at word
    granularity, since that's the finest resolution Tesseract exposes.
    """
    words = _ocr_words(image)
    pieces: list[str] = []
    word_spans: list[_WordSpan] = []
    offset = 0
    for i, word in enumerate(words):
        if i > 0:
            pieces.append(" ")
            offset += 1
        start = offset
        pieces.append(word.text)
        offset += len(word.text)
        word_spans.append(_WordSpan(start=start, end=offset, word=word))
    return "".join(pieces), word_spans


def _rects_for_span(span: Span, word_spans: list[_WordSpan]) -> list[tuple[float, float, float, float]]:
    """Every OCR word overlapping `span` is redacted in full -- see the
    module docstring for why sub-word partial masking isn't attempted here.
    """
    rects = []
    for ws in word_spans:
        if ws.start >= span.end or ws.end <= span.start:
            continue
        word = ws.word
        rects.append((word.left, word.top, word.left + word.width, word.top + word.height))
    return rects


def _pad_and_clamp(
    rect: tuple[float, float, float, float], size: tuple[int, int]
) -> tuple[float, float, float, float]:
    """Pad a redact rect before drawing, then clamp to the image bounds.

    Tesseract's *whole-word* bbox estimate itself (not just sub-word
    slicing, which is no longer attempted -- see module docstring) can be
    off horizontally by more than a small fixed margin on low-contrast
    source images: verified empirically against a simulated low-contrast
    AWS-console-style account ID, where the reported left edge was off by
    roughly a third of the text's own height. That imprecision is specific
    to horizontal glyph-edge detection, not row/line placement, which
    Tesseract locates reliably -- so the horizontal pad scales with word
    height (proportionate across font sizes) while the vertical pad stays a
    small fixed margin, to avoid bleeding into an adjacent line's text when
    lines are closely spaced (verified against a tight-line-spacing case).
    """
    x0, y0, x1, y1 = rect
    w, h = size
    h_pad = (y1 - y0) * _HORIZONTAL_PAD_FACTOR
    x0 = max(0.0, x0 - h_pad)
    y0 = max(0.0, y0 - _VERTICAL_PAD_PX)
    x1 = min(float(w), x1 + h_pad)
    y1 = min(float(h), y1 + _VERTICAL_PAD_PX)
    return (x0, y0, x1, y1)


def redact_pixels(image: Image.Image, spans: list[Span], word_spans: list[_WordSpan]) -> Image.Image:
    draw = ImageDraw.Draw(image)
    fill = _REDACT_FILL + (255,) if image.mode == "RGBA" else _REDACT_FILL
    for span in spans:
        for rect in _rects_for_span(span, word_spans):
            draw.rectangle(_pad_and_clamp(rect, image.size), fill=fill)
    return image


def fresh_copy(image: Image.Image) -> Image.Image:
    """Rebuild `image` from a raw pixel buffer so the result has an empty
    `.info` dict -- see module docstring for why this alone is sufficient
    to strip all metadata.
    """
    return Image.frombytes(image.mode, image.size, image.tobytes())


def verify_redacted(image: Image.Image, spans: list[Span]) -> None:
    """Fail loudly if any matched span text is still OCR-recoverable from
    the redacted output, guarding against rect-computation bugs (PLAN.md
    2.4's verification-pass philosophy, applied to OCR'd content).
    """
    text, _ = reconstruct_text_and_word_map(image)
    for span in spans:
        if span.text in text:
            raise ImageRedactionVerificationError(
                f"redaction verification failed: {span.entity_type} span "
                f"{span.text!r} still recoverable via OCR after redaction"
            )


def ocr_redact_image(
    image: Image.Image, offline: bool, identity_detector: Detector | None = None
) -> tuple[Image.Image, list[Span]]:
    """Full OCR-detect-redact-verify pipeline for a single raster image.

    `image` must already be in a mode `ImageDraw`/`tobytes` can round-trip
    (the standalone image handler normalizes to RGB/RGBA before calling
    this; the PDF handler's scanned-page path renders pages directly to
    RGB). Returns the redacted, metadata-free image plus the spans that were
    found, for the caller to embed however its own format requires.

    `identity_detector` lets a caller merge in usernames discovered from
    context this function can't see itself -- e.g. the PDF handler's
    scanned-page path passing a `KnownIdentityDetector` built from usernames
    discovered elsewhere in the same document (platform_identity.py). Passed
    through to `detect_text_with_claude` rather than merged in afterwards --
    see that function's docstring for why the ordering matters. The
    standalone image handler has no such document-level context, so it never
    passes one.
    """
    text, word_spans = reconstruct_text_and_word_map(image)
    spans = detect_text_with_claude(text, offline, identity_detector=identity_detector)
    redacted = redact_pixels(image, spans, word_spans)
    fresh = fresh_copy(redacted)
    verify_redacted(fresh, spans)
    return fresh, spans
