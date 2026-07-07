"""Image handler (PLAN.md 2.2, 2.4, 2.5, build phase 5).

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
unlike the PDF handler (phase 4, which redacts real glyph objects with exact
positions), that bbox is an estimate that can be measurably wrong -- verified
empirically against a simulated low-contrast AWS-console-style account ID,
where attempting to proportionally slice a word's bbox by character index
(to implement the partial-mask entity types' "keep last 4 digits" rule from
PLAN.md 2.3) left a partially-redacted, still-legible fragment of a digit
that should have been fully hidden, even after adding a generous safety pad.
Given this project's standing priority that missed PII is far costlier than
over-redaction, the image handler deliberately does not attempt sub-word
partial masking at all: every entity type redacts the *entire* OCR word (or
words) its span overlaps. This sacrifices the "last 4 digits stay visible"
audit convenience specifically for screenshots, in exchange for eliminating
the partial-glyph leak risk entirely.

Known limitation: text whose foreground/background contrast is extremely
low (roughly under ~15 grey levels apart in informal testing) can defeat
OCR entirely despite the contrast-enhancement preprocessing, and won't be
detected or redacted. Such text isn't visibly leaking to a casual viewer,
but remains programmatically recoverable by anyone who applies similar
contrast enhancement -- flagged here rather than silently claimed as
covered.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytesseract
from PIL import Image, ImageDraw, ImageOps

from audit_redactor.detectors import detect_text_with_claude
from audit_redactor.detectors.base import Span
from audit_redactor.pipeline import register

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


def _reconstruct_text_and_word_map(image: Image.Image) -> tuple[str, list[_WordSpan]]:
    """Build the image's plain text (words joined by spaces) plus a parallel
    list mapping each text offset range back to the OCR word that produced
    it, mirroring the PDF handler's char-to-bbox map (phase 4) at word
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


def _redact_pixels(image: Image.Image, spans: list[Span], word_spans: list[_WordSpan]) -> Image.Image:
    draw = ImageDraw.Draw(image)
    fill = _REDACT_FILL + (255,) if image.mode == "RGBA" else _REDACT_FILL
    for span in spans:
        for rect in _rects_for_span(span, word_spans):
            draw.rectangle(_pad_and_clamp(rect, image.size), fill=fill)
    return image


def _fresh_copy(image: Image.Image) -> Image.Image:
    """Rebuild `image` from a raw pixel buffer so the result has an empty
    `.info` dict -- see module docstring for why this alone is sufficient
    to strip all metadata.
    """
    return Image.frombytes(image.mode, image.size, image.tobytes())


def _verify_redacted(image: Image.Image, spans: list[Span]) -> None:
    """Fail loudly if any matched span text is still OCR-recoverable from
    the redacted output, guarding against rect-computation bugs (PLAN.md
    2.4's verification-pass philosophy, applied to images).
    """
    text, _ = _reconstruct_text_and_word_map(image)
    for span in spans:
        if span.text in text:
            raise ImageRedactionVerificationError(
                f"redaction verification failed: {span.entity_type} span "
                f"{span.text!r} still recoverable via OCR after redaction"
            )


@register(".png", ".jpg", ".jpeg")
def redact_image(input_path: Path, output_path: Path, offline: bool) -> Path:
    image = Image.open(input_path)
    image.load()
    if image.mode in ("RGBA", "LA", "PA") or (image.mode == "P" and "transparency" in image.info):
        working = image.convert("RGBA")
    else:
        working = image.convert("RGB")

    text, word_spans = _reconstruct_text_and_word_map(working)
    spans = detect_text_with_claude(text, offline)
    redacted = _redact_pixels(working, spans, word_spans)
    fresh = _fresh_copy(redacted)

    _verify_redacted(fresh, spans)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fresh.save(output_path)
    return output_path
