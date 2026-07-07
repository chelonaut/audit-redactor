"""Image handler (PLAN.md 2.2, 2.4, 2.5, build phase 5).

Thin per-format wrapper around the shared OCR-redaction core in
`appliers/image_ocr.py` (also used by the PDF handler's scanned-page path) --
this module only handles PNG/JPEG-specific loading and mode normalization
before handing off to that shared pipeline.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image

from audit_redactor.appliers.image_ocr import ocr_redact_image
from audit_redactor.appliers.output_guard import ensure_output_does_not_exist
from audit_redactor.pipeline import register


@register(".png", ".jpg", ".jpeg")
def redact_image(input_path: Path, output_path: Path, offline: bool) -> Path:
    ensure_output_does_not_exist(output_path)
    image = Image.open(input_path)
    image.load()
    if image.mode in ("RGBA", "LA", "PA") or (image.mode == "P" and "transparency" in image.info):
        working = image.convert("RGBA")
    else:
        working = image.convert("RGB")

    fresh, _spans = ocr_redact_image(working, offline)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fresh.save(output_path)
    return output_path
