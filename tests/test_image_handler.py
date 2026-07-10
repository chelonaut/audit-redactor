import pytesseract
import pytest
from PIL import Image, ImageDraw, ImageFont, PngImagePlugin

from audit_redactor.appliers.image_ocr import ImageRedactionVerificationError, verify_redacted
from audit_redactor.appliers.output_guard import configure_ignore_verify_failure
from audit_redactor.detectors.base import Span
from audit_redactor.pipeline import redact_file

# Pillow's own bundled scalable default font -- portable across platforms
# (no OS font-path dependency), so these tests run identically locally and
# in the Linux Docker image.
_FONT = ImageFont.load_default(size=28)


def _make_image(path, lines: list[str], size=(950, 220), bg="white", fg="black", font=_FONT) -> None:
    img = Image.new("RGB", size, bg)
    draw = ImageDraw.Draw(img)
    for i, line in enumerate(lines):
        draw.text((20, 20 + i * 50), line, fill=fg, font=font)
    img.save(path)


class TestImageHandler:
    def test_redacts_all_detector_types(self, tmp_path) -> None:
        src = tmp_path / "doc.png"
        _make_image(
            src,
            [
                "AWS account 123456789012 owned by jane.doe@example.com",
                "Call 555-123-4567 or visit Tesco, see https://example.com/report",
            ],
        )
        dest = tmp_path / "out" / "doc.png"

        actual = redact_file(src, dest, True)

        assert actual == dest
        text = pytesseract.image_to_string(Image.open(dest))
        assert "123456789012" not in text
        assert "jane.doe@example.com" not in text
        assert "555-123-4567" not in text
        assert "Tesco" not in text
        assert "example.com/report" not in text

    def test_low_contrast_aws_console_style_account_id_is_redacted(self, tmp_path) -> None:
        # Simulates an AWS console top-nav account-info readout: dark navy
        # background, light-grey small text -- low but plausible real-world
        # contrast, not the near-invisible extreme.
        src = tmp_path / "console.png"
        font = ImageFont.load_default(size=16)
        img = Image.new("RGB", (400, 50), (35, 47, 62))
        draw = ImageDraw.Draw(img)
        draw.text((15, 15), "Account: 123456789012", fill=(215, 215, 219), font=font)
        img.save(src)
        dest = tmp_path / "out.png"

        redact_file(src, dest, True)

        text = pytesseract.image_to_string(Image.open(dest))
        assert "123456789012" not in text
        assert "9012" not in text  # image handler redacts whole words, no partial reveal

    def test_no_cross_line_bleed_into_adjacent_non_sensitive_lines(self, tmp_path) -> None:
        src = tmp_path / "tight.png"
        font = ImageFont.load_default(size=28)
        img = Image.new("RGB", (900, 140), "white")
        draw = ImageDraw.Draw(img)
        draw.text((20, 10), "Line one is not sensitive at all", fill="black", font=font)
        draw.text((20, 44), "Contact jane@example.com about this", fill="black", font=font)
        draw.text((20, 78), "Line three also has nothing secret", fill="black", font=font)
        img.save(src)
        dest = tmp_path / "out.png"

        redact_file(src, dest, True)

        text = pytesseract.image_to_string(Image.open(dest))
        assert "Line one is not sensitive at all" in text
        assert "Line three also has nothing secret" in text
        assert "jane@example.com" not in text

    def test_metadata_and_text_chunks_stripped(self, tmp_path) -> None:
        src = tmp_path / "doc.png"
        img = Image.new("RGB", (200, 100), "white")
        meta = PngImagePlugin.PngInfo()
        meta.add_text("Author", "Jane Doe")
        meta.add_text("Secret", "internal-project-codename")
        img.save(src, pnginfo=meta)
        dest = tmp_path / "out.png"

        redact_file(src, dest, True)

        result = Image.open(dest)
        assert result.info == {}
        raw = dest.read_bytes()
        assert b"internal-project-codename" not in raw
        assert b"Jane Doe" not in raw

    def test_transparency_preserved(self, tmp_path) -> None:
        src = tmp_path / "doc.png"
        img = Image.new("RGBA", (200, 100), (255, 255, 255, 0))
        draw = ImageDraw.Draw(img)
        draw.text((10, 10), "no sensitive content", fill=(0, 0, 0, 255), font=_FONT)
        img.save(src)
        dest = tmp_path / "out.png"

        redact_file(src, dest, True)

        result = Image.open(dest)
        assert result.mode == "RGBA"
        assert result.getpixel((0, 0))[3] == 0  # corner stays transparent

    def test_no_sensitive_content_stays_readable(self, tmp_path) -> None:
        src = tmp_path / "doc.png"
        _make_image(src, ["Just a plain paragraph with no PII at all"])
        dest = tmp_path / "out.png"

        redact_file(src, dest, True)

        text = pytesseract.image_to_string(Image.open(dest))
        assert "plain paragraph" in text

    def test_original_file_never_modified(self, tmp_path) -> None:
        src = tmp_path / "doc.png"
        _make_image(src, ["Contact jane@example.com"])
        original_bytes = src.read_bytes()
        dest = tmp_path / "out.png"

        redact_file(src, dest, True)

        assert src.read_bytes() == original_bytes

    def test_jpeg_extension_variant(self, tmp_path) -> None:
        src = tmp_path / "doc.jpg"
        _make_image(src, ["Contact jane@example.com"])
        dest = tmp_path / "out.jpg"

        redact_file(src, dest, True)

        text = pytesseract.image_to_string(Image.open(dest))
        assert "jane@example.com" not in text

    def test_declines_to_overwrite_existing_output(self, tmp_path) -> None:
        src = tmp_path / "doc.png"
        _make_image(src, ["Contact jane@example.com"])
        dest = tmp_path / "out.png"
        _make_image(dest, ["unrelated prior output"])
        prior_bytes = dest.read_bytes()

        with pytest.raises(FileExistsError):
            redact_file(src, dest, True)

        assert dest.read_bytes() == prior_bytes

    def test_declines_when_output_path_is_the_input_path(self, tmp_path) -> None:
        src = tmp_path / "doc.png"
        _make_image(src, ["Contact jane@example.com"])
        original_bytes = src.read_bytes()

        with pytest.raises(FileExistsError):
            redact_file(src, src, True)

        assert src.read_bytes() == original_bytes


class TestVerifyRedacted:
    def test_raises_when_span_text_still_recoverable(self) -> None:
        img = Image.new("RGB", (550, 60), "white")
        draw = ImageDraw.Draw(img)
        draw.text((10, 10), "leaked jane@example.com right here", fill="black", font=_FONT)

        span = Span(
            text="jane@example.com",
            entity_type="EMAIL",
            confidence=1.0,
            source="regex",
            start=7,
            end=23,
        )
        with pytest.raises(ImageRedactionVerificationError):
            verify_redacted(img, [span])

    def test_passes_when_span_text_absent(self) -> None:
        img = Image.new("RGB", (350, 60), "white")
        draw = ImageDraw.Draw(img)
        draw.text((10, 10), "nothing sensitive here", fill="black", font=_FONT)

        span = Span(
            text="jane@example.com",
            entity_type="EMAIL",
            confidence=1.0,
            source="regex",
            start=0,
            end=16,
        )
        verify_redacted(img, [span])  # should not raise

    def test_short_at_mention_does_not_fail_verification(self) -> None:
        img = Image.new("RGB", (550, 60), "white")
        draw = ImageDraw.Draw(img)
        draw.text((10, 10), "Some coincidental @O text sitting here", fill="black", font=_FONT)

        span = Span(
            text="@O",
            entity_type="USERNAME_MENTION",
            confidence=1.0,
            source="regex",
            start=19,
            end=21,
        )
        verify_redacted(img, [span])  # should not raise despite "@O" still visible


class TestIgnoreVerifyFailure:
    def test_deletes_output_and_raises_by_default(self, tmp_path, monkeypatch) -> None:
        src = tmp_path / "doc.png"
        _make_image(src, ["Contact jane@example.com."])
        dest = tmp_path / "out.png"

        def _always_fails(*args, **kwargs):
            raise ImageRedactionVerificationError("boom")

        monkeypatch.setattr("audit_redactor.appliers.image_ocr.verify_redacted", _always_fails)

        with pytest.raises(ImageRedactionVerificationError):
            redact_file(src, dest, True)

        assert not dest.exists()

    def test_keeps_output_and_warns_when_flag_set(self, tmp_path, monkeypatch, capsys) -> None:
        src = tmp_path / "doc.png"
        _make_image(src, ["Contact jane@example.com."])
        dest = tmp_path / "out.png"

        def _always_fails(*args, **kwargs):
            raise ImageRedactionVerificationError("boom")

        monkeypatch.setattr("audit_redactor.appliers.image_ocr.verify_redacted", _always_fails)
        configure_ignore_verify_failure(True)

        result = redact_file(src, dest, True)

        assert result == dest
        assert dest.exists()
        assert "⚠️" in capsys.readouterr().out
