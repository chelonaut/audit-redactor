import io
from pathlib import Path

import fitz
import pytesseract
import pytest
from PIL import Image, ImageDraw, ImageFont

from audit_redactor.appliers.pdf import PdfRedactionVerificationError, verify_pdf_redacted
from audit_redactor.detectors.base import Span
from audit_redactor.pipeline import redact_file

# Pillow's own bundled scalable default font -- portable across platforms,
# matching the convention in tests/test_image_handler.py.
_FONT = ImageFont.load_default(size=28)


def _make_pdf(path: Path, lines: list[str]) -> None:
    doc = fitz.open()
    page = doc.new_page()
    for i, line in enumerate(lines):
        page.insert_text((72, 72 + i * 20), line, fontsize=11)
    doc.save(path)
    doc.close()


class TestPdfHandler:
    def test_redacts_all_detector_types_and_flattens(self, tmp_path) -> None:
        src = tmp_path / "doc.pdf"
        _make_pdf(
            src,
            [
                "AWS account 123456789012 owned by jane.doe@example.com.",
                "Call 555-123-4567 or visit Tesco, see https://example.com/report",
            ],
        )
        dest = tmp_path / "out" / "doc.pdf"

        actual = redact_file(src, dest, True)

        assert actual == dest
        redacted = fitz.open(dest)
        text = redacted[0].get_text()
        assert "123456789012" not in text
        assert "9012" in text  # last 4 digits kept per PLAN.md 2.3
        assert "jane.doe@example.com" not in text
        assert "555-123-4567" not in text
        assert "Tesco" not in text
        assert "https://example.com/report" not in text
        redacted.close()

    def test_metadata_and_embedded_files_stripped(self, tmp_path) -> None:
        src = tmp_path / "doc.pdf"
        doc = fitz.open()
        doc.new_page()
        doc.set_metadata({"title": "Secret Project X", "author": "Jane Doe"})
        doc.embfile_add("secret.txt", b"contains 123456789012", filename="secret.txt")
        doc.save(src)
        doc.close()
        dest = tmp_path / "out.pdf"

        redact_file(src, dest, True)

        result = fitz.open(dest)
        assert result.metadata["title"] == ""
        assert result.metadata["author"] == ""
        assert result.embfile_count() == 0
        result.close()
        assert b"123456789012" not in dest.read_bytes()

    def test_hidden_ocg_layer_content_is_detected_and_redacted(self, tmp_path) -> None:
        src = tmp_path / "doc.pdf"
        doc = fitz.open()
        page = doc.new_page()
        ocg_xref = doc.add_ocg("HiddenLayer", on=False)
        page.insert_text((72, 72), "visible text here")
        page.insert_text((72, 100), "hidden leak@example.com", oc=ocg_xref)
        doc.save(src)
        doc.close()
        dest = tmp_path / "out.pdf"

        redact_file(src, dest, True)

        result = fitz.open(dest)
        assert result.get_ocgs() == {}
        text = result[0].get_text()
        assert "visible text here" in text
        assert "leak@example.com" not in text
        result.close()
        assert b"leak@example.com" not in dest.read_bytes()

    def test_form_widgets_removed(self, tmp_path) -> None:
        src = tmp_path / "doc.pdf"
        doc = fitz.open()
        page = doc.new_page()
        widget = fitz.Widget()
        widget.field_name = "field1"
        widget.field_type = fitz.PDF_WIDGET_TYPE_TEXT
        widget.rect = fitz.Rect(72, 100, 200, 120)
        widget.field_value = "secret value"
        page.add_widget(widget)
        doc.save(src)
        doc.close()
        dest = tmp_path / "out.pdf"

        redact_file(src, dest, True)

        result = fitz.open(dest)
        assert result.is_form_pdf == 0
        assert list(result[0].widgets()) == []
        result.close()

    def test_no_sensitive_content_leaves_page_unredacted(self, tmp_path) -> None:
        src = tmp_path / "doc.pdf"
        _make_pdf(src, ["Just a plain paragraph with no PII at all."])
        dest = tmp_path / "out.pdf"

        redact_file(src, dest, True)

        result = fitz.open(dest)
        assert "Just a plain paragraph with no PII at all." in result[0].get_text()
        result.close()

    def test_original_file_never_modified(self, tmp_path) -> None:
        src = tmp_path / "doc.pdf"
        _make_pdf(src, ["Contact jane@example.com."])
        original_bytes = src.read_bytes()
        dest = tmp_path / "out.pdf"

        redact_file(src, dest, True)

        assert src.read_bytes() == original_bytes

    def test_declines_to_overwrite_existing_output(self, tmp_path) -> None:
        src = tmp_path / "doc.pdf"
        _make_pdf(src, ["Contact jane@example.com."])
        dest = tmp_path / "out.pdf"
        _make_pdf(dest, ["unrelated prior output"])
        prior_bytes = dest.read_bytes()

        with pytest.raises(FileExistsError):
            redact_file(src, dest, True)

        assert dest.read_bytes() == prior_bytes

    def test_declines_when_output_path_is_the_input_path(self, tmp_path) -> None:
        src = tmp_path / "doc.pdf"
        _make_pdf(src, ["Contact jane@example.com."])
        original_bytes = src.read_bytes()

        with pytest.raises(FileExistsError):
            redact_file(src, src, True)

        assert src.read_bytes() == original_bytes


class TestSensitiveLinks:
    """A real end-to-end validation run against a browser-exported AWS
    console PDF found that a hyperlink's URI can carry an account ID that
    never appears as blacked-out visible text elsewhere -- `apply_redactions`
    only touches the page's content stream, not link annotations.
    """

    def test_link_uri_leaking_account_id_is_removed(self, tmp_path) -> None:
        src = tmp_path / "doc.pdf"
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "click the link below")
        page.insert_link(
            {
                "kind": fitz.LINK_URI,
                "from": fitz.Rect(72, 90, 300, 110),
                "uri": "https://console.aws.amazon.com/s3/buckets/acct-123456789012",
            }
        )
        doc.save(src)
        doc.close()
        dest = tmp_path / "out.pdf"

        redact_file(src, dest, True)

        result = fitz.open(dest)
        assert result[0].get_links() == []
        result.close()
        assert b"123456789012" not in dest.read_bytes()

    def test_ordinary_external_link_is_kept(self, tmp_path) -> None:
        src = tmp_path / "doc.pdf"
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "click the link below")
        page.insert_link(
            {
                "kind": fitz.LINK_URI,
                "from": fitz.Rect(72, 90, 300, 110),
                "uri": "https://example.com/report",
            }
        )
        doc.save(src)
        doc.close()
        dest = tmp_path / "out.pdf"

        redact_file(src, dest, True)

        result = fitz.open(dest)
        links = result[0].get_links()
        assert len(links) == 1
        assert links[0]["uri"] == "https://example.com/report"
        result.close()

    def test_link_uri_revealing_identified_username_is_removed(self, tmp_path) -> None:
        # A GitHub profile/repo link is a signal that "octocat" is a
        # username (platform_identity.py) even though the link URI itself
        # matches nothing else (no AWS ID/email/phone/company).
        src = tmp_path / "doc.pdf"
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "octocat")
        page.insert_link(
            {
                "kind": fitz.LINK_URI,
                "from": fitz.Rect(72, 90, 300, 110),
                "uri": "https://github.com/octocat/claude-news-aggregator-prompt/commits?author=octocat",
            }
        )
        doc.save(src)
        doc.close()
        dest = tmp_path / "out.pdf"

        redact_file(src, dest, True)

        result = fitz.open(dest)
        assert result[0].get_links() == []
        result.close()
        assert b"octocat" not in dest.read_bytes()


class TestIdentityDiscoveryAcrossPages:
    def test_username_from_page_one_link_redacts_bare_mention_on_page_two(self, tmp_path) -> None:
        src = tmp_path / "doc.pdf"
        doc = fitz.open()
        page1 = doc.new_page()
        page1.insert_text((72, 72), "octocat")
        page1.insert_link(
            {
                "kind": fitz.LINK_URI,
                "from": fitz.Rect(72, 60, 200, 90),
                "uri": "https://github.com/octocat",
            }
        )
        page2 = doc.new_page()
        page2.insert_text((72, 72), "octocat authored this with no link at all")
        doc.save(src)
        doc.close()
        dest = tmp_path / "out.pdf"

        redact_file(src, dest, True)

        result = fitz.open(dest)
        full_text = "".join(p.get_text() for p in result)
        result.close()
        assert "octocat" not in full_text
        assert b"octocat" not in dest.read_bytes()


class TestScannedPage:
    """A "scanned" page: its entire content is a raster image with no real,
    extractable text layer at all -- confirmed via a real end-to-end
    validation run to slip through the native text-based path completely
    unredacted, since `apply_redactions()` has nothing to act on and the
    post-save verification pass has no span text to check the raw bytes
    against in the first place.
    """

    def test_image_only_page_with_no_text_layer_is_ocr_redacted(self, tmp_path) -> None:
        img_path = tmp_path / "scan.png"
        image = Image.new("RGB", (900, 200), "white")
        draw = ImageDraw.Draw(image)
        draw.text((20, 20), "AWS account 123456789012", fill="black", font=_FONT)
        draw.text((20, 90), "owned by jane.doe@example.com", fill="black", font=_FONT)
        image.save(img_path)

        src = tmp_path / "scanned.pdf"
        doc = fitz.open()
        page = doc.new_page(width=900, height=200)
        page.insert_image(page.rect, filename=str(img_path))
        doc.save(src)
        doc.close()
        # Sanity check the fixture is genuinely text-less before redacting.
        check = fitz.open(src)
        assert check[0].get_text().strip() == ""
        check.close()

        dest = tmp_path / "out.pdf"
        redact_file(src, dest, True)

        result = fitz.open(dest)
        pix = result[0].get_pixmap()
        out_image = Image.open(io.BytesIO(pix.tobytes("png")))
        recovered_text = pytesseract.image_to_string(out_image)
        result.close()

        assert "123456789012" not in recovered_text
        assert "jane.doe@example.com" not in recovered_text
        assert b"123456789012" not in dest.read_bytes()
        assert b"jane.doe@example.com" not in dest.read_bytes()

    def test_page_with_real_text_and_an_incidental_image_is_not_rerouted(self, tmp_path) -> None:
        # A page with substantial real text (well above the "scanned"
        # threshold) plus a decorative image should still go through the
        # normal native-text path, not get rasterized wholesale.
        img_path = tmp_path / "logo.png"
        Image.new("RGB", (50, 50), "blue").save(img_path)

        src = tmp_path / "doc.pdf"
        doc = fitz.open()
        page = doc.new_page()
        page.insert_image(fitz.Rect(400, 700, 450, 750), filename=str(img_path))
        page.insert_text((72, 72), "Contact jane@example.com about the quarterly report.")
        doc.save(src)
        doc.close()
        dest = tmp_path / "out.pdf"

        redact_file(src, dest, True)

        result = fitz.open(dest)
        text = result[0].get_text()
        result.close()
        assert "jane@example.com" not in text
        assert "quarterly report" in text  # real text path preserves non-sensitive prose


class TestVerifyRedacted:
    def test_raises_when_span_text_still_recoverable(self, tmp_path) -> None:
        path = tmp_path / "bad.pdf"
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "leaked jane@example.com right here")
        doc.save(path)
        doc.close()

        span = Span(
            text="jane@example.com",
            entity_type="EMAIL",
            confidence=1.0,
            source="regex",
            start=7,
            end=23,
        )
        with pytest.raises(PdfRedactionVerificationError):
            verify_pdf_redacted(path, [span])

    def test_passes_when_span_text_absent(self, tmp_path) -> None:
        path = tmp_path / "good.pdf"
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "nothing sensitive here")
        doc.save(path)
        doc.close()

        span = Span(
            text="jane@example.com",
            entity_type="EMAIL",
            confidence=1.0,
            source="regex",
            start=0,
            end=16,
        )
        verify_pdf_redacted(path, [span])  # should not raise
