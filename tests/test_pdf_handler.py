from pathlib import Path

import fitz
import pytest

from audit_redactor.appliers.pdf import PdfRedactionVerificationError, verify_pdf_redacted
from audit_redactor.detectors.base import Span
from audit_redactor.pipeline import redact_file


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
