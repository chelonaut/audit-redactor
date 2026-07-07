import fitz
import pytest

from audit_redactor.pipeline import redact_file


class TestRedactFileDispatch:
    def test_unsupported_extension_raises(self, tmp_path) -> None:
        src = tmp_path / "notes.txt"
        src.write_text("hello", encoding="utf-8")
        dest = tmp_path / "notes.txt"

        with pytest.raises(ValueError, match="unsupported file format"):
            redact_file(src, dest, True)


class TestFilenameRedactionIntegration:
    """PLAN.md 2.5/phase 7: filename redaction applies automatically at the
    pipeline dispatch chokepoint, regardless of file type.
    """

    def test_sensitive_output_filename_redacted_for_json(self, tmp_path) -> None:
        src = tmp_path / "in.json"
        src.write_text('{"note": "nothing sensitive"}', encoding="utf-8")
        dest = tmp_path / "report-for-tesco-123456789012.json"

        actual = redact_file(src, dest, True)

        assert "tesco" not in actual.name.lower()
        assert "123456789012" not in actual.name
        assert actual.parent == dest.parent

    def test_sensitive_output_filename_redacted_for_markdown_to_pdf(self, tmp_path) -> None:
        src = tmp_path / "in.md"
        src.write_text("Nothing sensitive in the body.", encoding="utf-8")
        dest = tmp_path / "jane.doe@example.com-notes.md"

        actual = redact_file(src, dest, True)

        # Extension change (md -> pdf, phase 6) composes correctly with the
        # filename redaction applied to the originally-requested stem.
        assert actual.suffix == ".pdf"
        assert "jane.doe@example.com" not in actual.name

        doc = fitz.open(actual)
        try:
            assert "Nothing sensitive in the body" in doc[0].get_text()
        finally:
            doc.close()

    def test_non_sensitive_filename_left_unchanged(self, tmp_path) -> None:
        src = tmp_path / "in.json"
        src.write_text('{"note": "nothing sensitive"}', encoding="utf-8")
        dest = tmp_path / "quarterly-summary.json"

        actual = redact_file(src, dest, True)

        assert actual == dest
