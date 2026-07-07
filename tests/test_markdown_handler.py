import fitz

from audit_redactor.pipeline import redact_file


def _extract_text(pdf_path) -> str:
    doc = fitz.open(pdf_path)
    try:
        return "".join(page.get_text() for page in doc)
    finally:
        doc.close()


class TestMarkdownHandler:
    def test_redacts_all_detector_types_and_renders_to_pdf(self, tmp_path) -> None:
        src = tmp_path / "notes.md"
        src.write_text(
            "# Audit notes\n\n"
            "Contact jane.doe@example.com or @jane-doe.\n"
            "AWS account 123456789012, call 555-123-4567.\n"
            "Client: Tesco. See https://example.com/report for details.\n",
            encoding="utf-8",
        )
        dest = tmp_path / "out" / "notes.md"

        actual = redact_file(src, dest, True)

        assert actual == tmp_path / "out" / "notes.pdf"
        text = _extract_text(actual)
        assert "jane.doe@example.com" not in text
        assert "@jane-doe" not in text
        assert "555-123-4567" not in text
        assert "Tesco" not in text
        assert "example.com/report" not in text
        # AWS account ID keeps its last 4 digits per PLAN.md 2.3.
        assert "9012" in text
        assert "123456789012" not in text
        # Non-sensitive structure is preserved (rendered from the "# Audit
        # notes" heading).
        assert "Audit notes" in text

    def test_markdown_extension_variant_renders_to_pdf(self, tmp_path) -> None:
        src = tmp_path / "notes.markdown"
        src.write_text("Reach me at test@example.com.", encoding="utf-8")
        dest = tmp_path / "redacted.markdown"

        actual = redact_file(src, dest, True)

        assert actual == tmp_path / "redacted.pdf"
        assert "test@example.com" not in _extract_text(actual)

    def test_no_sensitive_content_still_renders(self, tmp_path) -> None:
        src = tmp_path / "plain.md"
        src.write_text("Just a plain paragraph with no PII at all.", encoding="utf-8")
        dest = tmp_path / "redacted.md"

        actual = redact_file(src, dest, True)

        assert "Just a plain paragraph with no PII at all" in _extract_text(actual)

    def test_original_file_never_modified(self, tmp_path) -> None:
        src = tmp_path / "notes.md"
        original = "Contact jane@example.com about the audit."
        src.write_text(original, encoding="utf-8")
        dest = tmp_path / "out.md"

        redact_file(src, dest, True)

        assert src.read_text(encoding="utf-8") == original

    def test_markdown_mask_characters_survive_html_conversion(self, tmp_path) -> None:
        # Regression test: the mask/placeholder text must not collide with
        # Markdown syntax (e.g. `*` is emphasis, `[...]` can start a link)
        # once fed through the Markdown-to-HTML converter, or the rendered
        # PDF ends up with garbled/incorrect text instead of a clean mask.
        src = tmp_path / "notes.md"
        src.write_text(
            "AWS account 123456789012 and call 555-123-4567 re Tesco.\n",
            encoding="utf-8",
        )
        dest = tmp_path / "out.md"

        actual = redact_file(src, dest, True)

        text = _extract_text(actual)
        assert "xxxxxxxx9012" in text
        assert "xxx-xxx-xxxx" in text
        assert "(REDACTED)" in text
