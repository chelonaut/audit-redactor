from audit_redactor.pipeline import redact_file


class TestMarkdownHandler:
    def test_redacts_all_detector_types_in_place(self, tmp_path) -> None:
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

        assert actual == dest
        redacted = dest.read_text(encoding="utf-8")
        assert "jane.doe@example.com" not in redacted
        assert "@jane-doe" not in redacted
        assert "555-123-4567" not in redacted
        assert "Tesco" not in redacted
        assert "https://example.com/report" not in redacted
        # AWS account ID keeps its last 4 digits per PLAN.md 2.3.
        assert "9012" in redacted
        assert "123456789012" not in redacted
        # Non-sensitive structure is preserved untouched.
        assert "# Audit notes" in redacted

    def test_markdown_extension_variant(self, tmp_path) -> None:
        src = tmp_path / "notes.markdown"
        src.write_text("Reach me at test@example.com.", encoding="utf-8")
        dest = tmp_path / "redacted.markdown"

        redact_file(src, dest, True)

        assert "test@example.com" not in dest.read_text(encoding="utf-8")

    def test_no_sensitive_content_left_unchanged(self, tmp_path) -> None:
        src = tmp_path / "plain.md"
        original = "Just a plain paragraph with no PII at all."
        src.write_text(original, encoding="utf-8")
        dest = tmp_path / "redacted.md"

        redact_file(src, dest, True)

        assert dest.read_text(encoding="utf-8") == original
        # Original is never modified.
        assert src.read_text(encoding="utf-8") == original
