import fitz
import pytest

from audit_redactor.handlers.markdown_handler import _render_task_list_checkboxes
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

    def test_declines_to_overwrite_existing_output(self, tmp_path) -> None:
        src = tmp_path / "notes.md"
        src.write_text("Contact jane.doe@example.com.\n", encoding="utf-8")
        # The handler always renders to a .pdf regardless of the requested
        # extension -- the guard must check that *actual* final path, not
        # the literal "out.md" passed in.
        dest = tmp_path / "out.md"
        actual_output = tmp_path / "out.pdf"
        actual_output.write_bytes(b"%PDF-1.4 unrelated prior output")
        prior_bytes = actual_output.read_bytes()

        with pytest.raises(FileExistsError):
            redact_file(src, dest, True)

        assert actual_output.read_bytes() == prior_bytes

    def test_discovers_username_from_link_and_redacts_bare_mention(self, tmp_path) -> None:
        src = tmp_path / "notes.md"
        src.write_text(
            "See [my profile](https://github.com/chelonaut) for more.\n"
            "chelonaut is the author of this repo.\n",
            encoding="utf-8",
        )
        dest = tmp_path / "out.md"

        actual = redact_file(src, dest, True)

        text = _extract_text(actual)
        assert "chelonaut" not in text

    def test_fenced_code_block_preserves_line_breaks_and_indentation(self, tmp_path) -> None:
        # Regression test: without the "fenced_code" markdown extension, a
        # ``` block is misread as a single inline <code> span (not <pre>),
        # whose language hint leaks into the visible text and whose
        # newlines get collapsed onto one line when Chromium renders it --
        # neither of which is a redaction bug, but both make the rendered
        # output wrong compared to the source.
        src = tmp_path / "notes.md"
        src.write_text(
            "```python\n"
            "def notify():\n"
            '    email = "jane.doe@example.com"\n'
            "```\n",
            encoding="utf-8",
        )
        dest = tmp_path / "out.md"

        actual = redact_file(src, dest, True)

        text = _extract_text(actual)
        assert "python" not in text
        assert "def notify():" in text
        assert '    email = "(REDACTED)"' in text

    def test_table_is_parsed_not_left_as_literal_pipe_text(self, tmp_path) -> None:
        # Regression test: without the "tables" markdown extension, a GFM
        # pipe table is left completely unparsed -- rendered as literal
        # "| a | b |" text instead of an actual table.
        src = tmp_path / "notes.md"
        src.write_text(
            "| Name | Email |\n"
            "|------|-------|\n"
            "| Jane Doe | jane.doe@example.com |\n",
            encoding="utf-8",
        )
        dest = tmp_path / "out.md"

        actual = redact_file(src, dest, True)

        text = _extract_text(actual)
        assert "|" not in text
        assert "Jane Doe" in text
        assert "(REDACTED)" in text
        assert "jane.doe@example.com" not in text

    def test_task_list_items_render_as_checkboxes(self, tmp_path) -> None:
        src = tmp_path / "notes.md"
        src.write_text(
            "- [ ] Review AWS account 123456789012\n"
            "- [x] Notify jane.doe@example.com\n"
            "- Normal bullet item\n",
            encoding="utf-8",
        )
        dest = tmp_path / "out.md"

        actual = redact_file(src, dest, True)

        text = _extract_text(actual)
        # The literal "[ ]"/"[x]" markers must be gone (replaced by a real
        # <input type="checkbox">, which isn't extractable as text) while
        # the redacted item text survives -- and content still gets redacted.
        assert "[ ]" not in text
        assert "[x]" not in text
        assert "Review AWS account xxxxxxxx9012" in text
        assert "Notify (REDACTED)" in text
        assert "Normal bullet item" in text

    def test_task_list_checkbox_syntax_inside_redacted_text_not_mangled(self, tmp_path) -> None:
        # The checkbox regex runs on the already-redacted string -- confirm
        # a placeholder or masked value sitting right after the checkbox
        # marker doesn't confuse the substitution.
        src = tmp_path / "notes.md"
        src.write_text("- [x] jane.doe@example.com is done\n", encoding="utf-8")
        dest = tmp_path / "out.md"

        actual = redact_file(src, dest, True)

        text = _extract_text(actual)
        assert "[x]" not in text
        assert "(REDACTED) is done" in text


class TestRenderTaskListCheckboxes:
    def test_unchecked_item(self) -> None:
        result = _render_task_list_checkboxes("- [ ] Todo item")
        assert result == '- <input type="checkbox" disabled> Todo item'

    def test_checked_item_lowercase_x(self) -> None:
        result = _render_task_list_checkboxes("- [x] Done item")
        assert result == '- <input type="checkbox" checked disabled> Done item'

    def test_checked_item_uppercase_x(self) -> None:
        result = _render_task_list_checkboxes("- [X] Done item")
        assert result == '- <input type="checkbox" checked disabled> Done item'

    def test_asterisk_and_plus_bullets(self) -> None:
        assert '<input type="checkbox" disabled>' in _render_task_list_checkboxes("* [ ] Todo")
        assert '<input type="checkbox" disabled>' in _render_task_list_checkboxes("+ [ ] Todo")

    def test_indentation_preserved(self) -> None:
        result = _render_task_list_checkboxes("  - [ ] Nested todo")
        assert result == '  - <input type="checkbox" disabled> Nested todo'

    def test_non_task_list_line_untouched(self) -> None:
        assert _render_task_list_checkboxes("- Normal bullet item") == "- Normal bullet item"

    def test_bracket_text_that_is_not_a_task_marker_untouched(self) -> None:
        # A literal "[ ]" that isn't a checkbox marker at all (no bullet
        # prefix) must be left alone.
        text = "Some text with [ ] a bracket in the middle."
        assert _render_task_list_checkboxes(text) == text
