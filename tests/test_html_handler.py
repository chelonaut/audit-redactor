import fitz

from audit_redactor.handlers.html_handler import redact_html_source
from audit_redactor.pipeline import redact_file


def _extract_text(pdf_path) -> str:
    doc = fitz.open(pdf_path)
    try:
        return "".join(page.get_text() for page in doc)
    finally:
        doc.close()


class TestRedactHtmlSource:
    def test_strips_script_tags_entirely(self) -> None:
        html = '<html><body><script>leak("123456789012")</script><p>hi</p></body></html>'
        redacted, _ = redact_html_source(html)
        assert "<script" not in redacted
        assert "123456789012" not in redacted

    def test_strips_meta_tags(self) -> None:
        html = '<html><head><meta name="author" content="Jane Doe"></head><body>hi</body></html>'
        redacted, _ = redact_html_source(html)
        assert "<meta" not in redacted
        assert "Jane Doe" not in redacted

    def test_strips_html_comments(self) -> None:
        html = "<html><body><!-- internal note: jane@example.com --><p>hi</p></body></html>"
        redacted, _ = redact_html_source(html)
        assert "internal note" not in redacted
        assert "jane@example.com" not in redacted

    def test_strips_data_attributes(self) -> None:
        html = '<html><body><div data-user-id="123456789012">hi</div></body></html>'
        redacted, _ = redact_html_source(html)
        assert "data-user-id" not in redacted
        assert "123456789012" not in redacted

    def test_redacts_title_tag_text(self) -> None:
        html = "<html><head><title>Report for jane@example.com</title></head><body>hi</body></html>"
        redacted, _ = redact_html_source(html)
        assert "jane@example.com" not in redacted

    def test_leaves_style_content_untouched(self) -> None:
        html = "<html><head><style>.foo { color: red; }</style></head><body>hi</body></html>"
        redacted, _ = redact_html_source(html)
        assert ".foo { color: red; }" in redacted

    def test_redacts_body_text_node(self) -> None:
        html = "<html><body><p>Contact jane@example.com for details.</p></body></html>"
        redacted, spans = redact_html_source(html)
        assert "jane@example.com" not in redacted
        assert len(spans) == 1
        assert spans[0].text == "jane@example.com"


class TestHtmlHandler:
    def test_redacts_all_detector_types_and_renders_to_pdf(self, tmp_path) -> None:
        src = tmp_path / "doc.html"
        src.write_text(
            "<html><head><title>Report</title></head><body>"
            "<p>AWS account 123456789012 owned by jane.doe@example.com.</p>"
            "<p>Call 555-123-4567 or visit Tesco, see https://example.com/report</p>"
            "</body></html>",
            encoding="utf-8",
        )
        dest = tmp_path / "out" / "doc.html"

        actual = redact_file(src, dest, True)

        assert actual == tmp_path / "out" / "doc.pdf"
        text = _extract_text(actual)
        assert "123456789012" not in text
        assert "9012" in text  # AWS ID keeps last 4 digits per PLAN.md 2.3
        assert "jane.doe@example.com" not in text
        assert "555-123-4567" not in text
        assert "Tesco" not in text
        assert "example.com/report" not in text

    def test_htm_extension_variant(self, tmp_path) -> None:
        src = tmp_path / "doc.htm"
        src.write_text("<html><body>Contact jane@example.com</body></html>", encoding="utf-8")
        dest = tmp_path / "redacted.htm"

        actual = redact_file(src, dest, True)

        assert actual == tmp_path / "redacted.pdf"
        assert "jane@example.com" not in _extract_text(actual)

    def test_script_and_meta_content_never_reaches_output(self, tmp_path) -> None:
        src = tmp_path / "doc.html"
        src.write_text(
            "<html><head>"
            '<meta name="author" content="Jane Doe">'
            "<script>trackUser(\"123456789012\");</script>"
            "</head><body>"
            "<!-- internal note: contact jane@example.com -->"
            "<p>Hello world.</p>"
            "</body></html>",
            encoding="utf-8",
        )
        dest = tmp_path / "out.html"

        actual = redact_file(src, dest, True)

        raw = actual.read_bytes()
        assert b"Jane Doe" not in raw
        assert b"trackUser" not in raw
        assert b"internal note" not in raw
        assert "Hello world" in _extract_text(actual)

    def test_metadata_stripped_from_rendered_pdf(self, tmp_path) -> None:
        src = tmp_path / "doc.html"
        src.write_text("<html><head><title>Secret Title</title></head>"
                        "<body>hi</body></html>", encoding="utf-8")
        dest = tmp_path / "out.html"

        actual = redact_file(src, dest, True)

        doc = fitz.open(actual)
        try:
            assert doc.metadata["title"] == ""
            assert doc.metadata["producer"] == ""
        finally:
            doc.close()

    def test_no_sensitive_content_still_renders(self, tmp_path) -> None:
        src = tmp_path / "doc.html"
        src.write_text(
            "<html><body><p>Just a plain paragraph with no PII at all.</p></body></html>",
            encoding="utf-8",
        )
        dest = tmp_path / "out.html"

        actual = redact_file(src, dest, True)

        assert "Just a plain paragraph with no PII at all" in _extract_text(actual)

    def test_original_file_never_modified(self, tmp_path) -> None:
        src = tmp_path / "doc.html"
        original = "<html><body>Contact jane@example.com</body></html>"
        src.write_text(original, encoding="utf-8")
        dest = tmp_path / "out.html"

        redact_file(src, dest, True)

        assert src.read_text(encoding="utf-8") == original

    def test_external_resource_requests_are_blocked(self, tmp_path) -> None:
        # An <img>/<link> pointing at an external host must never actually
        # be fetched during rendering -- see appliers/html_render.py's
        # network-blocking rationale. A nonexistent domain is used so this
        # test fails loudly (via a hang/DNS-error surfacing as a Playwright
        # timeout) rather than silently passing if blocking regresses.
        src = tmp_path / "doc.html"
        src.write_text(
            '<html><head>'
            '<link rel="stylesheet" href="https://example-nonexistent-domain-xyz123.test/style.css">'
            "</head><body>"
            '<img src="https://example-nonexistent-domain-xyz123.test/tracker.gif?leak=secret">'
            "<p>Hello world</p>"
            "</body></html>",
            encoding="utf-8",
        )
        dest = tmp_path / "out.html"

        actual = redact_file(src, dest, True)

        assert "Hello world" in _extract_text(actual)
