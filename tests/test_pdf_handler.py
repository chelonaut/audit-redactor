import io
from pathlib import Path

import fitz
import pytesseract
import pytest
from PIL import Image, ImageDraw, ImageFont

from audit_redactor.appliers.output_guard import configure_ignore_verify_failure
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

    def test_ordinary_link_matching_a_redacted_visible_url_elsewhere_does_not_fail_verification(
        self, tmp_path
    ) -> None:
        # Found via a real Jira-exported PDF: the same plain URL appeared
        # both as blacked-out visible text (a "Exported from: <url>" line)
        # and, unrelated to that, as the target of an ordinary kept link
        # elsewhere on the page (e.g. site branding) whose URI carries
        # nothing else sensitive. That's correct per `test_ordinary_
        # external_link_is_kept` above, but `verify_pdf_redacted`'s "this
        # span's text must not exist anywhere in the raw file" check used to
        # flag it as leaked anyway, even though the actual visible
        # occurrence was fully redacted.
        src = tmp_path / "doc.pdf"
        doc = fitz.open()
        page = doc.new_page()
        url = "https://example.atlassian.net"
        page.insert_text((72, 72), f"Exported from: {url}")
        page.insert_text((72, 700), "Powered by Jira")
        page.insert_link({"kind": fitz.LINK_URI, "from": fitz.Rect(72, 690, 200, 715), "uri": url})
        doc.save(src)
        doc.close()
        dest = tmp_path / "out.pdf"

        redact_file(src, dest, True)

        result = fitz.open(dest)
        text = result[0].get_text()
        links = result[0].get_links()
        result.close()
        assert url not in text
        assert len(links) == 1
        assert links[0]["uri"] == url


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

    def test_screenshot_embedded_in_a_real_text_page_is_ocr_redacted_in_place(self, tmp_path) -> None:
        # A page with substantial real text plus an embedded screenshot (not
        # rerouted to whole-page rasterization, per the test above) must
        # still have that screenshot's own sensitive content OCR-redacted --
        # not silently left untouched just because the page has real text.
        img_path = tmp_path / "screenshot.png"
        image = Image.new("RGB", (900, 200), "white")
        draw = ImageDraw.Draw(image)
        draw.text((20, 20), "Customer_email: jane.doe@example.com", fill="black", font=_FONT)
        image.save(img_path)

        src = tmp_path / "doc.pdf"
        doc = fitz.open()
        page = doc.new_page()
        page.insert_image(fitz.Rect(72, 100, 972, 300), filename=str(img_path))
        page.insert_text((72, 72), "See the attached screenshot for the customer's order details.")
        doc.save(src)
        doc.close()
        dest = tmp_path / "out.pdf"

        redact_file(src, dest, True)

        result = fitz.open(dest)
        page_text = result[0].get_text()
        assert "attached screenshot" in page_text  # real text path preserves non-sensitive prose

        recovered_images = result[0].get_images(full=True)
        assert len(recovered_images) == 1
        raw = result.extract_image(recovered_images[0][0])["image"]
        out_image = Image.open(io.BytesIO(raw))
        recovered_text = pytesseract.image_to_string(out_image)
        result.close()

        assert "jane.doe@example.com" not in recovered_text
        assert b"jane.doe@example.com" not in dest.read_bytes()


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
            verify_pdf_redacted(path, [[span]])

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
        verify_pdf_redacted(path, [[span]])  # should not raise

    def test_passes_when_span_text_only_survives_inside_an_unrelated_longer_word(self, tmp_path) -> None:
        # A redacted curated name like "Kyzo" must not fail verification
        # just because the document separately contains a longer, different,
        # never-matched word that happens to start with the same letters
        # (e.g. "Kyzotech") -- a plain substring check can't tell the two
        # apart, but the word-boundary rule the detector itself used to
        # decide "Kyzotech" was never a match in the first place must also
        # apply here, or every short curated name risks failing verification
        # on unrelated document text.
        path = tmp_path / "good.pdf"
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "See the Kyzotech documentation for details.")
        doc.save(path)
        doc.close()

        span = Span(text="Kyzo", entity_type="COMPANY_NAME", confidence=1.0, source="company_list", start=8, end=12)
        verify_pdf_redacted(path, [[span]])  # should not raise

    def test_raises_when_span_text_recoverable_as_its_own_word(self, tmp_path) -> None:
        # The word-boundary awareness above must not make the check too
        # lenient -- a genuine, still-visible standalone occurrence must
        # still fail.
        path = tmp_path / "bad.pdf"
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "Still working with Kyzo on this deal.")
        doc.save(path)
        doc.close()

        span = Span(text="Kyzo", entity_type="COMPANY_NAME", confidence=1.0, source="company_list", start=8, end=12)
        with pytest.raises(PdfRedactionVerificationError):
            verify_pdf_redacted(path, [[span]])

    def test_bare_first_name_passes_when_only_leaked_via_another_names_visible_prefix(
        self, tmp_path
    ) -> None:
        """A standalone "John" span on one page, redacted down to just "J",
        must not be flagged as still-recoverable merely because a
        *different*, correctly-redacted "John Smith" span on another page
        legitimately shows "John" as its own length-scaled visible prefix
        (PLAN.md 2.3). Word-boundary matching alone (`_recoverable`) doesn't
        help here, since "John" is a genuine whole-word match inside "John
        Smith" -- only per-page scoping avoids the false positive.
        """
        path = tmp_path / "names.pdf"
        doc = fitz.open()
        page0 = doc.new_page()
        page0.insert_text((72, 72), "J")
        page1 = doc.new_page()
        page1.insert_text((72, 72), "John xxxxxx")
        doc.save(path)
        doc.close()

        bare_name = Span(
            text="John",
            entity_type="PERSON_NAME",
            confidence=1.0,
            source="claude",
            start=0,
            end=4,
        )
        full_name = Span(
            text="John Smith",
            entity_type="PERSON_NAME",
            confidence=1.0,
            source="claude",
            start=0,
            end=10,
        )
        verify_pdf_redacted(path, [[bare_name], [full_name]])  # should not raise

    def test_short_at_mention_does_not_fail_verification(self, tmp_path) -> None:
        # A bare "@O" out of an unrelated sentence is too short a mention to
        # meaningfully verify -- found via a real document where one failed
        # verification purely because a 2-character needle has a real chance
        # of coincidentally turning up somewhere in the file, not because it
        # was an actual leak. Below MIN_USERNAME_MENTION_LENGTH, so skipped
        # by both the text-extraction and raw-bytes checks entirely.
        path = tmp_path / "doc.pdf"
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "Some coincidental @O text sitting on the page.")
        doc.save(path)
        doc.close()

        span = Span(
            text="@O",
            entity_type="USERNAME_MENTION",
            confidence=1.0,
            source="regex",
            start=19,
            end=21,
        )
        verify_pdf_redacted(path, [[span]])  # should not raise despite "@O" still visible

    def test_four_character_at_mention_still_fails_verification(self, tmp_path) -> None:
        # The exemption is strictly for mentions *below* the minimum -- a
        # mention at or above it must still be caught if it wasn't redacted.
        path = tmp_path / "doc.pdf"
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "Reviewed by @abcd on this PR.")
        doc.save(path)
        doc.close()

        span = Span(
            text="@abcd",
            entity_type="USERNAME_MENTION",
            confidence=1.0,
            source="regex",
            start=12,
            end=17,
        )
        with pytest.raises(PdfRedactionVerificationError):
            verify_pdf_redacted(path, [[span]])


class TestIgnoreVerifyFailure:
    """--ignore-verify-failure: a verification failure should keep the
    output file and warn instead of deleting it and raising -- for
    emergencies where losing an expensive redaction pass entirely is worse
    than shipping output that needs manual review.
    """

    def test_deletes_output_and_raises_by_default(self, tmp_path, monkeypatch) -> None:
        src = tmp_path / "doc.pdf"
        _make_pdf(src, ["Contact jane@example.com."])
        dest = tmp_path / "out.pdf"

        def _always_fails(*args, **kwargs):
            raise PdfRedactionVerificationError("boom")

        monkeypatch.setattr("audit_redactor.handlers.pdf_handler.verify_pdf_redacted", _always_fails)

        with pytest.raises(PdfRedactionVerificationError):
            redact_file(src, dest, True)

        assert not dest.exists()

    def test_keeps_output_and_warns_when_flag_set(self, tmp_path, monkeypatch, capsys) -> None:
        src = tmp_path / "doc.pdf"
        _make_pdf(src, ["Contact jane@example.com."])
        dest = tmp_path / "out.pdf"

        def _always_fails(*args, **kwargs):
            raise PdfRedactionVerificationError("boom")

        monkeypatch.setattr("audit_redactor.handlers.pdf_handler.verify_pdf_redacted", _always_fails)
        configure_ignore_verify_failure(True)

        result = redact_file(src, dest, True)

        assert result == dest
        assert dest.exists()
        assert "⚠️" in capsys.readouterr().out
