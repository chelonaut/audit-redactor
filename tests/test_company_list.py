from audit_redactor.detectors.base import EntityType
from audit_redactor.detectors.company_list import CompanyListDetector


def _texts(spans) -> set[str]:
    return {s.text for s in spans}


class TestCompanyListDetector:
    def setup_method(self) -> None:
        self.detector = CompanyListDetector()

    def test_matches_curated_name(self) -> None:
        spans = self.detector.detect("The order was placed with Tesco last week.")
        assert _texts(spans) == {"Tesco"}
        assert spans[0].entity_type == EntityType.COMPANY_NAME
        assert spans[0].source == "company_list"

    def test_case_insensitive_match(self) -> None:
        spans = self.detector.detect("shopping at ASDA and sainsbury's today")
        assert _texts(spans) == {"ASDA", "sainsbury's"}

    def test_name_with_apostrophe(self) -> None:
        spans = self.detector.detect("Invoice from Sainsbury's dated today.")
        assert _texts(spans) == {"Sainsbury's"}

    def test_name_with_ampersand(self) -> None:
        spans = self.detector.detect("M&S reported strong earnings.")
        assert _texts(spans) == {"M&S"}

    def test_name_with_hyphen_prefix_digit(self) -> None:
        spans = self.detector.detect("Nearest 7-Eleven is two blocks away.")
        assert _texts(spans) == {"7-Eleven"}

    def test_no_match_on_unrelated_text(self) -> None:
        spans = self.detector.detect("This document contains no client names at all.")
        assert spans == []

    def test_multiple_distinct_matches(self) -> None:
        text = "Compared pricing across Tesco, Carrefour, and Mercadona this quarter."
        spans = self.detector.detect(text)
        assert _texts(spans) == {"Tesco", "Carrefour", "Mercadona"}

    def test_custom_data_path(self, tmp_path) -> None:
        custom_list = tmp_path / "custom_companies.txt"
        custom_list.write_text("# comment line\nAcme Corp\n\nGlobex\n", encoding="utf-8")
        detector = CompanyListDetector(data_path=custom_list)
        spans = detector.detect("We are auditing Acme Corp and Globex this cycle.")
        assert _texts(spans) == {"Acme Corp", "Globex"}

    def test_matches_when_document_omits_accent_from_list_entry(self, tmp_path) -> None:
        custom_list = tmp_path / "custom_companies.txt"
        custom_list.write_text("Café Central\n", encoding="utf-8")
        detector = CompanyListDetector(data_path=custom_list)
        # Document typed without the accent -- should still match, and the
        # span should preserve exactly what's in the document (no accent).
        spans = detector.detect("We audited Cafe Central last year.")
        assert _texts(spans) == {"Cafe Central"}

    def test_matches_when_document_adds_accent_not_in_list_entry(self, tmp_path) -> None:
        custom_list = tmp_path / "custom_companies.txt"
        custom_list.write_text("Cafe Central\n", encoding="utf-8")
        detector = CompanyListDetector(data_path=custom_list)
        # List entry has no accent, but the document does -- should still match.
        spans = detector.detect("We audited Café Central last year.")
        assert _texts(spans) == {"Café Central"}

    def test_span_offsets_correct_around_accented_match(self, tmp_path) -> None:
        custom_list = tmp_path / "custom_companies.txt"
        custom_list.write_text("Café Central\n", encoding="utf-8")
        detector = CompanyListDetector(data_path=custom_list)
        text = "Invoice from Café Central, dated today."
        spans = detector.detect(text)
        assert len(spans) == 1
        span = spans[0]
        assert text[span.start : span.end] == "Café Central"

    def test_matches_bare_plural_of_curated_name(self, tmp_path) -> None:
        # Without swallowing the trailing "s", the word-boundary rule that
        # keeps "Kyzo" from matching inside "Kyzotech" would also leave the
        # *entire* plural "Kyzos" completely unredacted -- silently leaking
        # the same curated name in its plural form.
        custom_list = tmp_path / "custom_companies.txt"
        custom_list.write_text("Kyzo\n", encoding="utf-8")
        detector = CompanyListDetector(data_path=custom_list)
        spans = detector.detect("Several Kyzos accounts were affected.")
        assert _texts(spans) == {"Kyzos"}

    def test_matches_possessive_of_curated_name(self, tmp_path) -> None:
        custom_list = tmp_path / "custom_companies.txt"
        custom_list.write_text("Kyzo\n", encoding="utf-8")
        detector = CompanyListDetector(data_path=custom_list)
        spans = detector.detect("Kyzo's account was affected.")
        # The apostrophe already isn't a word character, so only the bare
        # name itself needs to be swallowed -- "'s" is left visible, which
        # reveals nothing on its own.
        assert _texts(spans) == {"Kyzo"}

    def test_does_not_match_unrelated_longer_word_sharing_a_prefix(self, tmp_path) -> None:
        custom_list = tmp_path / "custom_companies.txt"
        custom_list.write_text("Kyzo\n", encoding="utf-8")
        detector = CompanyListDetector(data_path=custom_list)
        spans = detector.detect("See the Kyzotech documentation for details.")
        assert spans == []


class TestConnectorTolerance:
    """"&"/"+"/"and" are interchangeable, with or without surrounding
    whitespace, regardless of which spelling the curated list happens to use.
    """

    def _detector(self, tmp_path, curated_name: str) -> CompanyListDetector:
        custom_list = tmp_path / "custom_companies.txt"
        custom_list.write_text(f"{curated_name}\n", encoding="utf-8")
        return CompanyListDetector(data_path=custom_list)

    def test_ampersand_in_list_matches_plus_and_and_in_document(self, tmp_path) -> None:
        detector = self._detector(tmp_path, "Example & Co")
        for variant in ["Example & Co", "Example+Co", "Example + Co", "Example&Co", "Example and Co"]:
            spans = detector.detect(f"Invoice from {variant} dated today.")
            assert _texts(spans) == {variant}, variant

    def test_plus_in_list_with_no_whitespace_matches_spaced_ampersand(self, tmp_path) -> None:
        detector = self._detector(tmp_path, "Example+Co")
        spans = detector.detect("Invoice from Example & Co dated today.")
        assert _texts(spans) == {"Example & Co"}

    def test_and_in_list_matches_ampersand_in_document(self, tmp_path) -> None:
        detector = self._detector(tmp_path, "Example and Co")
        spans = detector.detect("Invoice from Example & Co dated today.")
        assert _texts(spans) == {"Example & Co"}

    def test_and_connector_requires_word_boundaries_not_just_any_and_substring(self, tmp_path) -> None:
        # "and" must be its own word in the document -- it shouldn't turn a
        # curated "Example and Co" into matching unrelated text like
        # "Example Andorra Co" or "ExampleandCo" with no real word break.
        detector = self._detector(tmp_path, "Example and Co")
        spans = detector.detect("Example Andorra Co is not the same company.")
        assert spans == []

    def test_multiple_connectors_in_one_name(self, tmp_path) -> None:
        detector = self._detector(tmp_path, "A & B & C")
        spans = detector.detect("Invoice from A and B + C dated today.")
        assert _texts(spans) == {"A and B + C"}

    def test_plural_still_works_alongside_connector_tolerance(self, tmp_path) -> None:
        detector = self._detector(tmp_path, "Example & Co")
        spans = detector.detect("Several Example+Cos accounts were affected.")
        assert _texts(spans) == {"Example+Cos"}


class TestApostropheTolerance:
    """A document commonly drops the apostrophe a curated name has baked in
    ("Examples" for a curated "Example's") -- this must still match, since
    the apostrophe is otherwise just a literal character absent from the
    document text entirely.
    """

    def _detector(self, tmp_path, curated_name: str) -> CompanyListDetector:
        custom_list = tmp_path / "custom_companies.txt"
        custom_list.write_text(f"{curated_name}\n", encoding="utf-8")
        return CompanyListDetector(data_path=custom_list)

    def test_matches_with_apostrophe_omitted(self, tmp_path) -> None:
        detector = self._detector(tmp_path, "Example's")
        spans = detector.detect("Invoice from Examples dated today.")
        assert _texts(spans) == {"Examples"}

    def test_matches_with_curly_apostrophe_in_document(self, tmp_path) -> None:
        detector = self._detector(tmp_path, "Example's")
        spans = detector.detect("Invoice from Example’s dated today.")
        assert _texts(spans) == {"Example’s"}

    def test_matches_exact_spelling_too(self, tmp_path) -> None:
        detector = self._detector(tmp_path, "Example's")
        spans = detector.detect("Invoice from Example's dated today.")
        assert _texts(spans) == {"Example's"}

    def test_apostrophe_not_at_the_end_still_tolerated(self, tmp_path) -> None:
        detector = self._detector(tmp_path, "O'Example")
        spans = detector.detect("Invoice from OExample dated today.")
        assert _texts(spans) == {"OExample"}

    def test_does_not_match_unrelated_word(self, tmp_path) -> None:
        detector = self._detector(tmp_path, "Example's")
        spans = detector.detect("Examplesburg is a different place entirely.")
        assert spans == []


class TestLeadingThePrefixTolerance:
    """A curated name starting with "The " also matches a document that
    drops that prefix -- the reverse direction (bare curated name, "The "
    present in the document) already works via the ordinary word-boundary
    rule and needs no special casing.
    """

    def _detector(self, tmp_path, curated_name: str) -> CompanyListDetector:
        custom_list = tmp_path / "custom_companies.txt"
        custom_list.write_text(f"{curated_name}\n", encoding="utf-8")
        return CompanyListDetector(data_path=custom_list)

    def test_matches_document_without_the_prefix(self, tmp_path) -> None:
        detector = self._detector(tmp_path, "The Example Shop")
        spans = detector.detect("Invoice from Example Shop dated today.")
        assert _texts(spans) == {"Example Shop"}

    def test_still_matches_document_with_the_prefix(self, tmp_path) -> None:
        detector = self._detector(tmp_path, "The Example Shop")
        spans = detector.detect("Invoice from The Example Shop dated today.")
        # Both the full "The Example Shop" and (from the stripped variant)
        # the nested "Example Shop" match here -- harmless, overlapping
        # duplicates that `merge_spans` (appliers/text.py) resolves by
        # keeping the longer/earlier-starting one at redaction time.
        assert "The Example Shop" in _texts(spans)

    def test_bare_curated_name_still_matches_with_the_prefix_in_document(self, tmp_path) -> None:
        # The reverse direction: no special handling needed at all, since
        # "The " is just preceding context around an already-matching word.
        detector = self._detector(tmp_path, "Example Shop")
        spans = detector.detect("Invoice from The Example Shop dated today.")
        assert _texts(spans) == {"Example Shop"}

    def test_combines_with_connector_and_apostrophe_tolerance(self, tmp_path) -> None:
        detector = self._detector(tmp_path, "The Example's & Co")
        spans = detector.detect("Invoice from Examples and Co dated today.")
        assert _texts(spans) == {"Examples and Co"}
