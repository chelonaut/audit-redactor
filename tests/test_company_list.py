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
