from audit_redactor.appliers.text import merge_spans, redact_text
from audit_redactor.detectors.base import EntityType, Span


def _span(entity_type: str, text: str, start: int, confidence: float = 1.0) -> Span:
    return Span(
        text=text,
        entity_type=entity_type,
        confidence=confidence,
        source="regex",
        start=start,
        end=start + len(text),
    )


class TestApplySpanText:
    def test_aws_account_id_keeps_last_4_digits(self) -> None:
        text = "id 123456789012 end"
        span = _span(EntityType.AWS_ACCOUNT_ID, "123456789012", 3)
        assert redact_text(text, [span]) == "id xxxxxxxx9012 end"

    def test_aws_account_id_hyphenated_keeps_separators(self) -> None:
        text = "id 1234-5678-9012 end"
        span = _span(EntityType.AWS_ACCOUNT_ID, "1234-5678-9012", 3)
        assert redact_text(text, [span]) == "id xxxx-xxxx-9012 end"

    def test_phone_number_masks_all_digits(self) -> None:
        text = "call 555-123-4567 now"
        span = _span(EntityType.PHONE_NUMBER, "555-123-4567", 5)
        assert redact_text(text, [span]) == "call xxx-xxx-xxxx now"

    def test_aws_access_key_id_keeps_last_4_characters(self) -> None:
        text = "key AKIAIOSFODNN7EXAMPLE end"
        span = _span(EntityType.AWS_ACCESS_KEY_ID, "AKIAIOSFODNN7EXAMPLE", 4)
        assert redact_text(text, [span]) == "key xxxxxxxxxxxxxxxxMPLE end"

    def test_short_aws_access_key_id_left_as_is(self) -> None:
        text = "key ABCD end"
        span = _span(EntityType.AWS_ACCESS_KEY_ID, "ABCD", 4)
        assert redact_text(text, [span]) == "key ABCD end"

    def test_person_name_keeps_first_4_characters(self) -> None:
        text = "met Jonathan Smith today"
        span = _span(EntityType.PERSON_NAME, "Jonathan Smith", 4)
        result = redact_text(text, [span])
        assert result == "met Jona" + "x" * (len("Jonathan Smith") - 4) + " today"

    def test_short_person_name_left_as_is(self) -> None:
        text = "met Al today"
        span = _span(EntityType.PERSON_NAME, "Al", 4)
        assert redact_text(text, [span]) == "met Al today"

    def test_email_url_company_username_fully_redacted(self) -> None:
        text = "a@b.com Tesco @bob https://x.com"
        spans = [
            _span(EntityType.EMAIL, "a@b.com", 0),
            _span(EntityType.COMPANY_NAME, "Tesco", 8),
            _span(EntityType.USERNAME_MENTION, "@bob", 14),
            _span(EntityType.URL, "https://x.com", 19),
        ]
        assert redact_text(text, spans) == "(REDACTED) (REDACTED) (REDACTED) (REDACTED)"


class TestMergeSpans:
    def test_fully_contained_span_dropped(self) -> None:
        outer = _span(EntityType.URL, "https://www.example.com", 0)
        inner = _span(EntityType.EMAIL, "www.example.com", 8)
        merged = merge_spans([outer, inner])
        assert merged == [outer]

    def test_non_overlapping_spans_both_kept(self) -> None:
        first = _span(EntityType.EMAIL, "a@b.com", 0)
        second = _span(EntityType.URL, "https://x.com", 20)
        merged = merge_spans([second, first])
        assert merged == [first, second]
