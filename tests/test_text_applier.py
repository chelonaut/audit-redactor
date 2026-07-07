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

    def test_aws_access_key_id_keeps_prefix_and_last_4_characters(self) -> None:
        text = "key AKIAIOSFODNN7EXAMPLE end"
        span = _span(EntityType.AWS_ACCESS_KEY_ID, "AKIAIOSFODNN7EXAMPLE", 4)
        assert redact_text(text, [span]) == "key AKIAxxxxxxxxxxxxMPLE end"

    def test_short_aws_access_key_id_left_as_is(self) -> None:
        text = "key ABCDEFGH end"
        span = _span(EntityType.AWS_ACCESS_KEY_ID, "ABCDEFGH", 4)
        assert redact_text(text, [span]) == "key ABCDEFGH end"

    def test_aws_access_key_id_one_char_longer_than_threshold_masks_middle(self) -> None:
        # 9 characters -- one above the "prefix + last 4" length floor of 8
        # -- leaves exactly one character masked in the middle.
        text = "key ABCDEFGHI end"
        span = _span(EntityType.AWS_ACCESS_KEY_ID, "ABCDEFGHI", 4)
        assert redact_text(text, [span]) == "key ABCDxFGHI end"

    def test_21_character_iam_unique_id_masked_correctly(self) -> None:
        # AIDA-prefixed IAM user unique IDs (CloudTrail principalId fields)
        # were found, empirically, to sometimes be 21 characters -- one
        # longer than an access key's 20 -- confirming the masking rule
        # isn't hardcoded to exactly 20. Synthetic value, not a real ID.
        key = "AIDAQ7X9K2M4P8R1T6W3Y"
        assert len(key) == 21
        text = f"principalId: {key} end"
        span = _span(EntityType.AWS_ACCESS_KEY_ID, key, len("principalId: "))
        expected = f"principalId: {key[:4]}{'x' * (len(key) - 8)}{key[-4:]} end"
        assert redact_text(text, [span]) == expected

    def test_person_name_9_plus_chars_keeps_first_4_characters(self) -> None:
        text = "met Jonathan Smith today"
        span = _span(EntityType.PERSON_NAME, "Jonathan Smith", 4)
        result = redact_text(text, [span])
        assert result == "met Jona" + "x" * (len("Jonathan Smith") - 4) + " today"

    def test_person_name_7_or_8_chars_keeps_first_3_characters(self) -> None:
        text = "met Roberto today"
        span = _span(EntityType.PERSON_NAME, "Roberto", 4)
        assert redact_text(text, [span]) == "met Robxxxx today"

    def test_person_name_5_or_6_chars_keeps_first_2_characters(self) -> None:
        text = "met Jonah today"
        span = _span(EntityType.PERSON_NAME, "Jonah", 4)
        assert redact_text(text, [span]) == "met Joxxx today"

    def test_person_name_4_or_fewer_chars_keeps_first_1_character(self) -> None:
        # Regression test: a real document had Claude correctly identify a
        # 4-character name ("Sebb"), and the old flat "keep first 4" rule
        # masked *nothing at all* for it (there was nothing left after the
        # first 4 characters), which the post-redaction verification pass
        # correctly caught and failed the file over.
        text = "met Sebb today"
        span = _span(EntityType.PERSON_NAME, "Sebb", 4)
        assert redact_text(text, [span]) == "met Sxxx today"

    def test_person_name_2_chars_keeps_first_1_character(self) -> None:
        text = "met Al today"
        span = _span(EntityType.PERSON_NAME, "Al", 4)
        assert redact_text(text, [span]) == "met Ax today"

    def test_person_name_1_char_left_as_is(self) -> None:
        # A single character has nothing left to mask once the first
        # character is kept visible.
        text = "met X today"
        span = _span(EntityType.PERSON_NAME, "X", 4)
        assert redact_text(text, [span]) == "met X today"

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
