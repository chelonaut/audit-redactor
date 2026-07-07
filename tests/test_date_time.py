from audit_redactor.detectors.date_time import find_date_time_ranges


def _matched(text: str) -> set[str]:
    return {text[start:end] for start, end in find_date_time_ranges(text)}


class TestFindDateTimeRanges:
    def test_iso_date(self) -> None:
        assert _matched("Filed on 2026-07-06 for review.") == {"2026-07-06"}

    def test_iso_datetime_with_z(self) -> None:
        assert _matched("Exported 2026-07-06T17:55:28Z here.") == {"2026-07-06T17:55:28Z"}

    def test_day_month_year_hyphen(self) -> None:
        assert _matched("Due 06-07-2026 sharp.") == {"06-07-2026"}

    def test_slash_date(self) -> None:
        assert _matched("Printed 06/07/2026 today.") == {"06/07/2026"}

    def test_dotted_time(self) -> None:
        assert _matched("Captured at 17.55.28 sharp.") == {"17.55.28"}

    def test_compact_iso_date_only(self) -> None:
        assert _matched("Ref 20260516 archived.") == {"20260516"}

    def test_compact_iso_datetime_with_z(self) -> None:
        # AWS CloudTrail export filename format.
        text = "814356186259_CloudTrail_us-east-1_20260516T1805Z_abc.json"
        assert _matched(text) == {"20260516T1805Z"}

    def test_compact_iso_datetime_with_seconds(self) -> None:
        assert _matched("stamp 20260516T180500Z end") == {"20260516T180500Z"}

    def test_implausible_month_rejected(self) -> None:
        # Month 13 doesn't exist.
        assert _matched("Ref 2026-13-06 is not a date.") == set()

    def test_implausible_year_rejected(self) -> None:
        # Below the plausible-year floor.
        assert _matched("Ref 1999-07-06 is not a date.") == set()

    def test_implausible_hour_rejected_in_compact_form(self) -> None:
        assert _matched("Ref 20260516T2505Z is not a time.") == set()

    def test_bare_12_digit_run_not_matched(self) -> None:
        # An AWS account ID shape -- not a date under any of these patterns.
        assert _matched("Account: 123456789012") == set()

    def test_plain_prose_yields_nothing(self) -> None:
        assert _matched("nothing date-shaped in here at all") == set()
