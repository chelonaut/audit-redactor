from audit_redactor.detectors.base import EntityType
from audit_redactor.detectors.regex_detectors import (
    AwsAccessKeyIdDetector,
    AwsAccountIdDetector,
    EmailDetector,
    PhoneNumberDetector,
    UrlDetector,
    UsernameMentionDetector,
    run_regex_core,
)


def _texts(spans) -> set[str]:
    return {s.text for s in spans}


class TestAwsAccountIdDetector:
    def setup_method(self) -> None:
        self.detector = AwsAccountIdDetector()

    def test_bare_12_digit_account_id(self) -> None:
        spans = self.detector.detect("AWS account: 123456789012 is the target.")
        assert _texts(spans) == {"123456789012"}
        assert spans[0].entity_type == EntityType.AWS_ACCOUNT_ID

    def test_hyphenated_account_id(self) -> None:
        spans = self.detector.detect("Account ID 1234-5678-9012 was used.")
        assert _texts(spans) == {"1234-5678-9012"}

    def test_account_id_embedded_in_arn(self) -> None:
        text = "Role: arn:aws:iam::123456789012:role/CloudTrailRole"
        spans = self.detector.detect(text)
        # Only the 12-digit account ID is captured, not the whole ARN.
        assert _texts(spans) == {"123456789012"}
        span = spans[0]
        assert text[span.start : span.end] == "123456789012"

    def test_arn_digits_not_double_counted(self) -> None:
        text = "arn:aws:iam::123456789012:role/CloudTrailRole and also 111122223333"
        spans = self.detector.detect(text)
        assert _texts(spans) == {"123456789012", "111122223333"}
        assert len(spans) == 2

    def test_no_false_positive_on_non_12_digit_numbers(self) -> None:
        spans = self.detector.detect("Invoice #4532 total $199.99, year 2026.")
        assert spans == []


class TestPhoneNumberDetector:
    def setup_method(self) -> None:
        self.detector = PhoneNumberDetector()

    def test_us_hyphenated_format(self) -> None:
        spans = self.detector.detect("Call me at 555-123-4567 tomorrow.")
        assert _texts(spans) == {"555-123-4567"}
        assert spans[0].entity_type == EntityType.PHONE_NUMBER

    def test_us_parens_format(self) -> None:
        spans = self.detector.detect("Office: (555) 123-4567.")
        assert _texts(spans) == {"(555) 123-4567"}

    def test_international_plain_digits(self) -> None:
        spans = self.detector.detect("Reach us on +15551234567 anytime.")
        assert _texts(spans) == {"+15551234567"}

    def test_uk_spaced_format(self) -> None:
        spans = self.detector.detect("UK office: +44 20 7946 0958.")
        assert _texts(spans) == {"+44 20 7946 0958"}

    def test_bare_12_digit_run_not_matched_as_phone(self) -> None:
        # No separators and no leading '+' -- left to the AWS detector instead,
        # so the two detectors never disagree about the same digit run.
        spans = self.detector.detect("Account: 123456789012")
        assert spans == []

    def test_iso_date_not_matched_as_phone(self) -> None:
        spans = self.detector.detect("Screenshot 2026-07-06 at 17.55.28.png")
        assert spans == []

    def test_iso_datetime_not_matched_as_phone(self) -> None:
        spans = self.detector.detect("Exported at 2026-07-06T17:55:28Z for the audit.")
        assert spans == []

    def test_slash_date_not_matched_as_phone(self) -> None:
        spans = self.detector.detect("Printed 06/07/2026 for the record.")
        assert spans == []

    def test_implausible_date_shape_still_matched_as_phone(self) -> None:
        # Month 13 doesn't exist -- this is not a real date, so it falls
        # back to being treated as an ordinary separator-shaped number.
        spans = self.detector.detect("Reference 2026-13-45 was used.")
        assert _texts(spans) == {"2026-13-45"}

    def test_real_phone_number_with_short_groups_still_matched(self) -> None:
        # Shape alone ("NN-NN-NNNN") could look date-ish, but the group
        # lengths here (2-2-4, not the compact date shapes) don't collide
        # with anything find_date_time_ranges recognizes.
        spans = self.detector.detect("Ext 12-34-5678 please.")
        assert _texts(spans) == {"12-34-5678"}

    def test_partial_year_month_date_not_matched_as_phone(self) -> None:
        # "2021-06" (year-month, no day) is only 2 groups / 6 digits -- not a
        # 3-component date find_date_time_ranges recognizes, and not enough
        # digits to plausibly be a phone number either. Found via a real
        # document where this was misredacted.
        spans = self.detector.detect("Report period: 2021-06 summary")
        assert spans == []

    def test_partial_hour_minute_time_not_matched_as_phone(self) -> None:
        # "16.13" (hour.minute, no seconds) is only 2 groups / 4 digits --
        # not a 3-component HH.MM.SS time find_date_time_ranges recognizes,
        # and not enough digits to plausibly be a phone number either.
        spans = self.detector.detect("Logged at 16.13 today")
        assert spans == []

    def test_short_local_phone_number_still_matched(self) -> None:
        # A bare 7-digit local number (no area code) is the shortest real
        # phone format this project supports -- the digit-count floor must
        # not exclude it while excluding the 4-6 digit date/time fragments
        # above.
        spans = self.detector.detect("Call me at 555-1234 now.")
        assert _texts(spans) == {"555-1234"}

    def test_below_minimum_digit_count_not_matched(self) -> None:
        # Below the 7-digit floor, a separator-shaped run stays unmatched
        # even when it isn't a recognized date/time -- e.g. two arbitrary
        # 2-digit groups.
        spans = self.detector.detect("Section 12-34 of the report.")
        assert spans == []


class TestAwsAccessKeyIdDetector:
    def setup_method(self) -> None:
        self.detector = AwsAccessKeyIdDetector()

    def test_akia_long_term_key(self) -> None:
        spans = self.detector.detect("Access key AKIAIOSFODNN7EXAMPLE was used.")
        assert _texts(spans) == {"AKIAIOSFODNN7EXAMPLE"}
        assert spans[0].entity_type == EntityType.AWS_ACCESS_KEY_ID

    def test_asia_temporary_key(self) -> None:
        spans = self.detector.detect("Temp key ASIAV3ZUEFP6AAAAAAAA in use.")
        assert _texts(spans) == {"ASIAV3ZUEFP6AAAAAAAA"}

    def test_two_different_keys_both_found(self) -> None:
        text = "ASIAV3ZUEFP6AAAAAAAA and ASIAV3ZUEFP6BBBBBBBB"
        spans = self.detector.detect(text)
        assert _texts(spans) == {"ASIAV3ZUEFP6AAAAAAAA", "ASIAV3ZUEFP6BBBBBBBB"}

    def test_unrecognized_prefix_not_matched(self) -> None:
        spans = self.detector.detect("Not a key: ZZZZV3ZUEFP6AAAAAAAA")
        assert spans == []

    def test_too_short_not_matched(self) -> None:
        spans = self.detector.detect("Too short: AKIAIOSFODNN7EXAMP")
        assert spans == []

    def test_21_character_iam_unique_id_still_matched(self) -> None:
        # Regression test: AIDA-prefixed IAM user unique IDs (CloudTrail
        # principalId fields) were found, empirically, to sometimes be 21
        # characters -- one longer than an access key's 20. The suffix
        # length must be a minimum, not an exact count, or a real ID like
        # this silently goes undetected. Synthetic value, not a real ID.
        key = "AIDAQ7X9K2M4P8R1T6W3Y"
        assert len(key) == 21
        spans = self.detector.detect(f"principalId: {key}")
        assert _texts(spans) == {key}


class TestEmailDetector:
    def setup_method(self) -> None:
        self.detector = EmailDetector()

    def test_simple_email(self) -> None:
        spans = self.detector.detect("Contact jane.doe@example.com for access.")
        assert _texts(spans) == {"jane.doe@example.com"}
        assert spans[0].entity_type == EntityType.EMAIL

    def test_multiple_emails(self) -> None:
        text = "cc: alice@company.co.uk, bob+audit@sub.company.io"
        spans = self.detector.detect(text)
        assert _texts(spans) == {"alice@company.co.uk", "bob+audit@sub.company.io"}


class TestUsernameMentionDetector:
    def setup_method(self) -> None:
        self.detector = UsernameMentionDetector()

    def test_github_style_mention(self) -> None:
        spans = self.detector.detect("Reviewed by @octocat in the PR.")
        assert _texts(spans) == {"@octocat"}
        assert spans[0].entity_type == EntityType.USERNAME_MENTION

    def test_mention_with_hyphen(self) -> None:
        spans = self.detector.detect("Assigned to @jane-doe.")
        assert _texts(spans) == {"@jane-doe"}

    def test_email_local_part_not_matched_as_mention(self) -> None:
        spans = self.detector.detect("Email jane@example.com only.")
        assert spans == []


class TestUrlDetector:
    def setup_method(self) -> None:
        self.detector = UrlDetector()

    def test_https_url(self) -> None:
        spans = self.detector.detect("See https://example.com/path?x=1 for details.")
        assert _texts(spans) == {"https://example.com/path?x=1"}
        assert spans[0].entity_type == EntityType.URL

    def test_www_url_without_scheme(self) -> None:
        spans = self.detector.detect("Visit www.example.com today.")
        assert _texts(spans) == {"www.example.com"}

    def test_www_inside_scheme_url_not_double_matched(self) -> None:
        spans = self.detector.detect("Go to https://www.example.com/page now.")
        assert _texts(spans) == {"https://www.example.com/page"}
        assert len(spans) == 1


class TestRunRegexCore:
    def test_combines_all_detectors(self) -> None:
        text = (
            "AWS account 123456789012 owned by jane.doe@example.com "
            "(@jane-doe), call 555-123-4567 or see https://example.com/audit"
        )
        spans = run_regex_core(text)
        entity_types = {s.entity_type for s in spans}
        assert entity_types == {
            EntityType.AWS_ACCOUNT_ID,
            EntityType.EMAIL,
            EntityType.USERNAME_MENTION,
            EntityType.PHONE_NUMBER,
            EntityType.URL,
        }
