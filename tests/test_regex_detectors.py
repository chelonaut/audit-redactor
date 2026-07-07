from audit_redactor.detectors.base import EntityType
from audit_redactor.detectors.regex_detectors import (
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
