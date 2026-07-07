"""Regex core detectors: AWS account numbers, AWS access key IDs, phone
numbers, emails, @-mention usernames, and URLs (PLAN.md 2.3, build phase 2).

These are the highest-confidence detectors in the pipeline (PLAN.md 2.8 step
1) -- every span they emit is applied immediately, with no NER/Claude
round-trip. `confidence=1.0` reflects that trust, not a probability estimate.
"""

from __future__ import annotations

import re

from audit_redactor.detectors.api_keys import API_KEY_DETECTORS
from audit_redactor.detectors.base import EntityType, Span
from audit_redactor.detectors.date_time import find_date_time_ranges

# Matches an AWS account ID either embedded in an ARN (`arn:aws:...::123456789012:...`)
# or written bare, as 12 contiguous digits or the AWS console's 4-4-4
# hyphenated display format (e.g. "1234-5678-9012"). A single alternation is
# used (rather than two separate regexes) so a digit run inside an ARN is
# never also re-matched by the bare-digits branch.
_AWS_ACCOUNT_RE = re.compile(
    r"arn:aws[a-zA-Z0-9-]*:[a-zA-Z0-9-]*:[a-zA-Z0-9-]*:(?P<arn_id>\d{12}):"
    r"|(?<!\d)(?P<bare_id>\d{4}-\d{4}-\d{4}|\d{12})(?!\d)"
)

# AWS access key IDs are always exactly 20 characters: one of a fixed set of
# 4-letter type prefixes (sourced from AWS's own "unique identifiers" docs --
# not guaranteed exhaustive if AWS ever adds a new prefix) followed by 16
# uppercase alphanumeric characters. AKIA (long-term access key) and ASIA
# (temporary/STS access key) are the two seen day to day; the rest identify
# other IAM resource types but share the exact same shape.
_AWS_ACCESS_KEY_RE = re.compile(
    r"(?<![A-Z0-9])(?:ABIA|ACCA|AGPA|AIDA|AIPA|AKIA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)"
    r"[A-Z0-9]{16}(?![A-Z0-9])"
)

# Phone numbers are only matched when they carry a separator or a leading
# "+" -- a bare 12-digit run is deliberately left to the AWS detector above,
# so the two detectors don't disagree about the same digits (AWS masks all
# but the last 4 digits; phone numbers are redacted completely).
_PHONE_RE = re.compile(
    r"(?<!\w)(?:"
    r"\+\d{7,14}"
    r"|(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?\d{2,4}(?:[\s.-]\d{2,4}){1,3}"
    r")(?!\w)"
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}")

# @-mention style usernames (GitHub, Slack, Notion, Jira, etc.), e.g. "@octocat".
_MENTION_RE = re.compile(r"(?<!\w)@[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\b")

_SCHEME_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"')\]]+", re.IGNORECASE)
_WWW_URL_RE = re.compile(r"\bwww\.[^\s<>\"')\]]+", re.IGNORECASE)


class AwsAccountIdDetector:
    def detect(self, text: str) -> list[Span]:
        spans = []
        for m in _AWS_ACCOUNT_RE.finditer(text):
            group = "arn_id" if m.group("arn_id") else "bare_id"
            start, end = m.span(group)
            spans.append(
                Span(
                    text=m.group(group),
                    entity_type=EntityType.AWS_ACCOUNT_ID,
                    confidence=1.0,
                    source="regex",
                    start=start,
                    end=end,
                )
            )
        return spans


class PhoneNumberDetector:
    def detect(self, text: str) -> list[Span]:
        # A date/time shape (e.g. "2026-07-06", "17.55.28", a CloudTrail
        # "20260516T1805Z") is unambiguously not a phone number, and
        # redacting it actively harms auditability -- knowing *when*
        # evidence is from is the point of keeping a document's dates
        # legible. See detectors/date_time.py.
        excluded = find_date_time_ranges(text)
        spans = []
        for m in _PHONE_RE.finditer(text):
            if any(m.start() < end and start < m.end() for start, end in excluded):
                continue
            spans.append(
                Span(
                    text=m.group(),
                    entity_type=EntityType.PHONE_NUMBER,
                    confidence=1.0,
                    source="regex",
                    start=m.start(),
                    end=m.end(),
                )
            )
        return spans


class AwsAccessKeyIdDetector:
    def detect(self, text: str) -> list[Span]:
        return [
            Span(
                text=m.group(),
                entity_type=EntityType.AWS_ACCESS_KEY_ID,
                confidence=1.0,
                source="regex",
                start=m.start(),
                end=m.end(),
            )
            for m in _AWS_ACCESS_KEY_RE.finditer(text)
        ]


class EmailDetector:
    def detect(self, text: str) -> list[Span]:
        return [
            Span(
                text=m.group(),
                entity_type=EntityType.EMAIL,
                confidence=1.0,
                source="regex",
                start=m.start(),
                end=m.end(),
            )
            for m in _EMAIL_RE.finditer(text)
        ]


class UsernameMentionDetector:
    def detect(self, text: str) -> list[Span]:
        return [
            Span(
                text=m.group(),
                entity_type=EntityType.USERNAME_MENTION,
                confidence=1.0,
                source="regex",
                start=m.start(),
                end=m.end(),
            )
            for m in _MENTION_RE.finditer(text)
        ]


class UrlDetector:
    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []
        covered: list[tuple[int, int]] = []
        for m in _SCHEME_URL_RE.finditer(text):
            spans.append(
                Span(
                    text=m.group(),
                    entity_type=EntityType.URL,
                    confidence=1.0,
                    source="regex",
                    start=m.start(),
                    end=m.end(),
                )
            )
            covered.append(m.span())
        for m in _WWW_URL_RE.finditer(text):
            if any(cstart <= m.start() < cend for cstart, cend in covered):
                continue  # already part of a scheme-prefixed URL match above
            spans.append(
                Span(
                    text=m.group(),
                    entity_type=EntityType.URL,
                    confidence=1.0,
                    source="regex",
                    start=m.start(),
                    end=m.end(),
                )
            )
        return spans


# Exposed for detectors/platform_identity.py's identity-URL discovery, which
# needs to find the same URLs this module already matches without
# duplicating the regex.
URL_PATTERNS = (_SCHEME_URL_RE, _WWW_URL_RE)


REGEX_DETECTORS = [
    AwsAccountIdDetector(),
    AwsAccessKeyIdDetector(),
    PhoneNumberDetector(),
    EmailDetector(),
    UsernameMentionDetector(),
    UrlDetector(),
    *API_KEY_DETECTORS,
]


def run_regex_core(text: str) -> list[Span]:
    """Run every regex detector and return the combined span list."""
    spans: list[Span] = []
    for detector in REGEX_DETECTORS:
        spans.extend(detector.detect(text))
    return spans
