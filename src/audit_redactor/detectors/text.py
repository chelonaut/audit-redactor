"""Combined deterministic detector set for plain-text content: the regex core
plus the curated company-name matcher (PLAN.md 2.8 step 1). Every handler
that redacts raw text (Markdown now; HTML/DOM text nodes in phase 6) runs
detection through this one function so they can't drift out of sync.
"""

from __future__ import annotations

from audit_redactor.detectors.base import Detector, Span
from audit_redactor.detectors.company_list import CompanyListDetector
from audit_redactor.detectors.regex_detectors import run_regex_core

_default_company_detector: CompanyListDetector | None = None


def _get_default_company_detector() -> CompanyListDetector:
    global _default_company_detector
    if _default_company_detector is None:
        _default_company_detector = CompanyListDetector()
    return _default_company_detector


def detect_text(
    text: str,
    company_detector: CompanyListDetector | None = None,
    identity_detector: Detector | None = None,
) -> list[Span]:
    """Run the regex core and curated company-name matcher over `text`.

    `identity_detector` (typically a `KnownIdentityDetector`, see
    detectors/platform_identity.py) is optional and merged in here --
    alongside the other always-local detectors -- rather than by callers
    concatenating spans after the fact, specifically so it's also included
    when this function feeds into `detect_text_with_claude` below: Claude
    must see an identified username already masked, the same as any other
    locally-detected span, not in plaintext.
    """
    detector = company_detector or _get_default_company_detector()
    spans = run_regex_core(text) + detector.detect(text)
    if identity_detector is not None:
        spans += identity_detector.detect(text)
    return spans
