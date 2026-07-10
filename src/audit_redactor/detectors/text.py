"""Combined deterministic detector set for plain-text content: the regex core
plus the curated company-name matcher (PLAN.md 2.8 step 1). Every handler
that redacts raw text (Markdown now; HTML/DOM text nodes in phase 6) runs
detection through this one function so they can't drift out of sync.
"""

from __future__ import annotations

from pathlib import Path

from audit_redactor.detectors.base import Detector, Span
from audit_redactor.detectors.company_list import CompanyListDetector
from audit_redactor.detectors.regex_detectors import run_regex_core

_default_company_detector: CompanyListDetector | None = None
_default_company_data_path: Path | str | None = None


def configure_default_company_list(data_path: Path | str | None) -> None:
    """Set (or reset, via `None`) the data path the shared default
    company-name detector loads from, and drop any already-built instance so
    the next lookup rebuilds from the new path.

    Called once by the CLI at startup (per PLAN.md 2.10's "point the
    CLI/detector at a different file" escape hatch) rather than threading a
    `company_detector` parameter through every handler -- every handler and
    caller that doesn't build its own detector shares this one process-wide
    default, mirroring how `claude_augment.py`'s usage totals/circuit breaker
    are reset once per CLI invocation instead of passed down every call site.
    """
    global _default_company_detector, _default_company_data_path
    _default_company_data_path = data_path
    _default_company_detector = None


def _get_default_company_detector() -> CompanyListDetector:
    global _default_company_detector
    if _default_company_detector is None:
        _default_company_detector = CompanyListDetector(_default_company_data_path)
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
