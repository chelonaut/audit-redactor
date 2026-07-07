from audit_redactor.detectors.base import Detector, EntityType, Span
from audit_redactor.detectors.company_list import CompanyListDetector
from audit_redactor.detectors.regex_detectors import REGEX_DETECTORS, run_regex_core
from audit_redactor.detectors.text import detect_text

__all__ = [
    "CompanyListDetector",
    "Detector",
    "EntityType",
    "REGEX_DETECTORS",
    "Span",
    "detect_text",
    "detect_text_with_claude",
    "run_regex_core",
]


def detect_text_with_claude(
    text: str, offline: bool = True, company_detector: CompanyListDetector | None = None
) -> list[Span]:
    """Local detection (regex core + curated company list) plus, when
    available, the Claude augmentation pass (PLAN.md 2.8 steps 3-6).

    The composed detector every whole-document-text handler (Markdown, HTML,
    PDF pages, images) calls instead of bare `detect_text`, so Claude
    augmentation is wired in at one place rather than per handler.
    `offline` defaults to `True` so call sites that don't care about Claude
    (unit tests, filename redaction) get local-only detection with no risk
    of an unexpected network call.

    The import below is deliberately deferred rather than module-level:
    `claude_augment.py` imports `appliers.text`, which itself imports
    `detectors.base` -- an eager top-level import here would make importing
    *any* submodule of `detectors` (even the base `Span`/`EntityType`
    import) transitively require `appliers.text` to already be loaded,
    which is circular and broke depending on which module happened to be
    imported first (worked under pytest's import order, broke as the actual
    CLI entrypoint's first import).
    """
    from audit_redactor.detectors.claude_augment import run_claude_augmentation

    spans = detect_text(text, company_detector)
    spans += run_claude_augmentation(text, spans, offline=offline)
    return spans
