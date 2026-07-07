"""Claude API augmentation pass (PLAN.md 2.8 steps 3-6, build phase 9).

Runs only when a Claude API key is available and `--offline` is not set --
strictly additive on top of the deterministic regex/company-list detectors,
never a dependency for baseline safety (PLAN.md 2.8's local-first ordering:
the document is already materially redacted before this pass ever runs).

Claude is shown the document text *after* the deterministic detectors' spans
have already been masked, and is asked to report only the entity mentions it
still finds -- keeping what leaves the local environment to a minimum and
keeping the model's job to "find what's left" rather than "find everything".

Claude never reports character offsets (that's arithmetic LLMs are
unreliable at); it reports verbatim substrings via a strict tool call, and
this module locates every occurrence of each substring in the *original*
text itself via literal, word-bounded search. A substring that can't be
found verbatim is dropped -- this doubles as PLAN.md 2.8 step 5's mandated
grounding/verbatim check, since a hallucinated or paraphrased span simply
won't match anything.
"""

from __future__ import annotations

import os
import re
import warnings

from anthropic import Anthropic, APIError

from audit_redactor.appliers.text import redact_text
from audit_redactor.detectors.base import EntityType, Span

# Cost-sensitive by design (PLAN.md 2.9: "~$5-14 per 1000 documents at
# Haiku/Sonnet pricing") -- this is a bulk, per-document extraction pass, not
# an open-ended reasoning task, so Sonnet rather than Opus is the deliberate
# default here. Callers needing Opus-grade recall despite the cost can pass
# `model=` explicitly to `run_claude_augmentation`.
DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_MAX_TOKENS = 4096

# Restricted to the two entity types PLAN.md 2.8 scopes this pass to --
# everything else (emails, phones, URLs, AWS IDs, curated company names) is
# already handled deterministically upstream at full confidence.
_ENTITY_TYPES = (EntityType.PERSON_NAME, EntityType.COMPANY_NAME)

_TOOL = {
    "name": "report_pii_spans",
    "description": (
        "Report every DISTINCT person name and company/organization name "
        'mentioned anywhere in the document that is NOT already hidden '
        'behind a "(REDACTED)" placeholder or a run of x characters. Report '
        "each distinct name only once, even if it appears many times in the "
        "document -- every literal occurrence will be located and redacted "
        "automatically downstream, so there is no need to enumerate repeats."
    ),
    "strict": True,
    "input_schema": {
        "type": "object",
        "properties": {
            "spans": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": (
                                "The exact substring as it appears in the document "
                                "-- verbatim, no paraphrasing or normalizing."
                            ),
                        },
                        "entity_type": {
                            "type": "string",
                            "enum": list(_ENTITY_TYPES),
                        },
                    },
                    "required": ["text", "entity_type"],
                    "additionalProperties": False,
                },
            }
        },
        "required": ["spans"],
        "additionalProperties": False,
    },
}

_SYSTEM_PROMPT = (
    "You are the review step of an automated document redaction pipeline. "
    "You will be shown a document whose sensitive spans have already been "
    'redacted -- replaced with the literal placeholder "(REDACTED)" or '
    "masked with runs of the letter x. Find any remaining PERSON names or "
    "COMPANY/organization names in the visible text that were missed.\n\n"
    "Some documents (exported tables, issue trackers, logs) contain dozens "
    "or hundreds of rows repeating a much smaller set of distinct names -- "
    "you only need to report each distinct name ONCE; every literal "
    "occurrence in the document will be found and redacted automatically "
    "afterward, so there is no need to track or list repeats yourself. Read "
    "the ENTIRE document from beginning to end before responding -- do not "
    "stop partway through a long table or list. A name missed here is a "
    "real information leak, so completeness matters more than a short "
    "answer: if a document genuinely contains dozens of distinct names, "
    "report all of them.\n\n"
    "Call report_pii_spans with every one you find, as exact verbatim "
    "substrings (do not include surrounding words, do not paraphrase or "
    "normalize). Do not report anything inside an already-redacted span. If "
    "you find nothing, call the tool with an empty spans list."
)


def claude_api_key_available(api_key: str | None = None) -> bool:
    return bool(api_key or os.environ.get("ANTHROPIC_API_KEY"))


def _find_grounded_spans(
    needle: str, entity_type: str, haystack: str, exclude: list[tuple[int, int]]
) -> list[Span]:
    """Every word-bounded, literal occurrence of `needle` in `haystack`,
    skipping any that overlap an already-redacted range in `exclude`.

    Word-bounding (same convention as the curated company-name matcher)
    keeps a short reported name from spuriously matching as a substring of
    an unrelated longer word.
    """
    if not needle:
        return []
    pattern = re.compile(r"(?<!\w)" + re.escape(needle) + r"(?!\w)")
    spans = []
    for m in pattern.finditer(haystack):
        if any(m.start() < end and start < m.end() for start, end in exclude):
            continue
        spans.append(
            Span(
                text=m.group(),
                entity_type=entity_type,
                confidence=1.0,
                source="claude",
                start=m.start(),
                end=m.end(),
            )
        )
    return spans


def run_claude_augmentation(
    text: str,
    existing_spans: list[Span],
    *,
    offline: bool = False,
    api_key: str | None = None,
    model: str = DEFAULT_MODEL,
    client: Anthropic | None = None,
) -> list[Span]:
    """Ask Claude to find PERSON_NAME/COMPANY_NAME spans the local detectors
    missed, and return them as fully-grounded `Span`s against `text`.

    Returns `[]` (never raises) when `offline` is set, no API key is
    available, or the API call itself fails -- PLAN.md 2.8: Claude is
    strictly additive, never a dependency for baseline safety. An API
    failure emits a warning rather than failing silently, so a persistently
    broken key doesn't go unnoticed.
    """
    if offline or not claude_api_key_available(api_key):
        return []

    partially_redacted = redact_text(text, existing_spans)
    if not partially_redacted.strip():
        return []

    anthropic_client = client or Anthropic(api_key=api_key)
    try:
        response = anthropic_client.messages.create(
            model=model,
            max_tokens=DEFAULT_MAX_TOKENS,
            system=_SYSTEM_PROMPT,
            tools=[_TOOL],
            tool_choice={"type": "tool", "name": "report_pii_spans"},
            messages=[{"role": "user", "content": partially_redacted}],
        )
    except APIError as exc:
        warnings.warn(f"Claude augmentation pass skipped: {exc}", RuntimeWarning, stacklevel=2)
        return []

    tool_use = next((block for block in response.content if block.type == "tool_use"), None)
    if tool_use is None:
        return []

    exclude = [(span.start, span.end) for span in existing_spans]
    found: list[Span] = []
    for item in tool_use.input.get("spans", []):
        entity_type = item.get("entity_type")
        span_text = item.get("text", "")
        if entity_type not in _ENTITY_TYPES:
            continue
        found.extend(_find_grounded_spans(span_text, entity_type, text, exclude))
    return found
