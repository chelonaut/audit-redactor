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
import time
import warnings
from dataclasses import dataclass

from anthropic import (
    Anthropic,
    APIConnectionError,
    APIError,
    InternalServerError,
    RateLimitError,
)

from audit_redactor.appliers.text import redact_text
from audit_redactor.detectors.base import EntityType, Span


@dataclass
class UsageTotals:
    """Running total of Claude API usage for the current process.

    Module-level rather than threaded through every call site's return value
    on purpose: this is a single-process, run-once-and-exit CLI tool, not a
    long-lived server, so the usual objection to mutable global state (which
    caller's total am I looking at?) doesn't apply -- there's only ever one
    run. Threading a usage value through detect_text_with_claude, every
    handler, pipeline.redact_file, and batch.run_batch just to report a
    number at the very end would touch far more of the codebase for a purely
    observational feature.
    """

    api_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0


_usage_totals = UsageTotals()


def get_usage_totals() -> UsageTotals:
    return _usage_totals


def reset_usage_totals() -> None:
    """Zero the running total. Call sites: the CLI entrypoint (defensive --
    a fresh process already starts at zero) and tests, so one test's calls
    don't bleed into another's assertions."""
    global _usage_totals
    _usage_totals = UsageTotals()


# Retry only genuinely transient conditions -- a permanent error (bad
# request, invalid API key) will never succeed no matter how many times
# it's retried, so retrying it would just burn the whole budget (and several
# minutes of wall-clock backoff) on something doomed from the first attempt.
_RETRYABLE_ERRORS = (RateLimitError, InternalServerError, APIConnectionError)
MAX_RETRIES = 10
INITIAL_RETRY_DELAY = 1.0  # seconds
MAX_RETRY_DELAY = 60.0  # seconds -- caps worst-case total wait to ~5 minutes

# Circuit breaker: once retries are exhausted for any single call, every
# later Claude call in this run gives up immediately rather than repeating
# the same slow, doomed retry sequence per page/chunk. Module-level for the
# same reason as UsageTotals above -- single-process, run-once CLI, not a
# long-lived server.
_circuit_breaker_open = False


def circuit_breaker_is_open() -> bool:
    return _circuit_breaker_open


def reset_circuit_breaker() -> None:
    global _circuit_breaker_open
    _circuit_breaker_open = False


def _call_claude_with_retry(anthropic_client: Anthropic, **create_kwargs):
    """Call `anthropic_client.messages.create(**create_kwargs)`, retrying
    transient failures with exponential backoff.

    Returns the response, or `None` if every retry was exhausted -- at which
    point the circuit breaker is tripped (with a warning) and the caller
    should treat this exactly like `offline`. A non-retryable `APIError`
    propagates immediately for the caller's existing handling.
    """
    global _circuit_breaker_open

    delay = INITIAL_RETRY_DELAY
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return anthropic_client.messages.create(**create_kwargs)
        except _RETRYABLE_ERRORS as exc:
            if attempt == MAX_RETRIES:
                _circuit_breaker_open = True
                warnings.warn(
                    f"Claude API failed after {MAX_RETRIES} retries ({exc}) -- "
                    "disabling the Claude augmentation pass for the rest of this "
                    "run and falling back to local-only redaction from here on.",
                    RuntimeWarning,
                    stacklevel=3,
                )
                return None
            print(
                f"    Claude API error (attempt {attempt}/{MAX_RETRIES}): {exc} "
                f"-- retrying in {delay:.0f}s...",
                flush=True,
            )
            time.sleep(delay)
            delay = min(delay * 2, MAX_RETRY_DELAY)
    return None  # unreachable, satisfies type checkers


# Cost-sensitive by design (PLAN.md 2.9: "~$5-14 per 1000 documents at
# Haiku/Sonnet pricing") -- this is a bulk, per-document extraction pass, not
# an open-ended reasoning task, so Sonnet rather than Opus is the deliberate
# default here. Callers needing Opus-grade recall despite the cost can pass
# `model=` explicitly to `run_claude_augmentation`.
DEFAULT_MODEL = "claude-sonnet-5"
# Raised from an initial 4096 after a real document (a dense, table-heavy
# issue-tracker export) used 2300-3300 output tokens on a single page purely
# reporting distinct names -- comfortably under 16000, but close enough to
# the old ceiling that a denser page could plausibly have exceeded it.
# Billing only reflects tokens actually generated, not this ceiling, so
# there's no cost downside to leaving headroom, and 16000 stays well short
# of the point where the SDK would require streaming for a non-streaming call.
DEFAULT_MAX_TOKENS = 16000

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
    available, the circuit breaker is open (see `_call_claude_with_retry`),
    or the API call itself fails after retries -- PLAN.md 2.8: Claude is
    strictly additive, never a dependency for baseline safety. A failure
    emits a warning rather than failing silently, so a persistently broken
    key (or a fully exhausted retry budget) doesn't go unnoticed.
    """
    if offline or not claude_api_key_available(api_key):
        return []

    if _circuit_breaker_open:
        return []

    partially_redacted = redact_text(text, existing_spans)
    if not partially_redacted.strip():
        return []

    anthropic_client = client or Anthropic(api_key=api_key)
    print("    Calling Claude...", flush=True)
    try:
        response = _call_claude_with_retry(
            anthropic_client,
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

    if response is None:
        # Retries exhausted -- _call_claude_with_retry already tripped the
        # circuit breaker and warned; nothing more to do here.
        return []
    _usage_totals.api_calls += 1
    _usage_totals.input_tokens += response.usage.input_tokens
    _usage_totals.output_tokens += response.usage.output_tokens

    print(
        f"    Claude responded. Claude usage so far: {_usage_totals.api_calls} API call(s), "
        f"{_usage_totals.input_tokens:,} input tokens, {_usage_totals.output_tokens:,} output tokens",
        flush=True,
    )

    if response.stop_reason == "max_tokens":
        # The tool-call response was cut off mid-generation before Claude
        # finished listing every distinct name/company it found for this
        # chunk. Whatever was reported before the cutoff is still used below
        # (better than discarding it), but recall for this chunk is not
        # complete -- that must be surfaced, not fail silently the way an
        # ordinary incomplete-but-valid response would.
        warnings.warn(
            "Claude augmentation response was truncated at the max_tokens "
            "limit -- person/company name recall may be incomplete for this "
            "chunk of the document.",
            RuntimeWarning,
            stacklevel=2,
        )

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
