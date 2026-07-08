import warnings

import anthropic
import pytest

from audit_redactor.detectors.base import EntityType, Span
from audit_redactor.detectors.claude_augment import (
    MAX_RETRIES,
    circuit_breaker_is_open,
    claude_api_key_available,
    get_usage_totals,
    reset_circuit_breaker,
    reset_usage_totals,
    run_claude_augmentation,
)
from audit_redactor.detectors.platform_identity import KnownIdentityDetector
from audit_redactor.detectors.text import detect_text


class _FakeToolUseBlock:
    type = "tool_use"

    def __init__(self, input_: dict) -> None:
        self.input = input_


class _FakeUsage:
    def __init__(self, input_tokens: int = 100, output_tokens: int = 20) -> None:
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


class _FakeResponse:
    def __init__(self, content: list, stop_reason: str = "tool_use", usage: _FakeUsage | None = None) -> None:
        self.content = content
        self.stop_reason = stop_reason
        self.usage = usage or _FakeUsage()


class _FakeMessages:
    def __init__(self, response: _FakeResponse, exc: Exception | None = None) -> None:
        self._response = response
        self._exc = exc
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self._exc is not None:
            raise self._exc
        return self._response


class _FakeClient:
    def __init__(self, response: _FakeResponse, exc: Exception | None = None) -> None:
        self.messages = _FakeMessages(response, exc)


class _FlakyMessages:
    """Raises `exc` for the first `fail_count` calls, then returns `response`
    (or keeps raising forever if `fail_count` is never exhausted within the
    number of calls actually made -- used to simulate a permanently broken
    API for circuit-breaker tests).
    """

    def __init__(self, exc: Exception, fail_count: int, response: "_FakeResponse") -> None:
        self._exc = exc
        self._fail_count = fail_count
        self._response = response
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if len(self.calls) <= self._fail_count:
            raise self._exc
        return self._response


class _FlakyClient:
    def __init__(self, exc: Exception, fail_count: int, response: "_FakeResponse") -> None:
        self.messages = _FlakyMessages(exc, fail_count, response)


def _tool_response(spans: list[dict]) -> _FakeResponse:
    return _FakeResponse([_FakeToolUseBlock({"spans": spans})])


@pytest.fixture(autouse=True)
def _no_env_key(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


@pytest.fixture(autouse=True)
def _reset_usage_totals() -> None:
    reset_usage_totals()


@pytest.fixture(autouse=True)
def _reset_breaker_and_skip_sleep(monkeypatch) -> None:
    reset_circuit_breaker()
    # Retry tests would otherwise really wait (worst case ~5 minutes for a
    # full exhaustion with the 60s backoff cap) -- the retry *logic* is what's
    # under test, not real wall-clock delay.
    monkeypatch.setattr("audit_redactor.detectors.claude_augment.time.sleep", lambda _seconds: None)


class TestClaudeApiKeyAvailable:
    def test_false_when_no_key_anywhere(self) -> None:
        assert claude_api_key_available() is False

    def test_true_when_explicit_key_passed(self) -> None:
        assert claude_api_key_available("sk-ant-test") is True

    def test_true_when_env_var_set(self, monkeypatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        assert claude_api_key_available() is True


class TestRunClaudeAugmentation:
    def test_offline_skips_call_entirely(self) -> None:
        client = _FakeClient(_tool_response([]))
        spans = run_claude_augmentation("Jane Doe works here.", [], offline=True, client=client)
        assert spans == []
        assert client.messages.calls == []

    def test_no_api_key_skips_call_entirely(self) -> None:
        client = _FakeClient(_tool_response([]))
        spans = run_claude_augmentation("Jane Doe works here.", [], offline=False, client=client)
        assert spans == []
        assert client.messages.calls == []

    def test_grounded_span_is_returned(self) -> None:
        text = "Contact Jane Doe for details."
        client = _FakeClient(_tool_response([{"text": "Jane Doe", "entity_type": "PERSON_NAME"}]))
        spans = run_claude_augmentation(text, [], offline=False, api_key="sk-ant-test", client=client)
        assert len(spans) == 1
        assert spans[0].text == "Jane Doe"
        assert spans[0].entity_type == EntityType.PERSON_NAME
        assert spans[0].source == "claude"
        assert text[spans[0].start : spans[0].end] == "Jane Doe"

    def test_hallucinated_span_not_in_source_is_rejected(self) -> None:
        text = "Contact Jane Doe for details."
        client = _FakeClient(_tool_response([{"text": "John Smith", "entity_type": "PERSON_NAME"}]))
        spans = run_claude_augmentation(text, [], offline=False, api_key="sk-ant-test", client=client)
        assert spans == []

    def test_span_overlapping_existing_span_is_dropped(self) -> None:
        text = "Contact Jane Doe for details."
        existing = Span(
            text="Jane Doe",
            entity_type=EntityType.PERSON_NAME,
            confidence=1.0,
            source="regex",
            start=text.index("Jane Doe"),
            end=text.index("Jane Doe") + len("Jane Doe"),
        )
        client = _FakeClient(_tool_response([{"text": "Jane Doe", "entity_type": "PERSON_NAME"}]))
        spans = run_claude_augmentation(text, [existing], offline=False, api_key="sk-ant-test", client=client)
        assert spans == []

    def test_invalid_entity_type_is_rejected(self) -> None:
        text = "Contact Jane Doe for details."
        client = _FakeClient(_tool_response([{"text": "Jane Doe", "entity_type": "EMAIL"}]))
        spans = run_claude_augmentation(text, [], offline=False, api_key="sk-ant-test", client=client)
        assert spans == []

    def test_substring_match_requires_word_boundary(self) -> None:
        text = "Alphacorp is not the same as Alpha."
        client = _FakeClient(_tool_response([{"text": "Alpha", "entity_type": "COMPANY_NAME"}]))
        spans = run_claude_augmentation(text, [], offline=False, api_key="sk-ant-test", client=client)
        assert len(spans) == 1
        assert spans[0].start == text.index(" Alpha.") + 1

    def test_repeated_name_returns_every_occurrence(self) -> None:
        text = "Jane Doe called. Later, Jane Doe called again."
        client = _FakeClient(_tool_response([{"text": "Jane Doe", "entity_type": "PERSON_NAME"}]))
        spans = run_claude_augmentation(text, [], offline=False, api_key="sk-ant-test", client=client)
        assert len(spans) == 2

    def test_api_error_degrades_to_empty_list(self) -> None:
        import anthropic

        class _FakeAPIError(anthropic.APIError):
            # Avoid anthropic.APIError.__init__'s real signature (which
            # expects an httpx.Request) -- this only needs to be a real
            # APIError subclass so the except clause under test is exercised.
            def __init__(self, message: str) -> None:
                self._message = message

            def __str__(self) -> str:
                return self._message

        exc = _FakeAPIError("connection reset")
        client = _FakeClient(_tool_response([]), exc=exc)
        with pytest.warns(RuntimeWarning):
            spans = run_claude_augmentation(
                "Jane Doe works here.", [], offline=False, api_key="sk-ant-test", client=client
            )
        assert spans == []

    def test_partially_redacted_text_sent_not_raw_text(self) -> None:
        text = "Contact Jane Doe or jane@example.com for details."
        from audit_redactor.detectors.regex_detectors import run_regex_core

        existing = run_regex_core(text)
        client = _FakeClient(_tool_response([]))
        run_claude_augmentation(text, existing, offline=False, api_key="sk-ant-test", client=client)
        sent_text = client.messages.calls[0]["messages"][0]["content"]
        assert "jane@example.com" not in sent_text
        assert "Jane Doe" in sent_text


class TestIdentityDetectorClaudeOrdering:
    """Regression coverage for a real bug caught before it shipped: merging
    `KnownIdentityDetector` spans in *after* `detect_text_with_claude`
    returns (rather than threading them through `detect_text` as
    `detect_text_with_claude` does) would let Claude see an identified
    username in plaintext and independently report it too -- e.g. as
    PERSON_NAME, whose masking rule keeps the first 4 characters, unlike
    USERNAME_MENTION's full redaction. Whichever span won the resulting
    overlap in `merge_spans` could then leave part of the username visible.
    These tests exercise the fix at the level `detect_text_with_claude`
    itself can't be unit-tested at (it takes no injectable `client`): compose
    spans the same way it does, then verify Claude never even sees the
    identified username, and that a same-text competing report from Claude
    would be rejected as already covered even if it somehow occurred.
    """

    def test_identified_username_is_masked_before_claude_sees_the_text(self) -> None:
        text = "Contact chelonaut for details."
        identity_detector = KnownIdentityDetector({"chelonaut"})
        existing = detect_text(text, identity_detector=identity_detector)

        client = _FakeClient(_tool_response([]))
        run_claude_augmentation(text, existing, offline=False, api_key="sk-ant-test", client=client)

        sent_text = client.messages.calls[0]["messages"][0]["content"]
        assert "chelonaut" not in sent_text
        assert "(REDACTED)" in sent_text

    def test_claude_reporting_the_same_span_is_rejected_as_already_covered(self) -> None:
        # Even if Claude ignored the masked placeholder and still reported
        # the name (e.g. by copying it from elsewhere in its own reasoning),
        # the grounding/exclude check must drop it -- proving no duplicate,
        # differently-typed span for the same text can ever reach
        # merge_spans.
        text = "Contact chelonaut for details."
        identity_detector = KnownIdentityDetector({"chelonaut"})
        existing = detect_text(text, identity_detector=identity_detector)

        client = _FakeClient(_tool_response([{"text": "chelonaut", "entity_type": "PERSON_NAME"}]))
        claude_spans = run_claude_augmentation(
            text, existing, offline=False, api_key="sk-ant-test", client=client
        )

        assert claude_spans == []
        entity_types = {span.entity_type for span in existing}
        assert entity_types == {EntityType.USERNAME_MENTION}

    def test_truncated_response_warns_but_still_returns_partial_spans(self) -> None:
        # A response cut off at max_tokens mid-generation must not fail
        # silently -- the caller needs to know recall may be incomplete for
        # this chunk, even though whatever was reported before the cutoff is
        # still used.
        text = "Contact Jane Doe for details."
        client = _FakeClient(
            _FakeResponse(
                [_FakeToolUseBlock({"spans": [{"text": "Jane Doe", "entity_type": "PERSON_NAME"}]})],
                stop_reason="max_tokens",
            )
        )
        with pytest.warns(RuntimeWarning, match="truncated"):
            spans = run_claude_augmentation(text, [], offline=False, api_key="sk-ant-test", client=client)
        assert len(spans) == 1
        assert spans[0].text == "Jane Doe"

    def test_non_truncated_response_does_not_warn(self) -> None:
        text = "Contact Jane Doe for details."
        client = _FakeClient(_tool_response([{"text": "Jane Doe", "entity_type": "PERSON_NAME"}]))
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            spans = run_claude_augmentation(text, [], offline=False, api_key="sk-ant-test", client=client)
        assert len(spans) == 1


class TestUsageTotals:
    def test_successful_call_accumulates_tokens(self) -> None:
        text = "Contact Jane Doe for details."
        client = _FakeClient(
            _FakeResponse(
                [_FakeToolUseBlock({"spans": []})],
                usage=_FakeUsage(input_tokens=150, output_tokens=40),
            )
        )
        run_claude_augmentation(text, [], offline=False, api_key="sk-ant-test", client=client)

        totals = get_usage_totals()
        assert totals.api_calls == 1
        assert totals.input_tokens == 150
        assert totals.output_tokens == 40

    def test_multiple_calls_accumulate_across_calls(self) -> None:
        text = "Contact Jane Doe for details."
        client = _FakeClient(
            _FakeResponse([_FakeToolUseBlock({"spans": []})], usage=_FakeUsage(100, 20))
        )
        run_claude_augmentation(text, [], offline=False, api_key="sk-ant-test", client=client)
        run_claude_augmentation(text, [], offline=False, api_key="sk-ant-test", client=client)

        totals = get_usage_totals()
        assert totals.api_calls == 2
        assert totals.input_tokens == 200
        assert totals.output_tokens == 40

    def test_offline_call_does_not_accumulate(self) -> None:
        text = "Contact Jane Doe for details."
        client = _FakeClient(_tool_response([]))
        run_claude_augmentation(text, [], offline=True, client=client)

        assert get_usage_totals().api_calls == 0

    def test_api_error_does_not_accumulate(self) -> None:
        import anthropic

        class _FakeAPIError(anthropic.APIError):
            def __init__(self, message: str) -> None:
                self._message = message

            def __str__(self) -> str:
                return self._message

        client = _FakeClient(_tool_response([]), exc=_FakeAPIError("boom"))
        with pytest.warns(RuntimeWarning):
            run_claude_augmentation(
                "Contact Jane Doe.", [], offline=False, api_key="sk-ant-test", client=client
            )

        assert get_usage_totals().api_calls == 0

    def test_reset_zeroes_totals(self) -> None:
        text = "Contact Jane Doe for details."
        client = _FakeClient(_tool_response([]))
        run_claude_augmentation(text, [], offline=False, api_key="sk-ant-test", client=client)
        assert get_usage_totals().api_calls == 1

        reset_usage_totals()

        totals = get_usage_totals()
        assert totals.api_calls == 0
        assert totals.input_tokens == 0
        assert totals.output_tokens == 0


class _FakeRateLimitError(anthropic.RateLimitError):
    def __init__(self, message: str) -> None:
        self._message = message

    def __str__(self) -> str:
        return self._message


class TestRetryAndCircuitBreaker:
    def test_retries_transient_error_then_succeeds(self) -> None:
        text = "Contact Jane Doe for details."
        exc = _FakeRateLimitError("rate limited")
        client = _FlakyClient(exc, fail_count=3, response=_tool_response([{"text": "Jane Doe", "entity_type": "PERSON_NAME"}]))

        spans = run_claude_augmentation(text, [], offline=False, api_key="sk-ant-test", client=client)

        assert len(spans) == 1
        assert spans[0].text == "Jane Doe"
        assert len(client.messages.calls) == 4  # 3 failures + 1 success
        assert circuit_breaker_is_open() is False
        assert get_usage_totals().api_calls == 1  # only the successful call counts

    def test_exhausts_retries_and_trips_circuit_breaker(self) -> None:
        text = "Contact Jane Doe for details."
        exc = _FakeRateLimitError("still rate limited")
        client = _FlakyClient(exc, fail_count=MAX_RETRIES, response=_tool_response([]))

        with pytest.warns(RuntimeWarning, match="disabling the Claude augmentation pass"):
            spans = run_claude_augmentation(text, [], offline=False, api_key="sk-ant-test", client=client)

        assert spans == []
        assert len(client.messages.calls) == MAX_RETRIES
        assert circuit_breaker_is_open() is True
        assert get_usage_totals().api_calls == 0

    def test_open_circuit_breaker_skips_call_entirely(self) -> None:
        text = "Contact Jane Doe for details."
        exc = _FakeRateLimitError("still rate limited")
        first_client = _FlakyClient(exc, fail_count=MAX_RETRIES, response=_tool_response([]))
        with pytest.warns(RuntimeWarning):
            run_claude_augmentation(text, [], offline=False, api_key="sk-ant-test", client=first_client)
        assert circuit_breaker_is_open() is True

        second_client = _FakeClient(_tool_response([{"text": "Jane Doe", "entity_type": "PERSON_NAME"}]))
        spans = run_claude_augmentation(text, [], offline=False, api_key="sk-ant-test", client=second_client)

        assert spans == []
        assert second_client.messages.calls == []  # never even attempted

    def test_non_retryable_error_fails_immediately_without_retry(self) -> None:
        class _FakeBadRequestError(anthropic.APIError):
            def __init__(self, message: str) -> None:
                self._message = message

            def __str__(self) -> str:
                return self._message

        text = "Contact Jane Doe for details."
        client = _FakeClient(_tool_response([]), exc=_FakeBadRequestError("bad request"))

        with pytest.warns(RuntimeWarning, match="Claude augmentation pass skipped"):
            spans = run_claude_augmentation(text, [], offline=False, api_key="sk-ant-test", client=client)

        assert spans == []
        assert len(client.messages.calls) == 1  # no retries for a non-transient error
        assert circuit_breaker_is_open() is False
