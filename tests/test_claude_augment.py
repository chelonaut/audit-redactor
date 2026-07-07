import pytest

from audit_redactor.detectors.base import EntityType, Span
from audit_redactor.detectors.claude_augment import (
    claude_api_key_available,
    run_claude_augmentation,
)


class _FakeToolUseBlock:
    type = "tool_use"

    def __init__(self, input_: dict) -> None:
        self.input = input_


class _FakeResponse:
    def __init__(self, content: list) -> None:
        self.content = content


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


def _tool_response(spans: list[dict]) -> _FakeResponse:
    return _FakeResponse([_FakeToolUseBlock({"spans": spans})])


@pytest.fixture(autouse=True)
def _no_env_key(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


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
