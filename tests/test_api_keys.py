from audit_redactor.detectors.api_keys import (
    AnthropicApiKeyDetector,
    AtlassianApiTokenDetector,
    GitHubTokenDetector,
    JwtDetector,
    NotionTokenDetector,
    OpenAiApiKeyDetector,
    SlackTokenDetector,
    SlackWebhookDetector,
)
from audit_redactor.detectors.base import EntityType


def _texts(spans) -> set[str]:
    return {s.text for s in spans}


class TestSlackTokenDetector:
    def setup_method(self) -> None:
        self.detector = SlackTokenDetector()

    def test_bot_token(self) -> None:
        # Deliberately not shaped like a real token (no digit-run segments
        # mimicking Slack's actual team-ID/bot-ID convention) -- a
        # realistic-looking placeholder tripped GitHub's own secret-scanning
        # push protection, which is a good sign the regex is on target, but
        # the fixture only needs to satisfy *this* detector's shape.
        text = "Token: xoxb-NOTAREALSLACKTOKENVALUEPLACEHOLDER here."
        spans = self.detector.detect(text)
        assert _texts(spans) == {"xoxb-NOTAREALSLACKTOKENVALUEPLACEHOLDER"}
        assert spans[0].entity_type == EntityType.SLACK_TOKEN

    def test_app_level_token(self) -> None:
        text = "App token xapp-NOTAREALSLACKTOKENVALUEPLACEHOLDER used."
        spans = self.detector.detect(text)
        assert len(spans) == 1
        assert spans[0].text.startswith("xapp-")

    def test_no_false_positive_on_unrelated_text(self) -> None:
        assert self.detector.detect("xox marks the spot") == []


class TestSlackWebhookDetector:
    def setup_method(self) -> None:
        self.detector = SlackWebhookDetector()

    def test_webhook_with_scheme(self) -> None:
        # Deliberately not using Slack's real T.../B... team-ID/bot-ID path
        # convention -- this detector's regex doesn't require it, and a more
        # realistic-looking placeholder tripped GitHub's secret-scanning
        # push protection.
        text = "https://hooks.slack.com/services/NOTAREALID/NOTAREALID/NOTAREALTOKENVALUE"
        spans = self.detector.detect(text)
        assert _texts(spans) == {text}
        assert spans[0].entity_type == EntityType.SLACK_WEBHOOK

    def test_webhook_without_scheme(self) -> None:
        # The generic URL detector requires a scheme or "www." -- a bare
        # "hooks.slack.com/..." would otherwise slip through entirely.
        text = "hooks.slack.com/services/NOTAREALID/NOTAREALID/NOTAREALTOKENVALUE"
        spans = self.detector.detect(text)
        assert _texts(spans) == {text}


class TestAtlassianApiTokenDetector:
    def setup_method(self) -> None:
        self.detector = AtlassianApiTokenDetector()

    def test_atatt3_token(self) -> None:
        token = "ATATT3x" + "A" * 150
        spans = self.detector.detect(f"Token: {token} end.")
        assert _texts(spans) == {token}
        assert spans[0].entity_type == EntityType.ATLASSIAN_API_TOKEN

    def test_too_short_not_matched(self) -> None:
        assert self.detector.detect("ATATT3xshort") == []


class TestGitHubTokenDetector:
    def setup_method(self) -> None:
        self.detector = GitHubTokenDetector()

    def test_classic_personal_access_token(self) -> None:
        token = "ghp_" + "1" * 40
        spans = self.detector.detect(f"Token {token} here.")
        assert _texts(spans) == {token}
        assert spans[0].entity_type == EntityType.GITHUB_TOKEN

    def test_oauth_token(self) -> None:
        token = "gho_" + "a" * 40
        assert _texts(self.detector.detect(token)) == {token}

    def test_app_server_to_server_token(self) -> None:
        token = "ghs_" + "b" * 40
        assert _texts(self.detector.detect(token)) == {token}

    def test_fine_grained_token(self) -> None:
        token = "github_pat_" + "A" * 90
        spans = self.detector.detect(f"Fine-grained: {token} end.")
        assert _texts(spans) == {token}

    def test_no_false_positive_on_short_gh_prefix(self) -> None:
        assert self.detector.detect("ghost_writer wrote gh_notes.txt") == []


class TestAnthropicApiKeyDetector:
    def setup_method(self) -> None:
        self.detector = AnthropicApiKeyDetector()

    def test_standard_key(self) -> None:
        token = "sk-ant-api03-" + "B" * 90
        spans = self.detector.detect(f"Key: {token} end.")
        assert _texts(spans) == {token}
        assert spans[0].entity_type == EntityType.ANTHROPIC_API_KEY

    def test_admin_key_variant(self) -> None:
        token = "sk-ant-admin01-" + "C" * 90
        assert _texts(self.detector.detect(token)) == {token}


class TestOpenAiApiKeyDetector:
    def setup_method(self) -> None:
        self.detector = OpenAiApiKeyDetector()

    def test_legacy_secret_key(self) -> None:
        token = "sk-" + "C" * 40
        spans = self.detector.detect(f"Key: {token} end.")
        assert _texts(spans) == {token}
        assert spans[0].entity_type == EntityType.OPENAI_API_KEY

    def test_project_scoped_key(self) -> None:
        token = "sk-proj-" + "D" * 40
        assert _texts(self.detector.detect(token)) == {token}

    def test_service_account_key(self) -> None:
        token = "sk-svcacct-" + "E" * 40
        assert _texts(self.detector.detect(token)) == {token}

    def test_does_not_match_anthropic_key(self) -> None:
        # Regression guard: "sk-" and "sk-ant-" share a prefix -- this must
        # never fire on a real Anthropic key.
        anthropic_key = "sk-ant-api03-" + "B" * 90
        assert self.detector.detect(anthropic_key) == []

    def test_no_false_positive_on_short_sk_prefix(self) -> None:
        assert self.detector.detect("sk-8 is not a real key, just a label") == []


class TestNotionTokenDetector:
    def setup_method(self) -> None:
        self.detector = NotionTokenDetector()

    def test_legacy_secret_format(self) -> None:
        token = "secret_" + "E" * 43
        spans = self.detector.detect(f"Integration token {token} end.")
        assert _texts(spans) == {token}
        assert spans[0].entity_type == EntityType.NOTION_TOKEN

    def test_current_ntn_format(self) -> None:
        token = "ntn_" + "F" * 40
        assert _texts(self.detector.detect(token)) == {token}

    def test_no_false_positive_on_generic_secret_variable_name(self) -> None:
        # "secret_" alone is a common code/config identifier -- only the
        # full documented length should match.
        assert self.detector.detect("const secret_key = getSecret();") == []
        assert self.detector.detect("my_secret_value = 42") == []


class TestJwtDetector:
    def setup_method(self) -> None:
        self.detector = JwtDetector()

    def test_real_shaped_jwt(self) -> None:
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
            ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        spans = self.detector.detect(f"Authorization: Bearer {token}")
        assert _texts(spans) == {token}
        assert spans[0].entity_type == EntityType.JWT

    def test_two_segments_not_matched(self) -> None:
        assert self.detector.detect("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0") == []

    def test_non_json_looking_segments_not_matched(self) -> None:
        assert self.detector.detect("abc.def.ghi") == []
