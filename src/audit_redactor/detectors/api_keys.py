"""Third-party API key / token detectors (PLAN.md 2.3), kept separate from
regex_detectors.py's original core set since there are several of these and
they share nothing structurally with AWS/phone/email/URL detection beyond
"a distinctive fixed prefix, followed by a long random-looking suffix."

Each of these products documents its own token format publicly (so leaked
tokens found by scanners like this one can be identified and revoked), so
the prefixes below are sourced from that public documentation, not
reverse-engineered. Two services the caller asked about are deliberately
NOT included, each with a stated reason:

- **Atlassian Statuspage API keys** have no identifiable prefix -- they are
  (and always have been) plain random alphanumeric strings indistinguishable
  from any other opaque secret, so there is no regex-findable shape to key
  off of. (Jira and Confluence tokens *are* covered below -- both sit behind
  Atlassian's shared account/identity system, so one token format covers
  both products.)
- **Microsoft Copilot** has no distinct "Copilot API key" of its own to
  find: it authenticates via Microsoft Entra ID (Azure AD), whose access
  tokens are JWTs -- already covered by `JwtDetector` below -- and Azure's
  own opaque API keys (e.g. Cognitive Services) have no fixed prefix either.

Every entity type here is registered as full redaction in
`appliers/text.py` -- unlike an AWS account/access key ID, none of these
need a "show the last 4 characters so two keys can be told apart"
allowance, so the safer default (hide the whole thing) applies.

Overlap with other detectors is deliberately guarded against, not just
assumed away:
- OpenAI's "sk-" prefix and Anthropic's "sk-ant-" prefix share their first
  three characters -- `_OPENAI_TOKEN_RE` uses a negative lookahead so it
  never also matches (a prefix of) an Anthropic key.
- A Slack webhook or any of these tokens embedded inside a URL (e.g. a
  query-string parameter) will also be caught whole by the generic URL
  detector; `merge_spans` (appliers/text.py) resolves the resulting
  same-range overlap by keeping whichever detector ran first, and since
  both are full-redaction types the visible output is identical either way
  -- only the recorded entity_type label for that one span could differ.
- None of the fixed prefixes below collide with the AWS account ID / access
  key ID prefixes, the mention ("@") pattern, or each other.
"""

from __future__ import annotations

import re

from audit_redactor.detectors.base import EntityType, Span

# Slack tokens: xoxb- (bot), xoxp- (user), xapp- (app-level), plus the
# legacy xoxa-/xoxr-/xoxs- workspace/refresh token prefixes -- all share the
# same "xox<letter>-" (or "xapp-") shape followed by a long alphanumeric/
# hyphenated run.
_SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b|\bxapp-[A-Za-z0-9-]{10,72}\b")

# Slack incoming webhook URLs. Scheme is optional -- the generic URL
# detector only fires on a recognized scheme or a "www." prefix, so a bare
# "hooks.slack.com/services/..." (no "https://") would otherwise slip
# through entirely.
_SLACK_WEBHOOK_RE = re.compile(
    r"(?:https?://)?hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+"
)

# Atlassian Cloud API tokens (covers Jira and Confluence -- see module
# docstring). Current tokens use the "ATATT3" prefix; the length below is
# generous rather than exact since Atlassian doesn't publicly commit to one.
_ATLASSIAN_TOKEN_RE = re.compile(r"\bATATT3[A-Za-z0-9_=-]{100,}\b")

# GitHub tokens: the short-prefix family (ghp_ personal access token, gho_
# OAuth, ghu_/ghs_ GitHub App user-to-server/server-to-server, ghr_ App
# refresh token) are all "gh<letter>_" + a long alphanumeric run; the newer
# fine-grained personal access tokens use a longer "github_pat_" prefix.
_GITHUB_TOKEN_RE = re.compile(r"\bgh[oprsu]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{80,}\b")

# Anthropic API keys: "sk-ant-", including the "sk-ant-admin-..." admin-key
# variant ("admin" just becomes part of the matched suffix).
_ANTHROPIC_TOKEN_RE = re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")

# OpenAI API keys: legacy "sk-" secret keys, "sk-proj-" project-scoped keys,
# and "sk-svcacct-" service-account keys. The negative lookahead is the
# overlap guard against Anthropic's "sk-ant-" above -- see module docstring.
_OPENAI_TOKEN_RE = re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b")

# Notion tokens: "secret_" (original internal-integration-token format) and
# "ntn_" (current format). "secret_" alone would be a dangerously generic
# word to key off of (common as a code/config variable name) -- requiring
# the full documented 43-character suffix is what makes it safe to match
# without flooding on unrelated "secret_..." identifiers in prose or code.
_NOTION_TOKEN_RE = re.compile(r"\bsecret_[A-Za-z0-9]{43}\b|\bntn_[A-Za-z0-9]{35,}\b")

# JWTs: three dot-separated base64url segments. A JWT header and payload are
# both JSON objects (`{"alg":...}`, `{"sub":...}`), and `{"` is virtually
# always how each begins -- which base64url-encodes to the distinctive
# "eyJ" seen at the start of essentially every real-world JWT. Requiring
# *both* the header and payload segments (not just the header) to start
# with "eyJ" makes this precise enough to use without a checksum or a real
# structural JSON-decode step.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")


class SlackTokenDetector:
    def detect(self, text: str) -> list[Span]:
        return [
            Span(
                text=m.group(),
                entity_type=EntityType.SLACK_TOKEN,
                confidence=1.0,
                source="regex",
                start=m.start(),
                end=m.end(),
            )
            for m in _SLACK_TOKEN_RE.finditer(text)
        ]


class SlackWebhookDetector:
    def detect(self, text: str) -> list[Span]:
        return [
            Span(
                text=m.group(),
                entity_type=EntityType.SLACK_WEBHOOK,
                confidence=1.0,
                source="regex",
                start=m.start(),
                end=m.end(),
            )
            for m in _SLACK_WEBHOOK_RE.finditer(text)
        ]


class AtlassianApiTokenDetector:
    def detect(self, text: str) -> list[Span]:
        return [
            Span(
                text=m.group(),
                entity_type=EntityType.ATLASSIAN_API_TOKEN,
                confidence=1.0,
                source="regex",
                start=m.start(),
                end=m.end(),
            )
            for m in _ATLASSIAN_TOKEN_RE.finditer(text)
        ]


class GitHubTokenDetector:
    def detect(self, text: str) -> list[Span]:
        return [
            Span(
                text=m.group(),
                entity_type=EntityType.GITHUB_TOKEN,
                confidence=1.0,
                source="regex",
                start=m.start(),
                end=m.end(),
            )
            for m in _GITHUB_TOKEN_RE.finditer(text)
        ]


class AnthropicApiKeyDetector:
    def detect(self, text: str) -> list[Span]:
        return [
            Span(
                text=m.group(),
                entity_type=EntityType.ANTHROPIC_API_KEY,
                confidence=1.0,
                source="regex",
                start=m.start(),
                end=m.end(),
            )
            for m in _ANTHROPIC_TOKEN_RE.finditer(text)
        ]


class OpenAiApiKeyDetector:
    def detect(self, text: str) -> list[Span]:
        return [
            Span(
                text=m.group(),
                entity_type=EntityType.OPENAI_API_KEY,
                confidence=1.0,
                source="regex",
                start=m.start(),
                end=m.end(),
            )
            for m in _OPENAI_TOKEN_RE.finditer(text)
        ]


class NotionTokenDetector:
    def detect(self, text: str) -> list[Span]:
        return [
            Span(
                text=m.group(),
                entity_type=EntityType.NOTION_TOKEN,
                confidence=1.0,
                source="regex",
                start=m.start(),
                end=m.end(),
            )
            for m in _NOTION_TOKEN_RE.finditer(text)
        ]


class JwtDetector:
    def detect(self, text: str) -> list[Span]:
        return [
            Span(
                text=m.group(),
                entity_type=EntityType.JWT,
                confidence=1.0,
                source="regex",
                start=m.start(),
                end=m.end(),
            )
            for m in _JWT_RE.finditer(text)
        ]


API_KEY_DETECTORS = [
    SlackTokenDetector(),
    SlackWebhookDetector(),
    AtlassianApiTokenDetector(),
    GitHubTokenDetector(),
    AnthropicApiKeyDetector(),
    OpenAiApiKeyDetector(),
    NotionTokenDetector(),
    JwtDetector(),
]
