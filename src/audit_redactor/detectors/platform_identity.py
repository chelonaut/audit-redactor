"""Cross-reference detector: discovers a person's platform username from a
profile/repo URL appearing anywhere in a document, then treats every bare,
literal occurrence of that username elsewhere in the *same* document as
sensitive too.

Every other detector in this project (regex core, company list, Claude)
looks at one isolated chunk of text with no memory of anything else in the
document. This one is fundamentally different: a URL like
`https://github.com/octocat/some-repo` is itself already redacted as a
plain URL span, but the bare word "octocat" showing up elsewhere with no
URL around it (a page's nav bar, an "authored by" line, a commit-author
breadcrumb) isn't caught by anything else -- it isn't an email, phone
number, AWS ID, @mention, or curated company name.

Deliberately split into two independent halves so "which URLs count as
identity evidence" can grow (more platforms, other clue types) without
touching "how do we redact a known name once we have one" at all:

  1. `find_identity_usernames()` -- extraction rules, one per platform, each
     just a (hostnames, reserved-path denylist, username shape) tuple. Only
     GitHub is registered today; GitLab/Bitbucket/etc. are a matter of
     appending another `IdentityUrlRule`, not restructuring anything.
  2. `KnownIdentityDetector` -- a fully generic literal-string detector with
     no idea where its usernames came from. Any future source of "this
     string is a personal identifier" evidence (not just a URL) can reuse it
     unchanged.

Callers own the two-phase document flow this requires: scan the *whole*
document's text and link/attribute targets to build one username set first,
then run `KnownIdentityDetector` alongside every other detector on the
second, real redaction pass over the same document. See each handler
(pdf_handler.py, html_handler.py, markdown_handler.py, json_handler.py) for
the per-format wiring.

Known limitations (not silently claimed as covered):
- Can't distinguish a personal username from an organisation name or an
  unlisted reserved keyword from the URL shape alone -- both look
  identical structurally. The reserved-segment denylist below covers
  GitHub's well-known top-level routes but isn't exhaustive, and an org
  name not on it is treated exactly like a personal username (consistent
  with this project's recall-over-precision bias elsewhere, but can
  over-redact a legitimate public reference).
- Matching is case-sensitive -- a differently-capitalised mention of the
  same username elsewhere in the document is missed.
- `_MIN_USERNAME_LENGTH` is a partial mitigation against common short
  English words colliding with a real username, not a guarantee.
- Only literal `github.com`/`www.github.com` URLs and `git@github.com:`
  SSH remotes are recognised -- no self-hosted/Enterprise Git instances.
- Discovery only looks at real text and link/attribute targets; it does not
  OCR image content, so a username visible only inside a screenshot (with
  no accompanying real link elsewhere in the document) won't be found.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlsplit

from audit_redactor.detectors.base import EntityType, Span
from audit_redactor.detectors.regex_detectors import URL_PATTERNS

# Below this, a "username" is indistinguishable from an ordinary short
# word -- a lot of common English words are three or four letters. Partial
# mitigation only, not a guarantee (see module docstring).
_MIN_USERNAME_LENGTH = 3

_GITHUB_USERNAME_RE = re.compile(r"[A-Za-z0-9](?:-?[A-Za-z0-9])*")

# GitHub's own top-level routes -- "github.com/settings" or
# "github.com/marketplace" is navigation chrome, not a person. Sourced from
# GitHub's publicly documented reserved-route list; not guaranteed
# exhaustive, and GitHub can add new top-level routes at any time.
_GITHUB_RESERVED_SEGMENTS = frozenset(
    {
        "about", "account", "admin", "announcements", "api", "apps", "blog",
        "business", "codespaces", "collections", "contact", "copilot",
        "customer-stories", "dashboard", "discussions", "education",
        "enterprise", "events", "explore", "features", "gist", "gists",
        "help", "home", "issues", "join", "login", "logout", "marketplace",
        "new", "nonprofit", "notifications", "organizations", "orgs",
        "plans", "pricing", "privacy", "pulls", "readme", "security",
        "settings", "site", "sponsors", "star", "stars", "support", "team",
        "terms", "topics", "trending", "watching", "search",
    }
)


@dataclass(frozen=True)
class IdentityUrlRule:
    """One platform's "how do I find a username in a URL" recipe."""

    hosts: frozenset[str]
    reserved_segments: frozenset[str]
    username_re: re.Pattern[str]


# Add GitLab/Bitbucket/etc. here later -- same shape, different
# hosts/reserved-segment list/username regex. Nothing else in this module
# or its callers needs to change to support another platform.
_IDENTITY_URL_RULES: tuple[IdentityUrlRule, ...] = (
    IdentityUrlRule(
        hosts=frozenset({"github.com", "www.github.com"}),
        reserved_segments=_GITHUB_RESERVED_SEGMENTS,
        username_re=_GITHUB_USERNAME_RE,
    ),
)

_SSH_GIT_RE = re.compile(r"git@([A-Za-z0-9.-]+):([A-Za-z0-9][A-Za-z0-9-]{0,38})/")


def _rule_for_host(host: str) -> IdentityUrlRule | None:
    host = host.lower()
    if host.startswith("www."):
        host = host[len("www.") :]
    for rule in _IDENTITY_URL_RULES:
        if host in rule.hosts or f"www.{host}" in rule.hosts:
            return rule
    return None


def _validate(username: str, rule: IdentityUrlRule) -> str | None:
    if len(username) < _MIN_USERNAME_LENGTH:
        return None
    if username.lower() in rule.reserved_segments:
        return None
    if not rule.username_re.fullmatch(username):
        return None
    return username


def _extract_from_url(url: str) -> str | None:
    parts = urlsplit(url)
    if not parts.netloc:
        return None
    rule = _rule_for_host(parts.netloc)
    if rule is None:
        return None
    segment = parts.path.strip("/").split("/", 1)[0]
    if not segment:
        return None
    return _validate(segment, rule)


def find_identity_usernames(texts: Iterable[str]) -> set[str]:
    """Scan `texts` for platform profile/repo URLs and SSH remotes, and
    return the set of usernames they reveal.

    Callers pass in *every* piece of text and every link/attribute target in
    the document being redacted (page text, PDF hyperlink URIs, JSON string
    leaves, HTML `href`/`src` attribute values, ...) so a username that only
    ever shows up bare -- with no accompanying link -- somewhere else in the
    same document is still caught on the second, redaction pass.
    """
    found: set[str] = set()
    for text in texts:
        for pattern in URL_PATTERNS:
            for m in pattern.finditer(text):
                url = m.group()
                if url.lower().startswith("www."):
                    url = "https://" + url
                username = _extract_from_url(url)
                if username:
                    found.add(username)
        for m in _SSH_GIT_RE.finditer(text):
            rule = _rule_for_host(m.group(1))
            if rule is None:
                continue
            username = _validate(m.group(2), rule)
            if username:
                found.add(username)
    return found


class KnownIdentityDetector:
    """Literal, word-bounded search for a fixed set of already-identified
    names.

    Has no idea where `usernames` came from -- deliberately generic, so any
    future source of "this string is a personal identifier" evidence can
    reuse it without a new detector class. Matches use a GitHub-username-
    shaped boundary (alnum/hyphen) rather than plain `\\b`, since `\\b` alone
    would misbehave around an internal hyphen in the username itself.
    """

    def __init__(self, usernames: Iterable[str]) -> None:
        self._patterns = [
            re.compile(r"(?<![A-Za-z0-9_-])" + re.escape(name) + r"(?![A-Za-z0-9_-])")
            for name in usernames
        ]

    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []
        for pattern in self._patterns:
            for m in pattern.finditer(text):
                spans.append(
                    Span(
                        text=m.group(),
                        entity_type=EntityType.USERNAME_MENTION,
                        confidence=1.0,
                        source="regex",
                        start=m.start(),
                        end=m.end(),
                    )
                )
        return spans
