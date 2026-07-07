"""HTML handler (PLAN.md 2.7, build phase 6).

Redacts the HTML source before any rendering happens: strips `<script>`
tags, HTML comments, `data-*` attributes, and `<meta>` tags outright
(PLAN.md 2.7 step 1 -- these can carry hidden PII or tracking IDs invisible
in the rendered page), then walks every remaining text node -- including
`<title>`, which Chrome uses as the rendered PDF's metadata title -- through
the same detector set every other format uses. Only the already-redacted
HTML is ever handed to Playwright for rendering (appliers/html_render.py);
the original, unredacted markup never reaches the browser engine.

`href`/`src` attribute *values* are a separate leak vector from visible text
and get their own check (`_strip_sensitive_uri_attrs`): verified empirically
that Chromium's PDF export preserves an anchor's `href` as a real, clickable
PDF link annotation carrying the full un-redacted URL, regardless of what
the anchor's visible text says -- the same class of leak already fixed for
the native PDF handler's link annotations (see pdf_handler.py's
`_strip_sensitive_links`), just reachable from a different source format.

The redacted HTML is then handed to `appliers/html_render.py`'s shared
render-and-finish pipeline (also used by the Markdown handler), which
renders via Playwright, strips PDF metadata, and runs the post-render
verification pass.
"""

from __future__ import annotations

from pathlib import Path

from bs4 import BeautifulSoup, Comment

from audit_redactor.appliers.html_render import render_and_finish_pdf
from audit_redactor.appliers.output_guard import ensure_output_does_not_exist
from audit_redactor.appliers.text import redact_text
from audit_redactor.detectors import KnownIdentityDetector, detect_text, detect_text_with_claude, find_identity_usernames
from audit_redactor.detectors.base import EntityType, Span
from audit_redactor.pipeline import register

# CSS/JS aren't prose text -- redacting inside them risks corrupting syntax
# for no benefit (there's no sensitive-data-in-source-code target in scope).
_SKIP_TEXT_PARENTS = {"script", "style"}

# Attributes that can carry a full URL invisibly (no accompanying visible
# text a normal detection pass would ever see) -- `href` on `<a>`/`<link>`,
# `src` on `<img>`/`<iframe>`/etc. (`<script>` is already decomposed above).
_URI_ATTRS = ("href", "src")


def _text_nodes(soup: BeautifulSoup) -> list:
    return [
        node
        for node in soup.find_all(string=True)
        if not (node.parent and node.parent.name in _SKIP_TEXT_PARENTS)
    ]


def _uri_attr_values(soup: BeautifulSoup) -> list[str]:
    return [
        tag.attrs[attr]
        for tag in soup.find_all(True)
        for attr in _URI_ATTRS
        if isinstance(tag.attrs.get(attr), str)
    ]


def _strip_sensitive_uri_attrs(soup: BeautifulSoup, identity_detector: KnownIdentityDetector) -> list[Span]:
    """Remove any `href`/`src` value that leaks sensitive data, mirroring
    `pdf_handler._strip_sensitive_links`'s reasoning exactly: these
    attributes are a separate leak vector from visible text, there's no
    sensible way to redact *part* of a URL without breaking it, and a span
    of type URL alone doesn't count (every URL is trivially a URL) -- what
    matters is any *other* entity type found embedded within it.

    Local-only detection (`detect_text`, not `detect_text_with_claude`)
    deliberately, same rationale as the PDF equivalent: URIs are short,
    isolated strings, not document prose.

    Returns the leak spans found (not applied to any text -- the attribute
    is dropped outright) purely so the caller can fold them into the
    post-render verification pass's span list too.
    """
    leak_spans: list[Span] = []
    for tag in soup.find_all(True):
        for attr in _URI_ATTRS:
            value = tag.attrs.get(attr)
            if not isinstance(value, str):
                continue
            spans = detect_text(value, identity_detector=identity_detector)
            attr_leaks = [span for span in spans if span.entity_type != EntityType.URL]
            if attr_leaks:
                leak_spans.extend(attr_leaks)
                del tag.attrs[attr]
    return leak_spans


def redact_html_source(html: str, offline: bool = True) -> tuple[str, list[Span]]:
    """Redact an HTML document's source, returning the redacted markup and
    every span found (for the post-render verification pass).

    `offline` defaults to `True` so callers that don't care about Claude
    augmentation (unit tests) get local-only detection with no risk of an
    unexpected network call.
    """
    soup = BeautifulSoup(html, "html.parser")

    for tag in soup.find_all("script"):
        tag.decompose()
    for tag in soup.find_all("meta"):
        tag.decompose()
    for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
        comment.extract()
    for tag in soup.find_all(True):
        for attr in list(tag.attrs):
            if attr.startswith("data-"):
                del tag.attrs[attr]

    # Discovery pass: a username can be revealed by a link's *target* with
    # no accompanying visible text at all (an avatar `<img>`, a "View on
    # GitHub" link whose text says nothing), or conversely show up as a bare
    # word with no link at all -- so both text nodes and href/src values feed
    # one identity-username set before either is redacted for real.
    text_nodes = _text_nodes(soup)
    identity_detector = KnownIdentityDetector(
        find_identity_usernames([str(n) for n in text_nodes] + _uri_attr_values(soup))
    )

    all_spans: list[Span] = []
    for node in text_nodes:
        text = str(node)
        spans = detect_text_with_claude(text, offline, identity_detector=identity_detector)
        if spans:
            all_spans.extend(spans)
            node.replace_with(redact_text(text, spans))

    all_spans.extend(_strip_sensitive_uri_attrs(soup, identity_detector))

    return str(soup), all_spans


@register(".html", ".htm")
def redact_html(input_path: Path, output_path: Path, offline: bool) -> Path:
    pdf_output_path = output_path.with_suffix(".pdf")
    ensure_output_does_not_exist(pdf_output_path)

    html = input_path.read_text(encoding="utf-8")
    redacted_html, spans = redact_html_source(html, offline)

    render_and_finish_pdf(redacted_html, spans, pdf_output_path)
    return pdf_output_path
