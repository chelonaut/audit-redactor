"""Curated client company name matcher (PLAN.md 2.3, 2.10).

The list is maintained as a standalone data file, confirmed via web search
when adding new names, and never web-searched during redaction itself (2.10).
"""

from __future__ import annotations

import re
import unicodedata
from importlib import resources
from pathlib import Path

from audit_redactor.detectors.base import EntityType, Span

_DEFAULT_NAMES_RESOURCE = resources.files("audit_redactor").joinpath("data", "company_names.txt")

# "&"/"+"/"and" are treated as the same connector, regardless of which one a
# curated name or a document happens to use, and regardless of surrounding
# whitespace -- "Example & Co", "Example+Co", and "Example and Co" are all
# the same company. "and" requires whitespace on both sides (unlike "&"/"+",
# which tolerate none) so it only matches as its own connecting word, not as
# a substring of an unrelated word like "sand" or "Andorra".
_CONNECTOR_RE = re.compile(r"\s*&\s*|\s*\+\s*|\s+and\s+", re.IGNORECASE)
_CONNECTOR_ALTERNATION = r"(?:\s*&\s*|\s*\+\s*|\s+and\s+)"

# Straight ASCII "'" and the Unicode "smart quote" "’" are treated as the
# same character, and as optional -- a document routinely drops the
# apostrophe entirely ("Sainsburys" for a curated "Sainsbury's"), which
# otherwise can't match at all since the apostrophe is baked into the
# curated name as a literal character with nothing in the document text to
# find it against.
_APOSTROPHE_CHARS = "'’"
_APOSTROPHE_ALTERNATION = f"[{_APOSTROPHE_CHARS}]?"

# Whichever of the above a curated name contains, at whatever position(s) --
# this is what `_build_special_pattern` scans a name for to decide whether it
# needs its own regex at all.
_SPECIAL_RE = re.compile(rf"\s*&\s*|\s*\+\s*|\s+and\s+|[{_APOSTROPHE_CHARS}]", re.IGNORECASE)

# A curated name starting with "The " also matches with that prefix dropped
# ("The Example Shop" -> "Example Shop") -- the reverse needs no special
# handling: a bare curated "Example Shop" already matches inside a
# document's "The Example Shop" via the ordinary word-boundary rule, since
# "The " is just preceding context, not part of the matched text itself.
_LEADING_THE_RE = re.compile(r"^the\s+", re.IGNORECASE)


def _parse_names(raw_text: str) -> list[str]:
    names = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        names.append(line)
    return names


def _fold_diacritics(text: str) -> tuple[str, list[int]]:
    """Strip combining diacritical marks (e.g. "e" for "é") so matching
    doesn't depend on accents being typed correctly, either in the curated
    list or in the document.

    Returns the folded text plus a per-character map back to `text`'s
    original indices, so matches found in the folded text can still be
    reported at their true offsets in the original (accented) text.
    """
    folded_chars: list[str] = []
    index_map: list[int] = []
    for i, ch in enumerate(text):
        for dch in unicodedata.normalize("NFKD", ch):
            if unicodedata.combining(dch):
                continue
            folded_chars.append(dch)
            index_map.append(i)
    return "".join(folded_chars), index_map


def _is_word_char(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _build_special_pattern(folded_name: str) -> re.Pattern[str] | None:
    """If `folded_name` contains an "&"/"+"/"and" connector or an apostrophe,
    compile a regex tolerating the variations a document commonly uses in
    their place: any of the other two connector spellings (with any amount
    of surrounding whitespace), or the apostrophe being a different quote
    character or missing entirely. Returns `None` for a name with neither,
    so `CompanyListDetector.detect()`'s fast plain substring scan keeps
    handling the (large majority) common case unaffected -- this is only
    built, and only checked, for the minority of curated names that actually
    contain one.

    A single regex handles a name with more than one such spot (e.g. "A & B
    & C", or a hypothetical "O'Brien & Sons") without any combinatorial
    blow-up: each occurrence becomes one alternation/optional group spliced
    between the surrounding literal (escaped) segments, not a separate
    variant string per combination.
    """
    pieces = []
    last = 0
    has_special = False
    for m in _SPECIAL_RE.finditer(folded_name):
        has_special = True
        pieces.append(re.escape(folded_name[last : m.start()]))
        pieces.append(_APOSTROPHE_ALTERNATION if m.group() in _APOSTROPHE_CHARS else _CONNECTOR_ALTERNATION)
        last = m.end()
    if not has_special:
        return None
    pieces.append(re.escape(folded_name[last:]))
    # Trailing "s?" mirrors detect()'s plain-match plural handling: swallowed
    # into the match only when it's the word's true end (not, say, the start
    # of an unrelated longer word), via the same `(?!\w)` that would
    # otherwise immediately follow the name itself.
    return re.compile(r"(?<!\w)" + "".join(pieces) + r"s?(?!\w)", re.IGNORECASE)


class CompanyListDetector:
    """Matches a curated list of client company names, loaded from a text file.

    Scans for each name with a plain case-insensitive substring search
    (`str.find`) rather than one big `(?:name1|name2|...)` regex alternation.
    Measured directly against a several-thousand-name list: the compiled
    alternation makes the regex engine re-test every remaining alternative at
    every text position, which gets slower as the list grows; a loop of
    native `str.find` calls stayed roughly 2-3x faster at that scale and
    needs no escaping/compilation step at all. Word-boundary and diacritic
    handling are unchanged from the regex version.

    A name containing an "&"/"+"/"and" connector (e.g. "Example & Co") or an
    apostrophe (e.g. "Example's") is the one exception to the plain-scan
    path: it gets its own small compiled regex (`_build_special_pattern`) so
    a document spelling it "Example + Co"/"Example&Co"/"Example and Co", or
    dropping the apostrophe entirely ("Examples"), still matches. This only
    adds a regex per name that actually needs one, not one across the whole
    list, so it doesn't reintroduce the alternation-at-scale cost above; most
    curated names have neither and never touch this path.

    A name starting with "The " is also matched with that prefix dropped
    (`_LEADING_THE_RE`) -- e.g. a curated "The Example Shop" also matches a
    document's bare "Example Shop". The reverse direction needs no extra
    handling: a curated "Example Shop" with no "The" already matches inside
    a document's "The Example Shop" via the ordinary word-boundary rule,
    since "The " there is just preceding context, not part of the match.

    Defaults to the bundled starter list at `audit_redactor/data/company_names.txt`.
    Pass `data_path` to point at a separate, private, real curated list instead
    (see `detectors/text.py`'s `configure_default_company_list` for how the
    CLI wires `--company-list` to this without every caller needing to pass
    its own detector).
    """

    def __init__(self, data_path: Path | str | None = None) -> None:
        if data_path is not None:
            raw_text = Path(data_path).read_text(encoding="utf-8")
        else:
            raw_text = _DEFAULT_NAMES_RESOURCE.read_text(encoding="utf-8")
        self.names = _parse_names(raw_text)
        # Folded and lowercased once at load time rather than per `detect()`
        # call, since the same detector instance is reused across every page/
        # chunk of a document. A name needing a special regex (connector or
        # apostrophe) goes to `_special_patterns` instead of the plain list --
        # its compiled regex already matches the name's own exact spelling
        # too, so keeping it in both would just double-report the same span.
        self._folded_names: list[str] = []
        self._special_patterns: list[re.Pattern[str]] = []
        for original in self.names:
            for variant in self._name_variants(original):
                folded = _fold_diacritics(variant)[0]
                if not folded:
                    continue
                pattern = _build_special_pattern(folded)
                if pattern is not None:
                    self._special_patterns.append(pattern)
                else:
                    self._folded_names.append(folded.lower())

    @staticmethod
    def _name_variants(name: str) -> list[str]:
        """A curated name, plus (only for one starting with "The ") a second
        variant with that prefix dropped -- both are then independently fed
        through the same connector/apostrophe/plain classification above.
        """
        variants = [name]
        stripped = _LEADING_THE_RE.sub("", name, count=1)
        if stripped != name:
            variants.append(stripped)
        return variants

    def detect(self, text: str) -> list[Span]:
        if not self._folded_names and not self._special_patterns:
            return []
        folded_text, index_map = _fold_diacritics(text)
        lowered = folded_text.lower()
        text_len = len(folded_text)
        spans = []
        for pattern in self._special_patterns:
            for m in pattern.finditer(folded_text):
                if m.start() == m.end():
                    continue
                start = index_map[m.start()]
                stop = index_map[m.end() - 1] + 1
                spans.append(
                    Span(
                        text=text[start:stop],
                        entity_type=EntityType.COMPANY_NAME,
                        confidence=1.0,
                        source="company_list",
                        start=start,
                        end=stop,
                    )
                )
        for name in self._folded_names:
            name_len = len(name)
            search_from = 0
            while True:
                idx = lowered.find(name, search_from)
                if idx == -1:
                    break
                end = idx + name_len
                search_from = idx + 1
                before_ok = idx == 0 or not _is_word_char(folded_text[idx - 1])
                if not before_ok:
                    continue
                after_ok = end == text_len or not _is_word_char(folded_text[end])
                match_end = end
                if not after_ok and folded_text[end].lower() == "s":
                    # A bare trailing "s" -- English pluralization of a
                    # proper noun, e.g. a document referring to "Sainsburys"
                    # (plural incidents/accounts) -- is swallowed into the
                    # match and redacted along with it. Without this, the
                    # word-boundary rule above (needed so "Mode" doesn't
                    # match inside "Model") leaves the *entire* plural
                    # mention completely unredacted, silently leaking the
                    # same curated name. A possessive ("Sainsbury's") needs
                    # no special case: the apostrophe right after the name
                    # already isn't a word character, so `after_ok` is
                    # already true for it.
                    after_s_ok = end + 1 == text_len or not _is_word_char(folded_text[end + 1])
                    if after_s_ok:
                        after_ok = True
                        match_end = end + 1
                if not after_ok:
                    continue
                start = index_map[idx]
                stop = index_map[match_end - 1] + 1
                spans.append(
                    Span(
                        text=text[start:stop],
                        entity_type=EntityType.COMPANY_NAME,
                        confidence=1.0,
                        source="company_list",
                        start=start,
                        end=stop,
                    )
                )
        return spans
