"""Date/time recognition -- used only to stop another detector (currently
just the phone-number regex) from misreading a date or timestamp as
something sensitive.

Unlike every other module under detectors/, this one never produces a
`Span`: a date aids auditability (knowing *when* evidence is from) rather
than threatening privacy, so there is nothing here to redact. It exists
purely to answer "is this range a date/time?" so a detector matching on raw
digit shape can skip over it -- e.g. a filename timestamp
"2026-07-06 at 17.55.28" or an AWS CloudTrail export's "20260516T1805Z" is
unambiguously a date/time, not a phone number.

Rather than one fixed regex per format, each shape below captures its
year/month/day/hour/minute/second components as groups and validates them
with plain range checks instead of baking ranges into the regex character
classes: a year is treated as plausible from 2000 to 50 years from today, a
month is 1-12, a day is 1-31, an hour is 0-23, a minute/second is 0-59. This
both widens coverage (one pattern per separator family instead of a
fixed-format regex per exact layout) and improves precision (a random
digit run doesn't get misclassified as a date just because it superficially
matches a separator shape -- e.g. "99-99-9999" is rejected).

Deliberately not a general-purpose date parser: it only needs to decide
"protect this range from the phone detector," not identify a calendar date
correctly in every locale/ambiguous-order case. Year-last shapes
(DD-MM-YYYY vs MM-DD-YYYY) are accepted without deciding which reading is
correct -- both components just need to be individually plausible as a
day-or-month.
"""

from __future__ import annotations

import re
from datetime import date

_MIN_YEAR = 2000
_MAX_YEAR = date.today().year + 50


def _year_ok(value: str) -> bool:
    return _MIN_YEAR <= int(value) <= _MAX_YEAR


def _month_ok(value: str) -> bool:
    return 1 <= int(value) <= 12


def _day_ok(value: str) -> bool:
    return 1 <= int(value) <= 31


def _hour_ok(value: str) -> bool:
    return 0 <= int(value) <= 23


def _minute_or_second_ok(value: str) -> bool:
    return 0 <= int(value) <= 59


# Year-first, single consistent separator (hyphen, slash, or dot) between
# all three date components, optionally followed by an ISO 8601 extended
# time component: "2026-05-16", "2026/05/16", "2026-07-06T17:55:28Z".
_YMD_RE = re.compile(
    r"(?<!\d)(?P<year>\d{4})(?P<sep>[-/.])(?P<month>\d{1,2})(?P=sep)(?P<day>\d{1,2})"
    r"(?:[T ](?P<hour>\d{2}):(?P<minute>\d{2})(?::(?P<second>\d{2}))?Z?)?(?!\d)"
)

# Year-last, single consistent separator: "16-05-2026", "16/05/2026". Which
# of the first two groups is the day vs. the month is deliberately never
# decided -- see module docstring.
_DAY_MONTH_OR_MONTH_DAY_YEAR_RE = re.compile(
    r"(?<!\d)(?P<a>\d{1,2})(?P<sep>[-/.])(?P<b>\d{1,2})(?P=sep)(?P<year>\d{4})(?!\d)"
)

# ISO 8601 basic (compact, no separators) date, optionally with a compact
# time component -- the AWS CloudTrail export filename format, e.g.
# "20260516T1805Z", "20260516T180500Z", or just the bare date "20260516".
_COMPACT_ISO_RE = re.compile(
    r"(?<!\d)(?P<year>\d{4})(?P<month>\d{2})(?P<day>\d{2})"
    r"(?:T(?P<hour>\d{2})(?P<minute>\d{2})(?P<second>\d{2})?Z?)?(?!\d)"
)

# Dotted time with no date component: "17.55.28".
_TIME_DOTTED_RE = re.compile(
    r"(?<!\d)(?P<hour>\d{1,2})\.(?P<minute>\d{2})\.(?P<second>\d{2})(?!\d)"
)


def find_date_time_ranges(text: str) -> list[tuple[int, int]]:
    """Return every `(start, end)` character range in `text` that looks like
    a real date and/or time, per the plausibility checks above.
    """
    ranges: list[tuple[int, int]] = []

    for m in _YMD_RE.finditer(text):
        if not (_year_ok(m["year"]) and _month_ok(m["month"]) and _day_ok(m["day"])):
            continue
        if m["hour"] is not None and not _hour_ok(m["hour"]):
            continue
        if m["minute"] is not None and not _minute_or_second_ok(m["minute"]):
            continue
        if m["second"] is not None and not _minute_or_second_ok(m["second"]):
            continue
        ranges.append(m.span())

    for m in _DAY_MONTH_OR_MONTH_DAY_YEAR_RE.finditer(text):
        a, b = int(m["a"]), int(m["b"])
        if _year_ok(m["year"]) and 1 <= a <= 31 and 1 <= b <= 31 and (a <= 12 or b <= 12):
            ranges.append(m.span())

    for m in _COMPACT_ISO_RE.finditer(text):
        if not (_year_ok(m["year"]) and _month_ok(m["month"]) and _day_ok(m["day"])):
            continue
        if m["hour"] is not None and not _hour_ok(m["hour"]):
            continue
        if m["minute"] is not None and not _minute_or_second_ok(m["minute"]):
            continue
        if m["second"] is not None and not _minute_or_second_ok(m["second"]):
            continue
        ranges.append(m.span())

    for m in _TIME_DOTTED_RE.finditer(text):
        if _hour_ok(m["hour"]) and _minute_or_second_ok(m["minute"]) and _minute_or_second_ok(m["second"]):
            ranges.append(m.span())

    return ranges
