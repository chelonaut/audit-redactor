"""JSON handler (PLAN.md 2.6, build phase 3).

Parses with `json.loads`, walks the tree, and redacts only string leaf
values -- never regexes the raw file text -- so the output is guaranteed
valid JSON by construction. Numeric/bool/null leaves are left untouched by
default; converting a number to a redacted string would silently change its
type and could break an auditor's schema validation.

Deliberately does not run the Claude augmentation pass (phase 9): detection
here happens per string leaf, and PLAN.md 2.8's design sends one whole
document's text to Claude per call, not one call per leaf -- doing the
latter would fire a Claude API call per JSON string value, which doesn't
scale and loses the full-document context the augmentation prompt relies on.
JSON documents therefore only get the deterministic regex/company-list pass,
same as every format in `--offline` mode. Worth revisiting with a two-pass
design (collect all leaves, one Claude call over the concatenated corpus,
then re-walk to apply grounded spans per leaf) if a real JSON-heavy PII case
surfaces.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from audit_redactor.appliers.text import PLACEHOLDER, redact_text
from audit_redactor.detectors import detect_text
from audit_redactor.pipeline import register

# Supplementary check per PLAN.md 2.6: a key name alone (e.g. "accountId")
# signals sensitivity even when the value itself wouldn't match any regex
# (e.g. an opaque internal ID), so these keys' string values are redacted
# outright regardless of what the detectors find.
_SENSITIVE_KEY_RE = re.compile(
    r"account.?(id|number)|ssn|social.?security|passport|api.?key|secret|password|token|credential",
    re.IGNORECASE,
)


def _is_sensitive_key(key: str) -> bool:
    return bool(_SENSITIVE_KEY_RE.search(key))


def _redact_value(key: str | None, value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _redact_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(key, item) for item in value]
    if isinstance(value, str):
        if key is not None and _is_sensitive_key(key):
            return PLACEHOLDER
        return redact_text(value, detect_text(value))
    return value


@register(".json")
def redact_json(input_path: Path, output_path: Path, offline: bool) -> Path:
    data = json.loads(input_path.read_text(encoding="utf-8"))
    redacted = _redact_value(None, data)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(redacted, indent=2) + "\n", encoding="utf-8")
    return output_path
