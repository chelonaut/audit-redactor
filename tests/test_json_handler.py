import json

import pytest

from audit_redactor.pipeline import redact_file


class TestJsonHandler:
    def test_redacts_string_leaves_and_stays_valid_json(self, tmp_path) -> None:
        src = tmp_path / "record.json"
        src.write_text(
            json.dumps(
                {
                    "contact": "jane.doe@example.com",
                    "client": "Tesco",
                    "note": "Call 555-123-4567 re: the audit.",
                    "nested": {"link": "https://example.com/report"},
                    "tags": ["ok", "reviewed by @jane-doe"],
                }
            ),
            encoding="utf-8",
        )
        dest = tmp_path / "out" / "record.json"

        actual = redact_file(src, dest, True)

        assert actual == dest
        redacted = json.loads(dest.read_text(encoding="utf-8"))
        assert "jane.doe@example.com" not in redacted["contact"]
        assert "Tesco" not in redacted["client"]
        assert "555-123-4567" not in redacted["note"]
        assert "https://example.com/report" not in redacted["nested"]["link"]
        assert "@jane-doe" not in redacted["tags"][1]
        assert redacted["tags"][0] == "ok"

    def test_sensitive_key_redacted_regardless_of_regex_match(self, tmp_path) -> None:
        src = tmp_path / "record.json"
        src.write_text(json.dumps({"accountId": "not-a-regex-match-9f8"}), encoding="utf-8")
        dest = tmp_path / "out.json"

        redact_file(src, dest, True)

        redacted = json.loads(dest.read_text(encoding="utf-8"))
        assert redacted["accountId"] == "(REDACTED)"

    def test_numeric_leaves_left_untouched(self, tmp_path) -> None:
        src = tmp_path / "record.json"
        src.write_text(json.dumps({"accountId": 123456789012, "count": 4}), encoding="utf-8")
        dest = tmp_path / "out.json"

        redact_file(src, dest, True)

        redacted = json.loads(dest.read_text(encoding="utf-8"))
        # Numeric values are left untouched by default (PLAN.md 2.6), even
        # under a sensitive key -- redacting would change the value's type.
        assert redacted["accountId"] == 123456789012
        assert redacted["count"] == 4

    def test_output_is_valid_json(self, tmp_path) -> None:
        src = tmp_path / "record.json"
        src.write_text(json.dumps({"a": [1, {"b": "test@example.com"}, None, True]}), encoding="utf-8")
        dest = tmp_path / "out.json"

        redact_file(src, dest, True)

        # json.loads succeeding is the assertion -- malformed output would raise.
        json.loads(dest.read_text(encoding="utf-8"))

    def test_declines_to_overwrite_existing_output(self, tmp_path) -> None:
        src = tmp_path / "record.json"
        src.write_text(json.dumps({"contact": "jane.doe@example.com"}), encoding="utf-8")
        dest = tmp_path / "out.json"
        dest.write_text('{"prior": "output"}', encoding="utf-8")

        with pytest.raises(FileExistsError):
            redact_file(src, dest, True)

        # The pre-existing output is untouched, not partially overwritten.
        assert json.loads(dest.read_text(encoding="utf-8")) == {"prior": "output"}

    def test_declines_when_output_path_is_the_input_path(self, tmp_path) -> None:
        src = tmp_path / "record.json"
        original = json.dumps({"contact": "jane.doe@example.com"})
        src.write_text(original, encoding="utf-8")

        with pytest.raises(FileExistsError):
            redact_file(src, src, True)

        # A misconfigured input==output invocation must never mutate the original.
        assert src.read_text(encoding="utf-8") == original
