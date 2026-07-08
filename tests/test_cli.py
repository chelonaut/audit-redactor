from click.testing import CliRunner

from audit_redactor.cli import EXIT_FATAL, EXIT_PARTIAL, EXIT_SUCCESS, main
from audit_redactor.detectors.claude_augment import UsageTotals


class TestExitCodes:
    """PLAN.md build phase 10: 0 success, 1 fatal, 2 partial (batch-only)."""

    def test_single_file_success_exits_zero(self, tmp_path) -> None:
        src = tmp_path / "in.json"
        src.write_text('{"note": "nothing sensitive"}', encoding="utf-8")
        dest = tmp_path / "out.json"

        result = CliRunner().invoke(main, ["redact", str(src), str(dest), "--offline"])

        assert result.exit_code == EXIT_SUCCESS

    def test_missing_input_exits_fatal(self, tmp_path) -> None:
        result = CliRunner().invoke(
            main, ["redact", str(tmp_path / "missing.json"), str(tmp_path / "out.json"), "--offline"]
        )

        assert result.exit_code == EXIT_FATAL

    def test_no_glob_matches_exits_fatal(self, tmp_path) -> None:
        result = CliRunner().invoke(
            main, ["redact", str(tmp_path / "*.nomatch"), str(tmp_path / "out"), "--offline"]
        )

        assert result.exit_code == EXIT_FATAL

    def test_single_file_hard_failure_exits_fatal(self, tmp_path) -> None:
        # Malformed JSON -- json.loads raises, and there's only one file, so
        # nothing at all succeeded.
        src = tmp_path / "bad.json"
        src.write_text("{not valid json", encoding="utf-8")
        dest = tmp_path / "out.json"

        result = CliRunner().invoke(main, ["redact", str(src), str(dest), "--offline"])

        assert result.exit_code == EXIT_FATAL

    def test_batch_partial_failure_exits_partial(self, tmp_path) -> None:
        input_dir = tmp_path / "in"
        input_dir.mkdir()
        (input_dir / "good.json").write_text('{"note": "fine"}', encoding="utf-8")
        (input_dir / "bad.json").write_text("{not valid json", encoding="utf-8")
        dest = tmp_path / "out"

        result = CliRunner().invoke(main, ["redact", str(input_dir), str(dest), "--offline"])

        assert result.exit_code == EXIT_PARTIAL

    def test_batch_total_failure_exits_fatal(self, tmp_path) -> None:
        input_dir = tmp_path / "in"
        input_dir.mkdir()
        (input_dir / "bad.json").write_text("{not valid json", encoding="utf-8")
        dest = tmp_path / "out"

        result = CliRunner().invoke(main, ["redact", str(input_dir), str(dest), "--offline"])

        assert result.exit_code == EXIT_FATAL

    def test_batch_full_success_exits_zero(self, tmp_path) -> None:
        input_dir = tmp_path / "in"
        input_dir.mkdir()
        (input_dir / "a.json").write_text('{"note": "fine"}', encoding="utf-8")
        (input_dir / "b.json").write_text('{"note": "also fine"}', encoding="utf-8")
        dest = tmp_path / "out"

        result = CliRunner().invoke(main, ["redact", str(input_dir), str(dest), "--offline"])

        assert result.exit_code == EXIT_SUCCESS

    def test_single_file_declines_to_overwrite_existing_output(self, tmp_path) -> None:
        src = tmp_path / "in.json"
        src.write_text('{"note": "nothing sensitive"}', encoding="utf-8")
        dest = tmp_path / "out.json"
        dest.write_text('{"prior": "output"}', encoding="utf-8")

        result = CliRunner().invoke(main, ["redact", str(src), str(dest), "--offline"])

        assert result.exit_code == EXIT_FATAL
        assert dest.read_text(encoding="utf-8") == '{"prior": "output"}'

    def test_batch_continues_past_a_preexisting_output_file(self, tmp_path) -> None:
        # One file's output already exists (e.g. a re-run, or a misconfigured
        # output dir) -- that one file must fail and be reported, but the
        # rest of the batch must still be attempted, per the "never stop on
        # one file's error" design.
        input_dir = tmp_path / "in"
        input_dir.mkdir()
        (input_dir / "a.json").write_text('{"note": "fine"}', encoding="utf-8")
        (input_dir / "b.json").write_text('{"note": "also fine"}', encoding="utf-8")
        dest = tmp_path / "out"
        dest.mkdir()
        (dest / "b.json").write_text('{"prior": "output"}', encoding="utf-8")

        result = CliRunner().invoke(main, ["redact", str(input_dir), str(dest), "--offline"])

        assert result.exit_code == EXIT_PARTIAL
        assert (dest / "a.json").exists()
        assert (dest / "b.json").read_text(encoding="utf-8") == '{"prior": "output"}'
        assert "b.json" in result.output
        assert "already exists" in result.output


class TestUsageSummary:
    def test_offline_run_prints_no_usage_summary(self, tmp_path) -> None:
        src = tmp_path / "in.json"
        src.write_text('{"note": "nothing sensitive"}', encoding="utf-8")
        dest = tmp_path / "out.json"

        result = CliRunner().invoke(main, ["redact", str(src), str(dest), "--offline"])

        assert "Claude usage" not in result.output

    def test_single_file_run_prints_usage_summary_when_calls_were_made(self, tmp_path, monkeypatch) -> None:
        src = tmp_path / "in.json"
        src.write_text('{"note": "nothing sensitive"}', encoding="utf-8")
        dest = tmp_path / "out.json"

        monkeypatch.setattr(
            "audit_redactor.cli.get_usage_totals",
            lambda: UsageTotals(api_calls=3, input_tokens=1234, output_tokens=567),
        )

        result = CliRunner().invoke(main, ["redact", str(src), str(dest), "--offline"])

        assert "Claude usage: 3 API call(s), 1,234 input tokens, 567 output tokens" in result.output

    def test_batch_run_prints_usage_summary_when_calls_were_made(self, tmp_path, monkeypatch) -> None:
        input_dir = tmp_path / "in"
        input_dir.mkdir()
        (input_dir / "a.json").write_text('{"note": "fine"}', encoding="utf-8")
        dest = tmp_path / "out"

        monkeypatch.setattr(
            "audit_redactor.cli.get_usage_totals",
            lambda: UsageTotals(api_calls=1, input_tokens=200, output_tokens=40),
        )

        result = CliRunner().invoke(main, ["redact", str(input_dir), str(dest), "--offline"])

        assert "Claude usage: 1 API call(s), 200 input tokens, 40 output tokens" in result.output
