import fitz
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


class TestIgnoreVerifyFailureOption:
    def _make_pdf(self, path) -> None:
        doc = fitz.open()
        doc.new_page()
        doc.save(path)
        doc.close()

    def test_verification_failure_exits_fatal_by_default(self, tmp_path, monkeypatch) -> None:
        src = tmp_path / "doc.pdf"
        self._make_pdf(src)
        dest = tmp_path / "out.pdf"

        def _always_fails(*args, **kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr("audit_redactor.handlers.pdf_handler.verify_pdf_redacted", _always_fails)

        result = CliRunner().invoke(main, ["redact", str(src), str(dest), "--offline"])

        assert result.exit_code == EXIT_FATAL
        assert not dest.exists()

    def test_ignore_verify_failure_flag_keeps_output_and_exits_zero(self, tmp_path, monkeypatch) -> None:
        src = tmp_path / "doc.pdf"
        self._make_pdf(src)
        dest = tmp_path / "out.pdf"

        def _always_fails(*args, **kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr("audit_redactor.handlers.pdf_handler.verify_pdf_redacted", _always_fails)

        result = CliRunner().invoke(
            main, ["redact", str(src), str(dest), "--offline", "--ignore-verify-failure"]
        )

        assert result.exit_code == EXIT_SUCCESS
        assert dest.exists()
        assert "--ignore-verify-failure" in result.output
        assert "⚠️" in result.output


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


class TestCompanyListOption:
    """--company-list (falling back to ~/client_names.txt) per PLAN.md 2.10 --
    lets a real, private client list live outside the repo instead of
    overwriting the bundled safe-sample data file that's checked into git.
    """

    def test_explicit_company_list_is_used(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr("audit_redactor.cli._DEFAULT_COMPANY_LIST_PATH", tmp_path / "unused.txt")
        company_list = tmp_path / "clients.txt"
        company_list.write_text("Acme Corp\n", encoding="utf-8")
        src = tmp_path / "in.json"
        src.write_text('{"note": "Contract with Acme Corp signed today."}', encoding="utf-8")
        dest = tmp_path / "out.json"

        result = CliRunner().invoke(
            main, ["redact", str(src), str(dest), "--offline", "--company-list", str(company_list)]
        )

        assert result.exit_code == EXIT_SUCCESS
        assert f"using {company_list} for company names redaction" in result.output
        assert "Acme Corp" not in dest.read_text(encoding="utf-8")

    def test_env_var_is_used_when_no_flag_given(self, tmp_path, monkeypatch) -> None:
        # redact.sh (the Docker wrapper) has no way to bind-mount the right
        # host file without first knowing its path -- rather than parsing
        # --company-list out of the CLI args to find that path, it reads
        # AUDIT_REDACTOR_COMPANY_LIST from the shell and forwards it as-is,
        # relying on Click's `envvar=` support picking it up here exactly
        # like an explicit --company-list would.
        monkeypatch.setattr("audit_redactor.cli._DEFAULT_COMPANY_LIST_PATH", tmp_path / "unused.txt")
        company_list = tmp_path / "clients.txt"
        company_list.write_text("Acme Corp\n", encoding="utf-8")
        src = tmp_path / "in.json"
        src.write_text('{"note": "Contract with Acme Corp signed today."}', encoding="utf-8")
        dest = tmp_path / "out.json"

        result = CliRunner().invoke(
            main,
            ["redact", str(src), str(dest), "--offline"],
            env={"AUDIT_REDACTOR_COMPANY_LIST": str(company_list)},
        )

        assert result.exit_code == EXIT_SUCCESS
        assert f"using {company_list} for company names redaction" in result.output
        assert "Acme Corp" not in dest.read_text(encoding="utf-8")

    def test_default_path_used_when_no_flag_given(self, tmp_path, monkeypatch) -> None:
        default_list = tmp_path / "client_names.txt"
        default_list.write_text("Acme Corp\n", encoding="utf-8")
        monkeypatch.setattr("audit_redactor.cli._DEFAULT_COMPANY_LIST_PATH", default_list)
        src = tmp_path / "in.json"
        src.write_text('{"note": "Contract with Acme Corp signed today."}', encoding="utf-8")
        dest = tmp_path / "out.json"

        result = CliRunner().invoke(main, ["redact", str(src), str(dest), "--offline"])

        assert result.exit_code == EXIT_SUCCESS
        assert f"using {default_list} for company names redaction" in result.output
        assert "Acme Corp" not in dest.read_text(encoding="utf-8")

    def test_missing_default_path_warns_and_falls_back_to_bundled_sample(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr("audit_redactor.cli._DEFAULT_COMPANY_LIST_PATH", tmp_path / "does_not_exist.txt")
        src = tmp_path / "in.json"
        # "Tesco" is one of the bundled safe-sample list's entries.
        src.write_text('{"note": "Compared prices at Tesco today."}', encoding="utf-8")
        dest = tmp_path / "out.json"

        result = CliRunner().invoke(main, ["redact", str(src), str(dest), "--offline"])

        assert result.exit_code == EXIT_SUCCESS
        assert "not found" in result.output
        assert "falling back to the bundled sample list" in result.output
        assert "Tesco" not in dest.read_text(encoding="utf-8")
