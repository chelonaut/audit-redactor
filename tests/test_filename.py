from pathlib import Path

from audit_redactor.appliers.filename import redact_filename


class TestRedactFilename:
    def test_redacts_aws_account_id_in_stem(self) -> None:
        result = redact_filename(Path("/out/report-1234-5678-9012.pdf"))
        assert result == Path("/out/report-xxxx-xxxx-9012.pdf")

    def test_redacts_company_name_in_stem(self) -> None:
        result = redact_filename(Path("/out/tesco-audit-notes.md"))
        assert result == Path("/out/(REDACTED)-audit-notes.md")

    def test_redacts_email_in_stem(self) -> None:
        result = redact_filename(Path("/out/jane.doe@example.com-report.pdf"))
        assert "jane.doe@example.com" not in str(result)
        assert result.suffix == ".pdf"

    def test_extension_left_untouched(self) -> None:
        result = redact_filename(Path("/out/tesco-report.PDF"))
        assert result.suffix == ".PDF"

    def test_parent_directory_left_untouched(self) -> None:
        result = redact_filename(Path("/out/tesco-clients/tesco-report.pdf"))
        assert result.parent == Path("/out/tesco-clients")

    def test_no_sensitive_content_left_unchanged(self) -> None:
        path = Path("/out/quarterly-summary.pdf")
        assert redact_filename(path) == path
