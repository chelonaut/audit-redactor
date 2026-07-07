import pytest

from audit_redactor.appliers.output_guard import ensure_output_does_not_exist


class TestEnsureOutputDoesNotExist:
    def test_raises_when_output_already_exists(self, tmp_path) -> None:
        existing = tmp_path / "out.txt"
        existing.write_text("prior content", encoding="utf-8")

        with pytest.raises(FileExistsError):
            ensure_output_does_not_exist(existing)

        # The check must never touch the file it's protecting.
        assert existing.read_text(encoding="utf-8") == "prior content"

    def test_allows_when_output_does_not_exist(self, tmp_path) -> None:
        ensure_output_does_not_exist(tmp_path / "does_not_exist_yet.txt")
