import pytest

from audit_redactor.detectors import configure_default_company_list


@pytest.fixture(autouse=True)
def _reset_default_company_list():
    """Reset the shared default company-name detector to the bundled sample
    list before and after every test.

    `cli.py`'s `redact` command points this at `~/client_names.txt` (or
    whatever `--company-list` says) and that setting persists process-wide
    until changed again. Without this reset, a `tests/test_cli.py` run
    earlier in the same pytest session could leave every later test's
    detector pointed at a real developer's actual `~/client_names.txt` (if
    one happens to exist on the machine running the suite), making other
    tests' company-match assertions depend on that machine's home directory.
    """
    configure_default_company_list(None)
    yield
    configure_default_company_list(None)
