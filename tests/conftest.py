import pytest

from audit_redactor.appliers.output_guard import configure_ignore_verify_failure
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


@pytest.fixture(autouse=True)
def _reset_ignore_verify_failure():
    """Reset the --ignore-verify-failure toggle before and after every test,
    same rationale as `_reset_default_company_list` above -- it's process-
    wide state that would otherwise leak between tests (or from a
    `tests/test_cli.py` run into every other test module's verification
    assertions) once any test turns it on.
    """
    configure_ignore_verify_failure(False)
    yield
    configure_ignore_verify_failure(False)
