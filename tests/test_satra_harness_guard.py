"""Head changes to the test harness make SATRA INCONCLUSIVE for human review (docs/satra/harness-isolation.md, step 3).

Unit tests call `harness_guard.suspicious(base, head)` on real directories; gate tests run the real gate path
(`container_on_host`, tests/test_satra_config.py) and check that no test ran once tampering is suspected.
"""
import json

import pytest

from backend.satra import harness_guard
from test_satra_config import BROKEN, SECURE, container_on_host, gate  # noqa: F401  (fixture)


def write(root, files):
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def check(tmp_path, head_files, base_files=None):
    app = {"app/__init__.py": "", "app/security.py": SECURE}
    base = write(tmp_path / "base", {**app, **(base_files or {})})
    head = write(tmp_path / "head", {**app, **(base_files or {}), **head_files})
    return harness_guard.suspicious(base, head)


PYTEST_SELECT = "addopts = -k owner\n"
FLAGGED = {
    "root conftest.py": {"conftest.py": "import pytest\n"},
    "nested conftest.py": {"app/conftest.py": ""},
    "pytest.py": {"pytest.py": ""},
    "pytest/ package": {"pytest/__init__.py": ""},
    "_pytest/ package": {"_pytest/runner.py": ""},
    "nested _pytest/": {"src/_pytest/__init__.py": ""},
    "_pytest.py": {"_pytest.py": ""},
    "pytest extension module": {"pytest.cpython-312-x86_64-linux-gnu.so": "x"},
    "sitecustomize.py": {"sitecustomize.py": ""},
    "usercustomize.py": {"lib/usercustomize.py": ""},
    ".pth file": {"extra.pth": "import os\n"},
    "pytest.ini": {"pytest.ini": "[pytest]\n"},
    ".pytest.ini": {".pytest.ini": "[pytest]\n"},
    "pytest.toml": {"pytest.toml": "[pytest]\n"},
    "pyproject ini_options": {"pyproject.toml": '[tool.pytest.ini_options]\naddopts = "-k owner"\n'},
    "pyproject native table": {"pyproject.toml": '[tool.pytest]\naddopts = ["-k", "owner"]\n'},
    "tox.ini [pytest]": {"tox.ini": "[pytest]\n" + PYTEST_SELECT},
    "setup.cfg [tool:pytest]": {"setup.cfg": "[tool:pytest]\n" + PYTEST_SELECT},
    "unreadable pyproject.toml": {"pyproject.toml": "[tool.pytest\n"},
    "unreadable setup.cfg": {"setup.cfg": "no section header\n"},
    "imports pytest": {"app/util.py": "import pytest\n"},
    "imports _pytest submodule": {"app/util.py": "import _pytest.reports as r\n"},
    "from _pytest import": {"app/util.py": "from _pytest import runner\n"},
    "__import__ pytest": {"app/util.py": "m = __import__('pytest')\n"},
    "import_module _pytest": {"app/util.py": "import importlib\nimportlib.import_module('_pytest.runner')\n"},
    "sys.modules item assignment": {"app/util.py": "import sys\nsys.modules['app.security'] = object()\n"},
    "sys.modules rebinding": {"app/util.py": "import sys\ndef f():\n    sys.modules = {}\n"},
    "sys.modules deletion": {"app/util.py": "import sys\ndel sys.modules['json']\n"},
    "sys alias update": {"app/util.py": "import sys as s\ns.modules.update({'x': None})\n"},
    "sys.modules setdefault": {"app/util.py": "import sys\nsys.modules.setdefault('x', None)\n"},
    "from sys import modules": {"app/util.py": "from sys import modules\n"},
    "unparseable code": {"app/util.py": "def broken(:\n"},
}


@pytest.mark.parametrize("case", list(FLAGGED))
def test_harness_changes_in_the_head_are_flagged(tmp_path, case):
    """Each harness file, pytest setting or pytest/sys.modules-touching non-test change is listed with a reason."""
    found = check(tmp_path, FLAGGED[case])
    assert [item["path"] for item in found] == list(FLAGGED[case]), found
    assert all(item["why"] for item in found)


def test_a_changed_existing_conftest_is_flagged(tmp_path):
    """Changing a conftest.py that the base already has is flagged, like adding one."""
    found = check(tmp_path, {"tests/conftest.py": "import pytest\nX = 2\n"}, {"tests/conftest.py": "import pytest\nX = 1\n"})
    assert [item["path"] for item in found] == ["tests/conftest.py"]


NOT_FLAGGED = {
    "unchanged conftest and settings": ({}, {"conftest.py": "import pytest\n", "pytest.ini": "[pytest]\n"}),
    "test files import pytest": ({"tests/test_app.py": "import pytest\n", "test_root.py": "import pytest\n",
                                  "app/sec_test.py": "import _pytest\n", "test/helpers.py": "import pytest\n"}, None),
    "pyproject outside the pytest table": ({"pyproject.toml": '[project]\nname = "b"\n[tool.pytest.ini_options]\naddopts = "-q"\n'},
                                           {"pyproject.toml": '[project]\nname = "a"\n[tool.pytest.ini_options]\naddopts = "-q"\n'}),
    "tox.ini outside [pytest]": ({"tox.ini": "[tox]\nenvlist = py313\n[pytest]\naddopts = -q\n"},
                                 {"tox.ini": "[tox]\nenvlist = py312\n[pytest]\naddopts = -q\n"}),
    "setup.cfg without a pytest section": ({"setup.cfg": "[metadata]\nname = b\n"}, None),
    "reads sys.modules": ({"app/util.py": "import sys\nme = sys.modules[__name__]\nok = sys.modules.get('json')\n"}, None),
    "pytest-like names": ({"app/pytest_helpers.py": "import pytest_mock_like\n", "docs/pytest_notes.txt": "x"}, None),
    "ordinary code change": ({"app/security.py": BROKEN}, None),
}


@pytest.mark.parametrize("case", list(NOT_FLAGGED))
def test_ordinary_changes_are_not_flagged(tmp_path, case):
    """Test files, deletions, unrelated settings and reads of sys.modules are not tampering."""
    head_files, base_files = NOT_FLAGGED[case]
    assert check(tmp_path, head_files, base_files) == []


def test_deleting_a_harness_file_is_not_flagged(tmp_path):
    """Removing the base's conftest.py or pytest.ini cannot add anything to the trusted run."""
    base = write(tmp_path / "base", {"app/__init__.py": "", "conftest.py": "import pytest\n", "pytest.ini": "[pytest]\n"})
    head = write(tmp_path / "head", {"app/__init__.py": ""})
    assert harness_guard.suspicious(base, head) == []


def test_asent_config_folder_is_not_compared(tmp_path):
    """The head's .asent/ is never used by a gate run (the base config is frozen), so it is not part of the comparison."""
    assert check(tmp_path, {".asent/satra/trusted_tests/conftest.py": "import pytest\n"}) == []


# --- gate runs ------------------------------------------------------------------------------------------

GATE_CASES = {
    "root conftest.py": {"conftest.py": "import pytest\n"},
    "pytest.py": {"pytest.py": "raise SystemExit(0)\n"},
    "pyproject.toml addopts": {"pyproject.toml": '[tool.pytest.ini_options]\naddopts = "-k owner"\n'},
    "sitecustomize.py": {"sitecustomize.py": ""},
    ".pth file": {"x.pth": "import os\n"},
    "app code importing pytest": {"app/util.py": "import pytest\n"},
    "app code writing sys.modules": {"app/util.py": "import sys\nsys.modules['app.security'] = None\n"},
}


@pytest.mark.parametrize("security", [SECURE, BROKEN], ids=["secure head", "broken head"])
@pytest.mark.parametrize("case", list(GATE_CASES))
def test_tampering_makes_the_gate_run_inconclusive_before_any_test_runs(tmp_path, container_on_host, case, security):
    """Suspected tampering is INCONCLUSIVE with the stated reason and the files listed; no image is built and no test runs."""
    status, details, uncertainty = gate(tmp_path, head_kwargs={"security": security, "extra": GATE_CASES[case]})
    assert status == "INCONCLUSIVE"
    assert details["reason"].startswith("test-harness tampering suspected")
    assert [item["path"] for item in details["harness_tampering"]] == list(GATE_CASES[case])
    assert any("tampering" in item for item in uncertainty)
    assert container_on_host.runs == [] and not container_on_host.engine.builds()


def test_project_tests_that_import_pytest_still_get_a_verdict(tmp_path, container_on_host):
    """Head test files may import pytest: no tampering finding, and the gate reaches its normal ACCEPT."""
    tests = {"tests/test_app.py": "import pytest\n\n\ndef test_app():\n    assert True\n"}
    status, details, _ = gate(tmp_path, head_kwargs={"project_tests": tests})
    assert status == "ACCEPT", details["reason"]
    assert "harness_tampering" not in details
