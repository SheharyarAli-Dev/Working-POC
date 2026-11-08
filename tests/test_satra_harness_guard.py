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


# Native extension modules: Python's import system prefers an extension module over the .py file of the
# same name in the same folder, so a head .so/.pyd/.dylib can replace any module, not only pytest.
NATIVE = ["app/security.cpython-312-x86_64-linux-gnu.so", "app/security.abi3.so", "lib/deep/x.SO",
          "app/fast.cp312-win_amd64.pyd", "app/fast.PYD", "app/mac.cpython-312-darwin.so", "app/mac.dylib"]


@pytest.mark.parametrize("path", NATIVE)
def test_native_modules_added_by_the_head_are_flagged(tmp_path, path):
    """Any added .so / .pyd / .dylib or EXTENSION_SUFFIXES file, any folder, any letter case, is a native module finding."""
    found = check(tmp_path, {path: "\x7fELF not really"})
    assert found == [{"path": path, "why": "native module " + path, "label": "native module " + path}]


def test_a_changed_native_module_is_flagged(tmp_path):
    """Changing a native module the base already has is flagged like adding one."""
    so = "app/speedups.cpython-312-x86_64-linux-gnu.so"
    assert [i["path"] for i in check(tmp_path, {so: "v2"}, {so: "v1"})] == [so]


def test_an_unchanged_native_module_from_the_base_is_not_flagged(tmp_path):
    """A .so file the base already had, byte for byte the same in the head, is not a finding."""
    so = "app/speedups.cpython-312-x86_64-linux-gnu.so"
    assert check(tmp_path, {"app/security.py": SECURE}, {so: "\x7fELF same bytes"}) == []


def test_every_extension_suffix_of_the_interpreter_is_covered(tmp_path):
    """Each suffix in importlib.machinery.EXTENSION_SUFFIXES is flagged (upper case too)."""
    from importlib.machinery import EXTENSION_SUFFIXES
    files = {"app/m%d%s" % (i, (suffix.upper() if i % 2 else suffix)): "x" for i, suffix in enumerate(EXTENSION_SUFFIXES)}
    assert sorted(i["path"] for i in check(tmp_path, files)) == sorted(files)


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
    "test files import pytest": ({"tests/test_app.py": "import pytest\n", "test_root.py": "from pytest import fixture\n",
                                  "app/sec_test.py": "import pytest.mark\n", "test/helpers.py": "p = __import__('pytest')\n"}, None),
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


def test_native_module_beside_a_broken_module_makes_the_gate_inconclusive(tmp_path, container_on_host):
    """The review's attack: broken app/security.py plus app/security.cpython-312-x86_64-linux-gnu.so is INCONCLUSIVE, never ACCEPT."""
    so = "app/security.cpython-312-x86_64-linux-gnu.so"
    status, details, _ = gate(tmp_path, head_kwargs={"security": BROKEN, "extra": {so: "\x7fELF stand-in for a compiled module"}})
    assert status == "INCONCLUSIVE"
    # Since step 8 the changed .py beside it is listed too ("shadowed by native module"); the .so comes first.
    assert details["reason"].startswith("test-harness tampering suspected: native module " + so + ", ")
    assert [item["path"] for item in details["harness_tampering"]] == [so, "app/security.py"]
    assert container_on_host.runs == []


def test_unchanged_native_module_from_the_base_keeps_the_normal_verdict(tmp_path, container_on_host):
    """A .so the base already had and the head did not change is not a finding; the gate reaches its normal verdict."""
    so = {"app/speedups.cpython-312-x86_64-linux-gnu.so": "\x7fELF same bytes in base and head"}
    status, details, _ = gate(tmp_path, {"extra": so})
    assert status == "ACCEPT", details["reason"]
    assert "harness_tampering" not in details


# Test-named files are exempt only from the plain `pytest` import check: a file under tests/ (for example the review's
# app/tests/shim.py) is still importable by code under test, so _pytest imports and sys.modules writes count anywhere.
TEST_NAMED = {
    "app/tests/shim.py writes sys.modules": {"app/tests/shim.py": "import sys\nsys.modules['app.security'] = object()\n"},
    "app/tests/shim.py imports _pytest": {"app/tests/shim.py": "from _pytest import runner\n"},
    "test file imports _pytest": {"tests/test_app.py": "import _pytest.reports\n"},
    "test_ file binds sys.modules": {"test_root.py": "from sys import modules\n"},
    "_test.py file deletes from sys.modules": {"app/sec_test.py": "import sys as s\ndel s.modules['json']\n"},
    "test file import_module _pytest": {"test/helpers.py": "import importlib\nimportlib.import_module('_pytest.runner')\n"},
}


@pytest.mark.parametrize("case", list(TEST_NAMED))
def test_test_named_files_are_still_checked_for_pytest_internals_and_sys_modules(tmp_path, case):
    """Only `import pytest` is allowed in test-named files; _pytest imports and sys.modules writes are flagged in every .py file."""
    found = check(tmp_path, TEST_NAMED[case])
    assert [item["path"] for item in found] == list(TEST_NAMED[case]), found


def test_review_shim_under_a_tests_folder_makes_the_gate_inconclusive(tmp_path, container_on_host):
    """The review's case: app/tests/shim.py that writes sys.modules, with a broken head, is INCONCLUSIVE and nothing runs."""
    shim = {"app/tests/__init__.py": "", "app/tests/shim.py": "import sys\nsys.modules['app.security'] = object()\n"}
    status, details, _ = gate(tmp_path, head_kwargs={"security": BROKEN, "extra": shim})
    assert status == "INCONCLUSIVE"
    assert details["reason"] == "test-harness tampering suspected: app/tests/shim.py"
    assert container_on_host.runs == []


def test_project_tests_that_import_pytest_still_get_a_verdict(tmp_path, container_on_host):
    """Head test files may import pytest: no tampering finding, and the gate reaches its normal ACCEPT."""
    tests = {"tests/test_app.py": "import pytest\n\n\ndef test_app():\n    assert True\n"}
    status, details, _ = gate(tmp_path, head_kwargs={"project_tests": tests})
    assert status == "ACCEPT", details["reason"]
    assert "harness_tampering" not in details


# --- second review (docs/satra/harness-isolation.md, step 8) ----------------------------------------------

import io  # noqa: E402
import zipfile  # noqa: E402
from pathlib import Path  # noqa: E402

from backend.orchestrator.context_service import ContextService  # noqa: E402
from backend.orchestrator.service import Service  # noqa: E402
from backend.satra import analyzer as satra_analyzer  # noqa: E402
from test_satra_config import project  # noqa: E402

# 1. Non-test code that imports a test-named module. A shim under tests/ may import pytest's public API (allowed in
#    test files), e.g. TestReport, and app code can then reach it through the shim.
SHIM = {"app/tests/__init__.py": "", "app/tests/shim.py": "from pytest import TestReport\n"}
REVIEW_APP = BROKEN + "from app.tests.shim import TestReport\nTestReport.passed = property(lambda self: True)\n"
TEST_IMPORTS = {
    "from app.tests.shim": "from app.tests.shim import TestReport\n",
    "import app.tests.shim": "import app.tests.shim\n",
    "relative from .tests.shim": "from .tests.shim import TestReport\n",
    "relative from .tests import shim": "from .tests import shim\n",
    "relative from . import tests": "from . import tests\n",
    "relative from ..test": "from ..test import helpers\n",
    "test_ module": "import test_utils\n",
    "_test module by name": "from app import helpers_test\n",
    "relative test_ module": "from .test_fixtures import make\n",
    "import_module literal": "import importlib\nimportlib.import_module('app.tests.shim')\n",
    "__import__ literal": "__import__('tests.shim')\n",
}


@pytest.mark.parametrize("case", list(TEST_IMPORTS))
def test_non_test_code_importing_a_test_module_is_flagged(tmp_path, case):
    """Non-test code importing from tests/ or test/, or a test_* / *_test module (relative imports too), is flagged."""
    found = check(tmp_path, {**SHIM, "app/util.py": TEST_IMPORTS[case]})
    assert [item["path"] for item in found] == ["app/util.py"], found


@pytest.mark.parametrize("source", ["from tests.helpers import make\n", "from .test_fixtures import make\n",
                                    "import app.tests.shim\n"])
def test_test_files_may_import_other_test_modules(tmp_path, source):
    """Test files importing test helpers is normal and not flagged."""
    assert check(tmp_path, {"tests/test_app.py": source, "tests/helpers.py": ""}) == []


@pytest.mark.parametrize("source", ["import testing\n", "from app import latest, contest_rules\n", "import attest.core\n",
                                    "from app.testsuite import x\n"])
def test_names_that_only_contain_test_are_not_test_modules(tmp_path, source):
    """testing, latest, contest_rules, attest, testsuite are not test-named modules."""
    assert check(tmp_path, {"app/util.py": source}) == []


def test_review_shim_with_test_report_makes_the_gate_inconclusive(tmp_path, container_on_host):
    """The review's case: app/tests/shim.py imports pytest.TestReport and broken app/security.py imports the shim: INCONCLUSIVE."""
    status, details, _ = gate(tmp_path, head_kwargs={"security": REVIEW_APP, "extra": SHIM})
    assert status == "INCONCLUSIVE"
    assert details["reason"] == "test-harness tampering suspected: app/security.py"
    assert container_on_host.runs == []


# 2. A changed .py beside a native module of the same name: the native module is what Python imports, so the
#    change would never be tested (and the base's .so would answer for it).
SO = "app/security.cpython-312-x86_64-linux-gnu.so"


def test_changed_py_next_to_a_base_native_module_is_flagged(tmp_path):
    """Base has app/security.py and app/security.<suffix>.so; the head changes only the .py: the .py is flagged."""
    found = check(tmp_path, {"app/security.py": BROKEN}, {SO: "\x7fELF base module"})
    assert found == [{"path": "app/security.py", "why": "shadowed by native module " + SO,
                      "label": "app/security.py (shadowed by native module %s)" % SO}]


@pytest.mark.parametrize("native", ["app/security.abi3.so", "app/security.pyd", "app/Security.DYLIB", "app/__init__.cpython-312-darwin.so"])
def test_any_native_suffix_of_the_same_module_name_shadows(tmp_path, native):
    """Every native suffix, any letter case, and __init__ modules count as the same module name."""
    target = "app/__init__.py" if "__init__" in native else "app/security.py"
    found = check(tmp_path, {target: "# changed\n"}, {native: "x"})
    assert [item["path"] for item in found] == [target], found


def test_head_added_native_module_flags_the_changed_py_too(tmp_path):
    """A head-added .so is a native-module finding, and the changed .py beside it is flagged as shadowed."""
    found = check(tmp_path, {"app/security.py": BROKEN, SO: "x"})
    assert sorted(item["path"] for item in found) == sorted(["app/security.py", SO])


@pytest.mark.parametrize("head, base", [
    ({"app/other.py": "# changed\n"}, {SO: "x"}),            # another module in the same folder
    ({"lib/security.py": "# new\n"}, {SO: "x"}),             # same name, other folder
    ({"app/notes.txt": "x"}, {SO: "x"}),                     # nothing changed next to it
])
def test_native_modules_do_not_flag_other_modules(tmp_path, head, base):
    """Only a changed .py with the same module name in the same folder is shadowed."""
    assert check(tmp_path, head, base) == []


def test_base_native_module_beside_a_changed_py_makes_the_gate_inconclusive(tmp_path, container_on_host):
    """Gate: base ships app/security.py + .so, head breaks the .py: INCONCLUSIVE before anything runs."""
    status, details, _ = gate(tmp_path, {"extra": {SO: "\x7fELF base module"}}, {"security": BROKEN, "extra": {SO: "\x7fELF base module"}})
    assert status == "INCONCLUSIVE"
    assert details["reason"] == "test-harness tampering suspected: app/security.py (shadowed by native module %s)" % SO
    assert container_on_host.runs == []


# 3. pythonpath entries of the base pytest.ini: a plain file there (a zip file is importable from sys.path), or the
#    directory removed, changes where the trusted run imports the head from.
def zipped(files):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        for name, text in files.items():
            archive.writestr(name, text)
    return data.getvalue()


def layout(tmp_path, ini, base_files, head_files, head_bytes=None):
    base = write(tmp_path / "base", {"app/__init__.py": "", **base_files})
    head = write(tmp_path / "head", {"app/__init__.py": "", **head_files})
    for name, data in (head_bytes or {}).items():
        (head / name).parent.mkdir(parents=True, exist_ok=True)
        (head / name).write_bytes(data)
    (tmp_path / "pytest.ini").write_text(ini)
    return harness_guard.suspicious(base, head, pytest_ini=tmp_path / "pytest.ini")


SRC = {"src/app/__init__.py": "", "src/app/security.py": SECURE}


def test_zip_file_named_like_a_pythonpath_entry_is_flagged(tmp_path):
    """The review's case: base `pythonpath = src`; the head replaces src/ by a zip file named src: both are flagged."""
    found = layout(tmp_path, "[pytest]\npythonpath = src\n", SRC, {}, {"src": zipped({"app/__init__.py": "", "app/security.py": SECURE})})
    assert [(item["path"], item["why"]) for item in found] == [
        ("src", "plain file where the base pytest.ini maps pythonpath entry src"),
        ("src/", "deletes the directory the base pytest.ini maps as pythonpath entry src")]


def test_plain_file_at_a_nested_pythonpath_entry_is_flagged(tmp_path):
    """Every pythonpath entry is checked, nested ones included; an existing directory entry is fine."""
    found = layout(tmp_path, "[pytest]\npythonpath = lib pkgs/src\n", {"lib/m.py": ""}, {"lib/m.py": "", "pkgs/src": "x"})
    assert [item["path"] for item in found] == ["pkgs/src"]


def test_deleting_a_pythonpath_directory_is_flagged(tmp_path):
    """Removing every file under the mapped directory is flagged even without a file in its place."""
    found = layout(tmp_path, "[pytest]\npythonpath = src\n", SRC, {"app/security.py": SECURE})
    assert [item["path"] for item in found] == ["src/"]


@pytest.mark.parametrize("ini", ["[pytest]\npythonpath = .\n", "[pytest]\n", "[pytest]\npythonpath = ../outside /abs\n"])
def test_pythonpath_rules_ignore_entries_outside_the_head(tmp_path, ini):
    """'.', no entry, and entries the plugin does not map into the head (.., absolute) add no finding."""
    assert layout(tmp_path, ini, SRC, {**SRC, "src/app/security.py": BROKEN}) == []


def test_editing_files_inside_a_pythonpath_directory_is_not_flagged(tmp_path):
    """Changing code inside src/ keeps src a directory: ordinary change."""
    assert layout(tmp_path, "[pytest]\npythonpath = src\n", SRC, {**SRC, "src/app/security.py": BROKEN}) == []


def test_zip_named_src_makes_the_gate_inconclusive(tmp_path, container_on_host):
    """Gate: base ini `pythonpath = src`; head deletes src/ and adds a zip file named src: INCONCLUSIVE, nothing runs.

    `create_gate_run` cannot yet place a head file where the base has a directory (backend/orchestrator/workspace_manager.py
    leaves the base's emptied folders in the candidate worktree, so the copy fails with IsADirectoryError). The run is
    created from the head without the zip, and the candidate workspace is then given the head's real shape."""
    import shutil
    ini = {".asent/satra/pytest.ini": "[pytest]\npythonpath = src\n"}
    base = project(tmp_path / "base", extra={**ini, **SRC})
    head = project(tmp_path / "head", security=BROKEN, extra=ini)
    service = Service(tmp_path / "runtime")
    run = service.create_gate_run(base, head, {})
    candidate = Path(run.candidate_workspace)
    shutil.rmtree(candidate / "src")
    (candidate / "src").write_bytes(zipped({"app/__init__.py": "", "app/security.py": SECURE}))
    context = ContextService(run.candidate_workspace, run.baseline_workspace, service.threats.snapshot(), gate=True)
    status, details, _ = satra_analyzer.analyze(context, tmp_path / "out", lambda *a: None)
    assert status == "INCONCLUSIVE"
    assert details["reason"] == "test-harness tampering suspected: src, src/"
    assert container_on_host.runs == []
