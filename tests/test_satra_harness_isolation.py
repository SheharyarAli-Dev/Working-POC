"""Trusted SATRA runs keep the pull request's head out of the test harness (docs/satra/harness-isolation.md).

Each attack below is planted in a head whose access check is broken (`return True`), so the trusted test
`test_other_user_denied` must fail. The attack must not change that result. Where the vector works
against an unguarded run (`python -m pytest` inside the head, with the trusted tests copied into it,
which is what SATRA did before this change), a control test shows that the same files do force a pass
there, so the guarded check is not vacuous.

Runs use `container_on_host` (tests/test_satra_config.py): the exact container command, executed on the
host with each mount's container path mapped to its host directory.
"""
import os
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from backend.orchestrator.hashing import copy_tree
from backend.satra import pytest_runner
from test_satra_config import BROKEN, SECURE, TRUSTED, container_on_host, flag, gate, project  # noqa: F401  (fixture)

IMAGE = "asent-satra-project:test"

# Writes a junit file in which every trusted test passed, then exits 0 before pytest can say otherwise.
FORGE = '''import os, sys
_path = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--junitxml=")), "results.xml")
with open(_path, "w") as _out:
    _out.write('<testsuites><testsuite name="pytest" tests="2">'
               '<testcase classname="asent_assurance.test_contract" name="test_owner_allowed"/>'
               '<testcase classname="asent_assurance.test_contract" name="test_other_user_denied"/>'
               '</testsuite></testsuites>')
os._exit(0)
'''
CONFTEST_FORCE_PASS = '''import pytest


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    report = yield
    report.outcome = "passed"
    report.longrepr = None
    return report
'''
# Runs only the test that a broken access check still passes.
SELECT = 'addopts = -k test_owner_allowed\npython_functions = test_owner*\n'
USER_SITE = ".local/lib/python%d.%d/site-packages/" % sys.version_info[:2]

ATTACKS = {
    "pytest.py": {"pytest.py": FORGE},
    "pytest/ package": {"pytest/__init__.py": FORGE, "pytest/__main__.py": ""},
    "_pytest/ package": {"_pytest/__init__.py": FORGE},
    "root conftest.py forcing passes": {"conftest.py": CONFTEST_FORCE_PASS},
    "pyproject.toml addopts": {"pyproject.toml": '[tool.pytest.ini_options]\naddopts = "-k test_owner_allowed"\npython_functions = "test_owner*"\n'},
    "pytest.ini": {"pytest.ini": "[pytest]\n" + SELECT},
    "tox.ini": {"tox.ini": "[pytest]\n" + SELECT},
    "setup.cfg": {"setup.cfg": "[tool:pytest]\n" + SELECT},
    "sitecustomize.py": {"sitecustomize.py": FORGE},
    "usercustomize.py": {"usercustomize.py": FORGE, USER_SITE + "usercustomize.py": FORGE},
    ".pth file": {"forge.pth": "import _asent_forge\n", "_asent_forge.py": FORGE,
                  USER_SITE + "forge.pth": "import _asent_forge\n", USER_SITE + "_asent_forge.py": FORGE},
}
# Vectors that force a pass on the unguarded run (the controls below prove each one).
WORKED_BEFORE = ["pytest.py", "pytest/ package", "_pytest/ package", "root conftest.py forcing passes",
                 "pyproject.toml addopts", "pytest.ini", "tox.ini", "setup.cfg"]


def statuses(result):
    return {t["name"]: t["status"] for t in result["tests"]}


def trusted_run(tmp_path, head_extra=None, security=BROKEN, base_kwargs=None, head_kwargs=None, pytest_ini=True):
    base = project(tmp_path / "base", **(base_kwargs or {}))
    head_kwargs = dict(head_kwargs or {})
    head = project(tmp_path / "head", security=security, extra={**head_kwargs.pop("extra", {}), **(head_extra or {})}, **head_kwargs)
    ini = base / ".asent/satra/pytest.ini" if pytest_ini else None
    return pytest_runner.run_pytest(head, tmp_path / "out", "all", True, trusted_tests_dir=base / ".asent/satra/trusted_tests",
                                    external=True, pytest_ini=ini, image=IMAGE)


def unguarded(tmp_path, head_extra):
    """The pre-change layout without its flags: trusted tests copied into the head, `python -m pytest` there."""
    head = copy_tree(project(tmp_path / "plain", security=BROKEN, extra=head_extra), tmp_path / "plain-work")
    copy_tree(tmp_path / "plain/.asent/satra/trusted_tests", head / "asent_assurance")
    env = {"PATH": "/usr/bin:/bin", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "HOME": str(head)}
    done = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--junitxml=results.xml", "asent_assurance"],
                          cwd=head, env=env, capture_output=True, text=True, timeout=60)
    cases = ET.parse(head / "results.xml").getroot().iter("testcase")
    failing = [c.get("name") for c in cases if c.find("failure") is not None or c.find("error") is not None]
    return done.returncode, failing


# --- the trusted run's command and layout -----------------------------------------------------------------

def test_trusted_run_mounts_base_tests_read_only_outside_the_head(tmp_path, container_on_host):
    """Trusted tests and base pytest.ini are mounted read-only at /trusted; pytest runs with python -P from there."""
    result = trusted_run(tmp_path, security="def can_access(user, owner):\n    return user == owner\n")
    assert result["exit_code"] == 0 and statuses(result) == {"test_owner_allowed": "PASS", "test_other_user_denied": "PASS"}
    [run] = container_on_host.runs
    cmd, mounts = run["cmd"], run["mounts"]
    at = cmd.index(IMAGE)
    assert cmd[at + 1:at + 6] == ["python", "-P", "-s", "-m", "pytest"]
    inner = cmd[at + 6:]
    assert flag(inner, "-c") == "/trusted/pytest.ini"
    assert "--rootdir=/trusted" in inner and "--confcutdir=/trusted" in inner
    assert ("-p", "no:cacheprovider") in set(zip(inner, inner[1:]))
    assert "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1" in [value for name, value in zip(cmd, cmd[1:]) if name == "-e"]
    assert [part for part in inner if part.startswith("/trusted/")] == ["/trusted/pytest.ini", "/trusted/asent_assurance"]
    assert inner[-1] == "/trusted/asent_assurance" and not any(part.startswith("/work") for part in inner)
    assert mounts["/trusted"][1] == "ro" and mounts["/work"][1] == "rw"
    trusted, work = Path(mounts["/trusted"][0]), Path(mounts["/work"][0])
    assert work not in trusted.parents and trusted not in work.parents and trusted != work
    assert sorted(run["before"]["/trusted"]) == ["asent_assurance/test_contract.py", "pytest.ini"]
    assert run["before"]["/trusted"]["asent_assurance/test_contract.py"] == TRUSTED.encode()


def test_trusted_pytest_ini_is_the_base_file(tmp_path, container_on_host):
    """The /trusted/pytest.ini is a byte copy of the base .asent/ ini; the head's ini is not used."""
    trusted_run(tmp_path, head_kwargs={"extra": {".asent/satra/pytest.ini": "[pytest]\naddopts = -k owner\n"}})
    assert container_on_host.runs[0]["before"]["/trusted"]["pytest.ini"] == (tmp_path / "base/.asent/satra/pytest.ini").read_bytes()


def test_without_a_base_ini_the_trusted_run_uses_an_empty_one(tmp_path, container_on_host):
    """No pytest_ini configured: /trusted/pytest.ini is an empty [pytest] section and the tests still run."""
    result = trusted_run(tmp_path, security="def can_access(user, owner):\n    return user == owner\n", pytest_ini=False)
    assert result["exit_code"] == 0 and result["passed"] == 2
    assert container_on_host.runs[0]["before"]["/trusted"]["pytest.ini"] == b"[pytest]\n"


SYS_PATH_PROBE = '''import os
import sys

import pytest


def test_head_is_importable_only_after_everything_else():
    head = os.environ["ASENT_SATRA_HEAD"]
    inside = [i for i, p in enumerate(sys.path) if p == head or p.startswith(head + os.sep)]
    assert inside == list(range(len(sys.path) - len(inside), len(sys.path))) and inside
    assert not pytest.__file__.startswith(head)
    import app.security
    assert app.security.__file__.startswith(head)
'''


def test_head_is_on_sys_path_only_after_the_standard_library_and_site_packages(tmp_path, container_on_host):
    """Head paths come last on sys.path, so a head module can never shadow pytest, the stdlib or an installed package."""
    result = trusted_run(tmp_path, base_kwargs={"trusted": SYS_PATH_PROBE})
    assert result["exit_code"] == 0, result["stdout"]
    assert statuses(result) == {"test_head_is_importable_only_after_everything_else": "PASS"}


def test_base_ini_pythonpath_entries_point_into_the_head(tmp_path, container_on_host):
    """`pythonpath = src` in the base ini makes the head's src/ importable (appended, after the head root's own entry order)."""
    probe = ("import app.security\n\n\ndef test_src_layout():\n    assert app.security.__file__.endswith('src/app/security.py')\n"
             "    assert not app.security.can_access('a', 'b')\n")
    src = {"src/app/__init__.py": "", "src/app/security.py": "def can_access(user, owner):\n    return user == owner\n"}
    result = trusted_run(tmp_path, head_extra=src, base_kwargs={"trusted": probe, "extra": {".asent/satra/pytest.ini": "[pytest]\npythonpath = src\n"}})
    assert result["exit_code"] == 0, result["stdout"]
    assert statuses(result) == {"test_src_layout": "PASS"}


# --- attacks ----------------------------------------------------------------------------------------------

def test_broken_head_without_any_attack_fails_the_trusted_test(tmp_path, container_on_host):
    """Reference result for the attack tests: a broken access check fails test_other_user_denied."""
    result = trusted_run(tmp_path)
    assert result["exit_code"] == 1 and statuses(result) == {"test_owner_allowed": "PASS", "test_other_user_denied": "FAIL"}


@pytest.mark.parametrize("attack", list(ATTACKS))
def test_head_harness_files_do_not_change_the_trusted_result(tmp_path, container_on_host, attack):
    """A head pytest.py, pytest/ or _pytest/ package, conftest, pytest settings or site hook cannot turn the failing test into a pass."""
    result = trusted_run(tmp_path, ATTACKS[attack])
    assert result["available"] and result["exit_code"] == 1, (attack, result.get("reason"), result.get("stdout"))
    assert statuses(result) == {"test_owner_allowed": "PASS", "test_other_user_denied": "FAIL"}, attack


@pytest.mark.parametrize("attack", WORKED_BEFORE)
def test_control_the_same_files_force_a_pass_on_an_unguarded_run(tmp_path, attack):
    """Control: on the unguarded layout the same attack files do hide the failure (exit 0, nothing failing)."""
    assert unguarded(tmp_path, None) == (1, ["test_other_user_denied"])
    assert unguarded(tmp_path / "attacked", ATTACKS[attack]) == (0, [])


# --- the results file (step 2) ----------------------------------------------------------------------------

PASSING_JUNIT = ('<testsuites><testsuite name="pytest" tests="2">'
                 '<testcase classname="asent_assurance.test_contract" name="test_owner_allowed"/>'
                 '<testcase classname="asent_assurance.test_contract" name="test_other_user_denied"/>'
                 '</testsuite></testsuites>')


def results_mount(run):
    return run["mounts"]["/results"]


@pytest.mark.parametrize("kind", ["trusted", "head tests"])
def test_results_file_is_written_to_a_fresh_tmpfs_directory_outside_the_head(tmp_path, container_on_host, kind):
    """--junitxml points at /results, an empty directory that is not inside /work (on /dev/shm where it exists) and is removed afterwards."""
    if kind == "trusted":
        result = trusted_run(tmp_path, security=SECURE)
    else:
        head = project(tmp_path / "head", project_tests={"tests/test_app.py": "def test_app():\n    assert True\n"})
        result = pytest_runner.run_pytest(head, tmp_path / "out", external=True, targets=["tests"], image=IMAGE)
    assert result["available"] and result["exit_code"] == 0
    [run] = container_on_host.runs
    assert "--junitxml=/results/results.xml" in run["cmd"] and not any("--junitxml=/work" in part for part in run["cmd"])
    source, mode = results_mount(run)
    assert mode == "rw" and run["before"]["/results"] == {}
    work = Path(run["mounts"]["/work"][0])
    assert work not in Path(source).parents and Path(source) not in work.parents
    if Path("/dev/shm").is_dir() and os.access("/dev/shm", os.W_OK):
        assert Path(source).parent == Path("/dev/shm") and result["results_location"] == "tmpfs (/dev/shm)"
    assert not Path(source).exists()


def test_results_files_in_the_head_are_deleted_before_the_run(tmp_path, container_on_host):
    """Every results.xml the head carries is removed from the copy before pytest starts; the real result stands."""
    forged = {"results.xml": PASSING_JUNIT, "app/results.xml": PASSING_JUNIT}
    result = trusted_run(tmp_path, forged)
    assert result["exit_code"] == 1 and statuses(result)["test_other_user_denied"] == "FAIL"
    assert result["removed_results_files"] == ["app/results.xml", "results.xml"]
    assert not [name for name in container_on_host.runs[0]["before"]["/work"] if name.endswith("results.xml")]
    assert (tmp_path / "head/results.xml").read_text() == PASSING_JUNIT  # only the copy is cleaned


# Code under test that overwrites ./results.xml (the old results path) when the process exits.
WRITE_WORK_RESULTS = BROKEN + '''
import atexit, os

def _forge():
    with open(os.path.join(os.getcwd(), "results.xml"), "w") as out:
        out.write(%r)
atexit.register(_forge)
''' % PASSING_JUNIT


def test_head_code_writing_results_xml_in_the_head_does_not_change_the_result(tmp_path, container_on_host):
    """Head code that writes /work/results.xml at exit no longer reaches the file SATRA reads."""
    result = trusted_run(tmp_path, security=WRITE_WORK_RESULTS)
    assert result["available"] and result["exit_code"] == 1
    assert statuses(result) == {"test_owner_allowed": "PASS", "test_other_user_denied": "FAIL"}


def test_head_code_that_exits_before_pytest_writes_results_is_unavailable(tmp_path, container_on_host):
    """Exit 0 without a results file (head calls os._exit(0) on import) is unavailable, not a pass."""
    result = trusted_run(tmp_path, security=BROKEN + "import os\nos._exit(0)\n")
    assert result["available"] is False and result["exit_code"] is None and result["pytest_exit_code"] == 0
    assert result["reason"] == "results file missing"


def test_forged_exit_code_with_the_real_results_file_is_unavailable(tmp_path, container_on_host):
    """Head code that forces exit 0 after a failing run leaves a results file that contradicts it: unavailable."""
    code = BROKEN + "import atexit, os\natexit.register(lambda: os._exit(0))\n"
    result = trusted_run(tmp_path, security=code)
    assert result["available"] is False and "does not match" in result["reason"]


def test_missing_results_file_makes_a_gate_run_inconclusive(tmp_path, container_on_host):
    """A gate run whose head trusted run has no results file is INCONCLUSIVE, never ACCEPT."""
    status, details, _ = gate(tmp_path, head_kwargs={"security": SECURE + "import os\nos._exit(0)\n"})
    assert status == "INCONCLUSIVE" and details["reason"] == "Candidate test execution is incomplete"


def junit(tmp_path, text):
    path = tmp_path / "results.xml"
    path.write_text(text)
    return path


ONE_PASS = '<testsuites><testsuite><testcase classname="c" name="t"/></testsuite></testsuites>'
ONE_FAIL = '<testsuites><testsuite><testcase classname="c" name="t"><failure message="x">x</failure></testcase></testsuite></testsuites>'


@pytest.mark.parametrize("text, code, words", [
    ("not xml at all", 0, "not valid XML"),
    ("<html><body/></html>", 0, "not a JUnit report"),
    (ONE_FAIL, 0, "does not match pytest exit code 0"),
    ("<testsuite/>", 0, "does not match pytest exit code 0"),
    (ONE_PASS, 1, "does not match pytest exit code 1"),
])
def test_invalid_results_files_are_refused(tmp_path, text, code, words):
    """Unparseable, non-JUnit, or exit-code-contradicting results files are refused."""
    tests, problem = pytest_runner.read_results(junit(tmp_path, text), code)
    assert tests is None and words in problem


def test_results_file_that_is_not_a_regular_file_is_refused(tmp_path):
    """A symlink (it could point at any host file) or a directory is refused, and a symlink is not followed."""
    target = junit(tmp_path, ONE_PASS)
    (tmp_path / "link").mkdir()
    (tmp_path / "link/results.xml").symlink_to(target)
    (tmp_path / "dir/results.xml").mkdir(parents=True)
    assert pytest_runner.read_results(tmp_path / "link/results.xml", 0)[0] is None
    assert pytest_runner.read_results(tmp_path / "dir/results.xml", 0)[0] is None
    assert pytest_runner.read_results(tmp_path / "none.xml", 0) == (None, "results file missing")


def test_oversized_results_file_is_refused(tmp_path, monkeypatch):
    """A results file over the size limit is refused without being parsed."""
    monkeypatch.setattr(pytest_runner, "RESULTS_LIMIT", 10)
    assert pytest_runner.read_results(junit(tmp_path, ONE_PASS), 0) == (None, "results file too large")


@pytest.mark.parametrize("text, code", [(ONE_PASS, 0), (ONE_FAIL, 1), ("<testsuites/>", 5)])
def test_consistent_results_files_are_read(tmp_path, text, code):
    """Pass with exit 0, failure with exit 1, and an empty report with exit 5 (no tests) are accepted as evidence."""
    tests, problem = pytest_runner.read_results(junit(tmp_path, text), code)
    assert problem is None and len(tests) == (0 if code == 5 else 1)


def test_host_builtin_run_writes_results_outside_the_workspace(tmp_path, monkeypatch):
    """The hash-pinned host path (no engine) also writes its results file outside the project copy."""
    seen = []
    monkeypatch.setattr(pytest_runner, "availability", lambda: {"docker": {"available": False}, "podman": {"available": False}})
    monkeypatch.setattr(pytest_runner, "permitted_builtin", lambda root: True)
    monkeypatch.setattr(pytest_runner.subprocess, "run", lambda cmd, *a, **k: seen.append(cmd) or subprocess.CompletedProcess(cmd, 4, "", ""))
    (tmp_path / "p").mkdir()
    result = pytest_runner.run_pytest(tmp_path / "p", tmp_path / "out")
    [cmd] = seen
    work = Path(cmd[cmd.index(str(pytest_runner.ROOT / "backend/satra/runner_entry.py")) + 1])
    junit_path = Path(next(part.split("=", 1)[1] for part in cmd if part.startswith("--junitxml=")))
    assert work not in junit_path.parents and result["available"] is False


@pytest.mark.xfail(strict=True, reason="Known limit (docs/satra/threat-model.md): code under test runs in the trusted "
                                       "pytest process and can still write a consistent forged results file and exit 0.")
def test_known_limit_in_process_code_under_test_can_still_forge_results(tmp_path, container_on_host):
    """Stated limit, kept as a strict xfail: it fails today; if it ever passes, the documentation must change."""
    forger = BROKEN + '''
import atexit, os, sys
_path = next(a.split("=", 1)[1] for a in sys.argv if a.startswith("--junitxml="))

def _forge():
    with open(_path, "w") as out:
        out.write(%r)
    os._exit(0)
atexit.register(_forge)
''' % PASSING_JUNIT
    result = trusted_run(tmp_path, security=forger)
    assert not (result["available"] and result["exit_code"] == 0 and result["failed"] == 0)


# --- the stated limit is documented (step 4) --------------------------------------------------------------

DOCS = Path(__file__).resolve().parents[1] / "docs"


def test_threat_model_states_that_in_process_forgery_is_not_solved():
    """The threat model, the gate guide and these notes state the in-process limit and name its strict xfail."""
    model = (DOCS / "satra/threat-model.md").read_text()
    assert "Code under test runs in the same process as the trusted tests" in model
    assert "does not hold against a head that attacks the test process itself" in model
    assert "test_known_limit_in_process_code_under_test_can_still_forge_results" in model
    assert "attacks the test process" in (DOCS / "asent-gate.md").read_text()
    assert "Stated limit" in (DOCS / "satra/harness-isolation.md").read_text()
    marker = test_known_limit_in_process_code_under_test_can_still_forge_results.pytestmark[0]
    assert marker.name == "xfail" and marker.kwargs["strict"] is True
