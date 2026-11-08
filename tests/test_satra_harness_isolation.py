"""Trusted SATRA runs keep the pull request's head out of the test harness (docs/satra/harness-isolation.md).

Each attack below is planted in a head whose access check is broken (`return True`), so the trusted test
`test_other_user_denied` must fail. The attack must not change that result. Where the vector works
against an unguarded run (`python -m pytest` inside the head, with the trusted tests copied into it,
which is what SATRA did before this change), a control test shows that the same files do force a pass
there, so the guarded check is not vacuous.

Runs use `container_on_host` (tests/test_satra_config.py): the exact container command, executed on the
host with each mount's container path mapped to its host directory.
"""
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from backend.orchestrator.hashing import copy_tree
from backend.satra import pytest_runner
from test_satra_config import BROKEN, TRUSTED, container_on_host, flag, project  # noqa: F401  (fixture)

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

