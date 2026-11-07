"""Step 6 of docs/dev-env-plan.md: SATRA in gate runs is driven by the base `.asent/` config.

Contract, trusted tests and counterfactual target come from the frozen base config; the candidate's
SRS.md cannot switch SATRA off. Real gate runs on small real projects; real pytest runs.

Docker/Podman is not installed on this machine, and a gate run never runs external code on the host.
To exercise the container path anyway, `container_on_host` reports Docker as available and executes
the exact pytest command that `run_pytest` builds for the container, with `/work` mapped to the
temporary copy. Only the isolation is replaced; the arguments, files and verdict logic are real.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from backend.orchestrator.context_service import ContextService
from backend.orchestrator.service import Service
from backend.satra import analyzer as satra_analyzer
from backend.satra import pytest_runner
from backend.satra.counterfactuals import mutate_return_true

SECURE = "def can_access(user, owner):\n    return user == owner\n"
BROKEN = "def can_access(user, owner):\n    return True\n"
TRUSTED = ("from app.security import can_access\n\n\ndef test_owner_allowed():\n    assert can_access('a', 'a')\n\n\n"
           "def test_other_user_denied():\n    assert not can_access('a', 'b')\n")
# Project security tests must pass SATRA's preflight (only `pytest` may be imported), so they get the
# function under test from a conftest fixture, the way InvoiceHub's tests get their client.
PROJECT_CONFTEST = "import pytest\nfrom app.security import can_access as real\n\n\n@pytest.fixture\ndef can_access():\n    return real\n"
WEAK_PROJECT_TEST = "def test_security(can_access):\n    assert can_access('a', 'a')\n"
STRONG_PROJECT_TEST = "def test_security(can_access):\n    assert not can_access('a', 'b')\n"
CONTRACT = {"rule_id": "AUTHZ.IDOR.001", "route": "GET /items/{id}", "expected_status": 403, "authority_sources": ["README#access"],
            "scope": ["app/security.py"], "counterfactual": {"operator": "RETURN_TRUE", "target": "app/security.py::can_access"}}


@pytest.fixture
def container_on_host(monkeypatch):
    real_run = subprocess.run

    def run(cmd, *args, **kwargs):
        if isinstance(cmd, list) and cmd and cmd[0] == "docker" and "asent-sandbox:local" in cmd:
            host = next(v.split(":/work")[0] for v in cmd if isinstance(v, str) and v.endswith(":/work:rw"))
            inner = cmd[cmd.index("asent-sandbox:local") + 1:]
            assert inner[:3] == ["python", "-m", "pytest"] and "--network" in cmd and "none" in cmd
            inner = [part.replace("/work", host) for part in inner]
            kwargs["cwd"] = host
            return real_run([sys.executable, *inner[1:]], *args, **kwargs)
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(pytest_runner, "availability", lambda: {"docker": {"available": True}, "podman": {"available": False}})
    monkeypatch.setattr(pytest_runner.subprocess, "run", run)


def project(root: Path, security=SECURE, trusted=TRUSTED, satra=None, extra=None, project_tests=None):
    files = {"app/__init__.py": "", "app/security.py": security, "app/main.py": "from app.security import can_access\n",
             "SRS.md": "unrelated text without any security words\n",
             ".asent/config.json": json.dumps({"schema_version": 1, "project": {"name": "t"}, "modules": {
                 "SATRA": {"enabled": True, "pytest_ini": "satra/pytest.ini", "source_dirs": ["app"], **(satra or {})},
                 "CAVR": {"enabled": False, "reason": "not in this test"}, "SABLE": {"enabled": False, "reason": "not in this test"}}}),
             ".asent/satra/contract.json": json.dumps(CONTRACT),
             ".asent/satra/pytest.ini": "[pytest]\npythonpath = .\n",
             ".asent/satra/trusted_tests/test_contract.py": trusted}
    files.update(project_tests or {})
    files.update(extra or {})
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def gate(tmp_path, base_kwargs=None, head_kwargs=None):
    base = project(tmp_path / "base", **(base_kwargs or {}))
    head = project(tmp_path / "head", **(head_kwargs or base_kwargs or {}))
    service = Service(tmp_path / "runtime")
    run = service.create_gate_run(base, head, {})
    context = ContextService(run.candidate_workspace, run.baseline_workspace, service.threats.snapshot(), gate=True)
    status, details, uncertainty = satra_analyzer.analyze(context, tmp_path / "out", lambda *a: None)
    return status, details, uncertainty


def test_secure_change_is_accepted_and_the_mutant_is_killed(tmp_path, container_on_host):
    status, details, uncertainty = gate(tmp_path)
    assert status == "ACCEPT", details["reason"]
    assert details["mode"] == "configured" and details["contract"]["rule_id"] == "AUTHZ.IDOR.001"
    assert details["oracle"]["valid_counterfactual"] is True
    assert details["executions"]["trusted_counterfactual"]["failed"] >= 1
    assert any("project security test" in item for item in uncertainty)


def test_regressed_head_is_rejected(tmp_path, container_on_host):
    status, details, _ = gate(tmp_path, head_kwargs={"security": BROKEN})
    assert status == "REJECT" and details["findings"][0]["diagnosis"] == "APPLICATION_REGRESSION"


def test_weak_project_security_test_is_rejected(tmp_path, container_on_host):
    kwargs = {"satra": {"project_security_tests": "tests/test_security.py"},
              "project_tests": {"tests/conftest.py": PROJECT_CONFTEST, "tests/test_security.py": WEAK_PROJECT_TEST}}
    status, details, _ = gate(tmp_path, kwargs)
    assert status == "REJECT" and details["oracle"]["accepted"] is False


def test_strong_project_security_test_is_accepted(tmp_path, container_on_host):
    kwargs = {"satra": {"project_security_tests": "tests/test_security.py"},
              "project_tests": {"tests/conftest.py": PROJECT_CONFTEST, "tests/test_security.py": STRONG_PROJECT_TEST}}
    status, details, _ = gate(tmp_path, kwargs)
    assert status == "ACCEPT", details["reason"]
    assert details["oracle"]["accepted"] is True


def test_failing_ordinary_project_tests_are_rejected(tmp_path, container_on_host):
    kwargs = {"project_tests": {"tests/test_app.py": "def test_app():\n    assert False\n"}}
    status, details, _ = gate(tmp_path, kwargs)
    assert status == "REJECT" and "Ordinary project tests" in details["reason"]


def test_without_a_container_engine_it_is_inconclusive(tmp_path, monkeypatch):
    monkeypatch.setattr(pytest_runner, "availability", lambda: {"docker": {"available": False}, "podman": {"available": False}})
    monkeypatch.setattr(pytest_runner, "permitted_builtin", lambda root: True)  # even a "known" tree must not run on the host
    status, details, _ = gate(tmp_path)
    assert status == "INCONCLUSIVE" and "Docker/Podman" in details["reason"]


def test_missing_counterfactual_target_is_inconclusive(tmp_path, container_on_host):
    missing = {**CONTRACT, "counterfactual": {"operator": "RETURN_TRUE", "target": "app/security.py::not_there"}}
    status, details, _ = gate(tmp_path, {"extra": {".asent/satra/contract.json": json.dumps(missing)}})
    assert status == "INCONCLUSIVE" and "counterfactual target" in details["reason"]


def test_trusted_tests_that_miss_the_mutant_are_inconclusive(tmp_path, container_on_host):
    blind = "from app.security import can_access\n\n\ndef test_owner_allowed():\n    assert can_access('a', 'a')\n"
    status, details, _ = gate(tmp_path, {"trusted": blind})
    assert status == "INCONCLUSIVE" and "do not detect" in details["reason"]


def test_disabled_contract_rule_is_inconclusive(tmp_path, container_on_host):
    base = project(tmp_path / "base")
    service = Service(tmp_path / "runtime")
    service.change_threats(record_id="AUTHZ.IDOR.001", enabled=False)
    run = service.create_gate_run(base, base, {})
    context = ContextService(run.candidate_workspace, run.baseline_workspace, service.threats.snapshot(), gate=True)
    status, details, _ = satra_analyzer.analyze(context, tmp_path / "out", lambda *a: None)
    assert status == "INCONCLUSIVE" and details["missing_rules"] == ["AUTHZ.IDOR.001"]


def test_trusted_tests_come_from_base_even_when_head_edits_them(tmp_path, container_on_host):
    lenient = "def test_nothing():\n    assert True\n"
    status, details, _ = gate(tmp_path, head_kwargs={"security": BROKEN, "trusted": lenient})
    assert status == "REJECT"


def test_candidate_srs_cannot_switch_satra_off_in_a_gate_run(tmp_path, container_on_host):
    # The SRS here has no security wording at all; the legacy path would return INCONCLUSIVE.
    assert gate(tmp_path, head_kwargs={"security": BROKEN})[0] == "REJECT"


def test_external_code_never_runs_on_the_host(tmp_path, monkeypatch):
    monkeypatch.setattr(pytest_runner, "availability", lambda: {"docker": {"available": False}, "podman": {"available": False}})
    monkeypatch.setattr(pytest_runner, "permitted_builtin", lambda root: True)
    (tmp_path / "p").mkdir()
    result = pytest_runner.run_pytest(tmp_path / "p", tmp_path / "o", external=True)
    assert result["available"] is False and "Docker/Podman" in result["reason"]


# --- mutate_return_true ---------------------------------------------------------------------------------

def test_mutate_top_level_function_and_method(tmp_path):
    (tmp_path / "m.py").write_text("def f(x):\n    return x > 1\n\nclass C:\n    def f(self):\n        return False\n")
    assert mutate_return_true(tmp_path, "m.py::f")
    namespace = {}
    exec((tmp_path / "m.py").read_text(), namespace)
    assert namespace["f"](0) is True and namespace["C"]().f() is True


@pytest.mark.parametrize("files,target", [({}, "m.py::f"), ({"m.py": "def g():\n    return 1\n"}, "m.py::f"),
                                          ({"m.py": "def f(:\n"}, "m.py::f")])
def test_mutate_fails_closed(tmp_path, files, target):
    for name, text in files.items():
        (tmp_path / name).write_text(text)
    before = {name: (tmp_path / name).read_text() for name in files}
    assert mutate_return_true(tmp_path, target) is False
    assert {name: (tmp_path / name).read_text() for name in files} == before
