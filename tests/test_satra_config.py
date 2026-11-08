"""Step 6 of docs/dev-env-plan.md: SATRA in gate runs is driven by the base `.asent/` config.

Contract, trusted tests and counterfactual target come from the frozen base config; the candidate's
SRS.md cannot switch SATRA off. Real gate runs on small real projects; real pytest runs.

Docker/Podman is not installed on this machine, and a gate run never runs external code on the host.
To exercise the container path anyway, `container_on_host` reports Docker as available and executes
the exact pytest command that `run_pytest` builds for the container, with `/work` mapped to the
temporary copy. Only the isolation is replaced; the arguments, files and verdict logic are real.
The per-project gate image is prepared by the real `project_image.prepare` against `FakeEngine`.
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.orchestrator.context_service import ContextService
from backend.orchestrator.service import Service
from backend.satra import analyzer as satra_analyzer
from backend.satra import project_image, pytest_runner
from backend.satra.counterfactuals import mutate_return_true
from test_satra_project_image import FakeEngine

SECURE = "def can_access(user, owner):\n    return user == owner\n"
BROKEN = "def can_access(user, owner):\n    return True\n"
TRUSTED = ("from app.security import can_access\n\n\ndef test_owner_allowed():\n    assert can_access('a', 'a')\n\n\n"
           "def test_other_user_denied():\n    assert not can_access('a', 'b')\n")
# Project security tests must pass SATRA's preflight (only `pytest` may be imported), so they get the
# function under test from a conftest fixture, the way InvoiceHub's tests get their client.
PROJECT_CONFTEST = "import pytest\nfrom app.security import can_access as real\n\n\n@pytest.fixture\ndef can_access():\n    return real\n"
WEAK_PROJECT_TEST = "def test_security(can_access):\n    assert can_access('a', 'a')\n"
STRONG_PROJECT_TEST = "def test_security(can_access):\n    assert not can_access('a', 'b')\n"
# A project with no third-party dependencies: an empty requirements file, an empty lockfile and a
# CAVR policy that approves nothing. The gate image is then the SATRA runner (pytest) only.
CAVR_POLICY = {"project_task_description": "access check service", "allowed_scopes": ["NETWORK_CONNECT:none"],
               "approved_requirements": [], "denied_packages": []}
NO_DEPENDENCIES = {"requirements.txt": "", "dependencies.lock.json": json.dumps({"packages": []}),
                   ".asent/cavr/policy.json": json.dumps(CAVR_POLICY)}
CONTRACT = {"rule_id": "AUTHZ.IDOR.001", "route": "GET /items/{id}", "expected_status": 403, "authority_sources": ["README#access"],
            "scope": ["app/security.py"], "counterfactual": {"operator": "RETURN_TRUE", "target": "app/security.py::can_access"}}


def mounts_of(cmd):
    """`-v src:dst[:mode]` flags of a container command -> {dst: (src, mode)}."""
    found = {}
    for flag_, value in zip(cmd, cmd[1:]):
        if flag_ == "-v":
            src, dst, mode = value.rsplit(":", 2)
            found[dst] = (src, mode)
    return found


@pytest.fixture
def container_on_host(monkeypatch):
    """Docker reported available; each `docker run <gate image> python -m pytest` runs on the host.

    The gate image comes from `project_image.prepare` with `FakeEngine` standing in for the engine's
    inspect/probe/build calls, so the install plan and CAVR approval are real. Only commands that run
    pytest in an `asent-satra-project:` image are executed (on the host); any other `docker` command,
    including one for `asent-sandbox:local`, goes to the real engine, which is not installed here, and
    so cannot pass. Each `-v` mount's container path is replaced by its host directory in the
    arguments, the `-e` values and the `-w` directory; the environment is only the `-e` values plus
    PATH, as in the container. Read-only mounts are recorded but not enforced on the host.
    Returns the recorded runs (command, timeout, mounts, each mount's files and bytes before the run) and
    the fake engine.
    """
    real_run = subprocess.run
    runs = []

    def run(cmd, *args, **kwargs):
        if isinstance(cmd, list) and cmd and cmd[0] == "docker":
            at = next((i for i, part in enumerate(cmd) if isinstance(part, str) and part.startswith(project_image.PROJECT_REPOSITORY + ":")), None)
            inner = cmd[at + 1:] if at is not None else []
            if inner[:3] == ["python", "-m", "pytest"] or inner[:5] == ["python", "-P", "-s", "-m", "pytest"]:
                mounts = mounts_of(cmd[:at])
                contents = {dst: {p.relative_to(src).as_posix(): p.read_bytes() for p in Path(src).rglob("*") if p.is_file()}
                            for dst, (src, _) in mounts.items()}
                runs.append({"cmd": list(cmd), "timeout": kwargs.get("timeout"), "mounts": mounts, "before": contents})
                assert "--network" in cmd and "none" in cmd

                pattern = re.compile("(?<![^=:])(%s)(?=/|$)" % "|".join(map(re.escape, mounts)))

                def host(text):
                    # One pass: a container path at the start or after '=' / ':' -> its host directory.
                    return pattern.sub(lambda m: mounts[m.group(1)][0], text)
                # The container's environment is only what `-e` passes; nothing else reaches it.
                env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
                env.update(host(value).split("=", 1) for flag_, value in zip(cmd[:at], cmd[1:at + 1]) if flag_ == "-e")
                kwargs["env"] = env
                kwargs["cwd"] = host(cmd[cmd.index("-w") + 1])
                return real_run([sys.executable, *[host(part) for part in inner[1:]]], *args, **kwargs)
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(pytest_runner, "availability", lambda: {"docker": {"available": True}, "podman": {"available": False}})
    monkeypatch.setattr(pytest_runner.subprocess, "run", run)
    engine = FakeEngine()
    monkeypatch.setattr(project_image, "_run", engine)
    return SimpleNamespace(runs=runs, engine=engine)


def project(root: Path, security=SECURE, trusted=TRUSTED, satra=None, extra=None, project_tests=None, deps=None):
    files = {**(NO_DEPENDENCIES if deps is None else deps),"app/__init__.py": "", "app/security.py": security, "app/main.py": "from app.security import can_access\n",
             "SRS.md": "unrelated text without any security words\n",
             ".asent/config.json": json.dumps({"schema_version": 1, "project": {"name": "t"}, "modules": {
                 "SATRA": {"enabled": True, "pytest_ini": "satra/pytest.ini", "source_dirs": ["app"], **(satra or {})},
                 "CAVR": {"enabled": True}, "SABLE": {"enabled": False, "reason": "not in this test"}}}),
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


# --- per-project gate image (docs/satra/per-project-sandbox.md, step 4) ---------------------------

ISOLATION = [("--network", "none"), ("--read-only", None), ("--cap-drop", "ALL"), ("--security-opt", "no-new-privileges"),
             ("--cpus", "1"), ("--pids-limit", "64"), ("--tmpfs", "/tmp:rw,nosuid,size=64m")]


def flag(cmd, name):
    return cmd[cmd.index(name) + 1] if name in cmd else None


def test_every_gate_test_run_uses_the_project_image_with_full_isolation(tmp_path, container_on_host):
    status, details, _ = gate(tmp_path)
    assert status == "ACCEPT", details["reason"]
    image = details["sandbox_image"]["image"]
    assert image.startswith("asent-satra-project:") and details["sandbox_image"]["packages"] == []
    assert len(container_on_host.runs) == len(details["executions"]) >= 3
    for run in container_on_host.runs:
        cmd = run["cmd"]
        assert "asent-sandbox:local" not in cmd and image in cmd
        for name, value in ISOLATION:
            assert name in cmd and (value is None or flag(cmd, name) == value), (name, cmd)
        assert flag(cmd, "--memory") == "512m" and run["timeout"] == 40


@pytest.mark.parametrize("deps, words", [
    ({"requirements.txt": "", ".asent/cavr/policy.json": json.dumps(CAVR_POLICY)}, "no dependencies.lock.json"),
    ({**NO_DEPENDENCIES, "requirements.txt": "six==1.17.0\n"}, "six"),
])
def test_without_an_approved_lockfile_there_is_no_fallback_image(tmp_path, container_on_host, deps, words):
    status, details, _ = gate(tmp_path, {"deps": deps})
    assert status == "INCONCLUSIVE" and words in details["reason"]
    assert container_on_host.runs == [] and not container_on_host.engine.builds()


def test_a_failed_image_build_is_inconclusive(tmp_path, container_on_host):
    container_on_host.engine.build_code = 1
    status, details, _ = gate(tmp_path)
    assert status == "INCONCLUSIVE" and "build failed" in details["reason"] and container_on_host.runs == []


def test_cavr_disabled_in_base_means_no_gate_image(tmp_path, container_on_host):
    config = json.loads((project(tmp_path / "probe") / ".asent/config.json").read_text())
    config["modules"]["CAVR"] = {"enabled": False, "reason": "off"}
    status, details, _ = gate(tmp_path, {"extra": {".asent/config.json": json.dumps(config)}})
    assert status == "INCONCLUSIVE" and "CAVR" in details["reason"] and container_on_host.runs == []


def test_head_cannot_add_a_package_to_the_gate_image(tmp_path, container_on_host):
    six = {"name": "six", "version": "1.17.0", "ecosystem": "PyPI", "filename": "six-1.17.0-py2.py3-none-any.whl",
           "sha256": "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274"}
    head_deps = {"requirements.txt": "six==1.17.0\n", "dependencies.lock.json": json.dumps({"packages": [six]}),
                 ".asent/cavr/policy.json": json.dumps({**CAVR_POLICY, "approved_requirements": ["six==1.17.0"]})}
    status, details, _ = gate(tmp_path, head_kwargs={"deps": head_deps})
    assert status == "ACCEPT", details["reason"]
    assert details["sandbox_image"]["packages"] == []
    assert [c["requirements.txt"] for c in container_on_host.engine.contexts] == [""]


def test_raised_limits_from_the_base_config_reach_every_run(tmp_path, container_on_host):
    limits = {".asent/satra/sandbox.json": json.dumps({"timeout_seconds": 120, "memory": "1g"})}
    status, details, _ = gate(tmp_path, {"extra": limits})
    assert status == "ACCEPT", details["reason"]
    assert details["sandbox_limits"] == {"timeout_seconds": 120, "memory": "1g", "source": "base .asent/satra/sandbox.json"}
    assert {(flag(r["cmd"], "--memory"), r["timeout"]) for r in container_on_host.runs} == {("1g", 120)}


def test_limits_raised_only_in_head_are_ignored(tmp_path, container_on_host):
    limits = {".asent/satra/sandbox.json": json.dumps({"timeout_seconds": 180, "memory": "2g"})}
    status, details, _ = gate(tmp_path, head_kwargs={"extra": limits})
    assert status == "ACCEPT" and {(flag(r["cmd"], "--memory"), r["timeout"]) for r in container_on_host.runs} == {("512m", 40)}


@pytest.mark.parametrize("limits", [{"timeout_seconds": 181}, {"memory": "3g"}, {"memory": "2049m"}])
def test_limits_above_the_cap_are_inconclusive(tmp_path, container_on_host, limits):
    status, details, _ = gate(tmp_path, {"extra": {".asent/satra/sandbox.json": json.dumps(limits)}})
    assert status == "INCONCLUSIVE" and "sandbox.json" in details["reason"] and container_on_host.runs == []


def test_demo_path_keeps_the_shared_image_and_default_limits(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(pytest_runner, "availability", lambda: {"docker": {"available": True}, "podman": {"available": False}})
    monkeypatch.setattr(pytest_runner.subprocess, "run", lambda cmd, *a, **k: seen.append((cmd, k.get("timeout"))) or
                        subprocess.CompletedProcess(cmd, 0, "", ""))
    (tmp_path / "p").mkdir()
    pytest_runner.run_pytest(tmp_path / "p", tmp_path / "out")
    [(cmd, timeout)] = seen
    assert "asent-sandbox:local" in cmd and flag(cmd, "--memory") == "512m" and timeout == 40


# --- the real InvoiceHub trusted suite through gate mode (docs/satra/trusted-suite.md) ----------------------

INVOICEHUB = Path(__file__).resolve().parents[1] / "demo_project" / "InvoiceHub"
# asent-target-invoicehub at base 57ae3dc: its .asent/ (+ "trusted_data": ["fixtures"]), lockfile, requirements.
INVOICEHUB_OVERLAY = Path(__file__).resolve().parent / "test_satra_data" / "invoicehub_gate"
INVOICEHUB_PDF_SHA256 = "ad55c63308a20f8591d0575d3b63d75155ad78b4d94eb59da4b5c146caaa73b9"  # demo_project/InvoiceHub/fixtures/invoice.pdf
INVOICEHUB_TRUSTED = 15  # conftest + test_archive (1), test_functional (5), test_security (9)


def invoicehub(root: Path, extra=None, trusted_data=True) -> Path:
    """The target's base: demo app/tests/fixtures (identical at 57ae3dc) + the overlay; `extra` bytes on top."""
    import shutil
    from backend.orchestrator.hashing import copy_tree
    copy_tree(INVOICEHUB, root)  # no .asent/, no __pycache__
    shutil.copytree(INVOICEHUB_OVERLAY, root, dirs_exist_ok=True)
    if not trusted_data:  # the target's config exactly as committed at 57ae3dc
        config = root / ".asent/config.json"
        document = json.loads(config.read_text())
        del document["modules"]["SATRA"]["trusted_data"]
        config.write_text(json.dumps(document, indent=2) + "\n")
    for name, data in (extra or {}).items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(data)
    return root


def invoicehub_gate(tmp_path, head_extra=None, trusted_data=True):
    """Gate mode for a head that only adds .gitignore (the pull request whose gate was INCONCLUSIVE)."""
    base = invoicehub(tmp_path / "base", trusted_data=trusted_data)
    head = invoicehub(tmp_path / "head", {".gitignore": b".asent-report/\n", **(head_extra or {})}, trusted_data=trusted_data)
    service = Service(tmp_path / "runtime")
    run = service.create_gate_run(base, head, {})
    context = ContextService(run.candidate_workspace, run.baseline_workspace, service.threats.snapshot(), gate=True)
    return satra_analyzer.analyze(context, tmp_path / "out", lambda *a: None)


def counts(result):
    return result.get("passed"), result.get("failed"), result.get("errors")


def test_invoicehub_trusted_suite_passes_through_gate_mode_on_the_host_harness(tmp_path, container_on_host):
    """All 15 real trusted tests pass on base and head, read the base invoice.pdf from /trusted, and kill the mutant."""
    status, details, _ = invoicehub_gate(tmp_path)
    executions = details["executions"]
    assert counts(executions["trusted_baseline"]) == (INVOICEHUB_TRUSTED, 0, 0), executions["trusted_baseline"].get("stdout", "")[-3000:]
    assert counts(executions["trusted_candidate"]) == (INVOICEHUB_TRUSTED, 0, 0)
    assert executions["trusted_counterfactual"]["failed"] + executions["trusted_counterfactual"]["errors"] >= 1
    assert status == "ACCEPT", details["reason"]
    assert details["trusted_data"] == {"files": [{"path": "fixtures/invoice.pdf", "bytes": 749, "sha256": INVOICEHUB_PDF_SHA256}],
                                       "file_count": 1, "total_bytes": 749}
    assert len(details["sandbox_image"]["packages"]) == 16
    for run in [r for r in container_on_host.runs if "/trusted" in r["mounts"]]:
        assert "fixtures/invoice.pdf" in run["before"]["/trusted"] and run["mounts"]["/trusted"][1] == "ro"


def test_invoicehub_target_config_without_trusted_data_reproduces_the_ci_failure(tmp_path, container_on_host):
    """The config exactly as committed at 57ae3dc: 0 passed, 1 failed, 14 errors, FileNotFoundError .../fixtures/invoice.pdf."""
    status, details, _ = invoicehub_gate(tmp_path, trusted_data=False)
    baseline = details["executions"]["trusted_baseline"]
    assert status == "INCONCLUSIVE" and "do not pass on the base commit" in details["reason"]
    assert counts(baseline) == (0, 1, 14)
    assert all("FileNotFoundError" in t["message"] and "fixtures/invoice.pdf" in t["message"] for t in baseline["tests"])


def test_invoicehub_head_replacing_the_fixture_does_not_change_the_trusted_runs(tmp_path, container_on_host):
    """A head with a broken invoice.pdf: trusted runs still pass on the base bytes; the project's own tests catch it."""
    status, details, _ = invoicehub_gate(tmp_path, {"fixtures/invoice.pdf": b"not a pdf"})
    executions = details["executions"]
    assert counts(executions["trusted_candidate"]) == (INVOICEHUB_TRUSTED, 0, 0)
    assert executions["ordinary_candidate"]["exit_code"] == 1
    assert status == "REJECT" and details["reason"] == "Ordinary project tests do not provide a clean regression result"
