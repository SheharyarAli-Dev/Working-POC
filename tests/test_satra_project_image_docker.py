"""Docker-backed checks of the SATRA runner and per-project gate images.

These skip without Docker locally. In CI (satra-ci.yml) every one of them is listed in the
"ran without skips" step, so a skip there fails the job.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

RUNNER = "asent-satra-runner:local"


@pytest.fixture(scope="module")
def docker():
    if shutil.which("docker") is None:
        pytest.skip("Docker not available")
    return "docker"


def _probe(engine, image, code):
    return subprocess.run([engine, "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                           "--security-opt", "no-new-privileges", image, "python", "-c", code],
                          text=True, capture_output=True, timeout=120)


def test_runner_image_has_only_pytest_and_its_dependencies(docker):
    listing = _probe(docker, RUNNER, "import importlib.metadata as m, json; "
                                     "print(json.dumps(sorted(d.metadata['Name'].lower() for d in m.distributions())))")
    assert listing.returncode == 0, listing.stderr
    assert set(json.loads(listing.stdout)) == {"pip", "pytest", "pluggy", "iniconfig", "packaging", "pygments"}
    for module in ("fastapi", "pydantic", "flask"):
        assert _probe(docker, RUNNER, f"import {module}").returncode != 0, module


# --- per-project gate images (real builds from PyPI; the build is the only step with network) ------

from backend.satra import project_image  # noqa: E402
from test_satra_project_image import NUMPY_CP314_ONLY, base, policy  # noqa: E402

SIX = {"name": "six", "version": "1.17.0", "ecosystem": "PyPI", "filename": "six-1.17.0-py2.py3-none-any.whl",
       "sha256": "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274"}
SIX_SDIST_SHA = "ff70335d468e7eb6ec65b95b99d3a2836546063f63acc5171de367e834932a81"  # real six-1.17.0.tar.gz


def test_gate_image_is_built_from_a_real_lock_entry_and_then_reused(docker, tmp_path, monkeypatch):
    monkeypatch.delenv("ASENT_SATRA_REUSE_IMAGES", raising=False)  # gate default: always build
    root, config = base(tmp_path, requirements="six==1.17.0\n", lock=[SIX], pol=policy(["six==1.17.0"]))
    built = project_image.prepare(root, config, docker)
    assert built["status"] == "READY" and not built["reused"], built["reason"] + built.get("build_log_tail", "")
    imported = _probe(docker, built["image"], "import six; print(six.__version__)")
    assert imported.returncode == 0 and imported.stdout.strip() == "1.17.0", imported.stderr
    assert _probe(docker, built["image"], "import flask").returncode != 0
    monkeypatch.setenv("ASENT_SATRA_REUSE_IMAGES", "1")  # local-development opt-in
    again = project_image.prepare(root, config, docker)
    assert again["reused"] and again["image"] == built["image"]
    monkeypatch.delenv("ASENT_SATRA_REUSE_IMAGES")
    rebuilt = project_image.prepare(root, config, docker)
    assert rebuilt["status"] == "READY" and not rebuilt["reused"], rebuilt["reason"] + rebuilt.get("build_log_tail", "")
    assert rebuilt["image"] == built["image"]


def test_a_changed_hash_makes_pip_refuse_the_build(docker, tmp_path):
    root, config = base(tmp_path, requirements="six==1.17.0\n", lock=[{**SIX, "sha256": SIX_SDIST_SHA}], pol=policy(["six==1.17.0"]))
    result = project_image.prepare(root, config, docker)
    assert result["status"] == "INCONCLUSIVE" and "build failed" in result["reason"]
    assert "HASH" in result["build_log_tail"].upper()


def test_pip_refuses_a_wheel_that_does_not_fit_even_past_the_tag_check(docker, tmp_path, monkeypatch):
    real = project_image.runner_identity

    def claims_cp314(engine):  # make the plan's own tag check pass, so pip is the one that refuses
        identity, problem = real(engine)
        return ({**identity, "tags": identity["tags"] + ["cp314-cp314-manylinux_2_28_x86_64"]}, None) if identity else (None, problem)

    monkeypatch.setattr(project_image, "runner_identity", claims_cp314)
    root, config = base(tmp_path, requirements="numpy==2.5.4\n", lock=[NUMPY_CP314_ONLY], pol=policy(["numpy==2.5.4"]))
    result = project_image.prepare(root, config, docker)
    assert result["status"] == "INCONCLUSIVE" and "build failed" in result["reason"], result["reason"]


# --- real gate runs in a per-project image (no fake engine, no host execution) --------------------

def _six_project():
    from test_satra_config import CAVR_POLICY, SECURE
    deps = {"requirements.txt": "six==1.17.0\n", "dependencies.lock.json": json.dumps({"packages": [SIX]}),
            ".asent/cavr/policy.json": json.dumps({**CAVR_POLICY, "approved_requirements": ["six==1.17.0"]})}
    return deps, "import six  # an approved third-party dependency\n\n\n" + SECURE


def test_real_gate_run_uses_an_approved_dependency_and_kills_the_mutant(docker, tmp_path):
    from test_satra_config import gate
    deps, secure = _six_project()
    status, details, _ = gate(tmp_path, {"deps": deps, "security": secure})
    assert status == "ACCEPT", details["reason"]
    assert [p["name"] for p in details["sandbox_image"]["packages"]] == ["six"]
    assert details["executions"]["trusted_counterfactual"]["failed"] >= 1
    assert all(run["backend"] == "docker" for run in details["executions"].values())


def test_real_gate_run_cannot_import_an_unlocked_dependency(docker, tmp_path):
    from test_satra_config import NO_DEPENDENCIES, gate
    _, secure = _six_project()
    status, details, _ = gate(tmp_path, {"deps": NO_DEPENDENCIES, "security": secure})
    assert status == "INCONCLUSIVE" and "do not pass on the base commit" in details["reason"]


# --- trusted-run isolation in a real container (docs/satra/harness-isolation.md, step 5) -----------------

# Head code under test, run on import inside the trusted pytest process: it tries to plant a file in /trusted,
# overwrite the trusted test, and append to the trusted-run plugin it finds in sys.modules. can_access returns a
# report of what happened; the string is truthy, so the access check is broken and the report appears in the
# real JUnit failure message of test_other_user_denied.
PROBE_HEAD = '''import errno
import os
import sys


def _try(path, text):
    try:
        with open(path, "a" if text is None else "w") as out:
            out.write(text or "")
    except OSError as error:
        return errno.errorcode.get(error.errno, str(error.errno))
    return "WRITTEN"


_plugin = getattr(sys.modules.get("asent_satra_trusted_run"), "__file__", None)
_REPORT = "PROBE[plugin=%s;plugin_write=%s;trusted_new=%s;trusted_test=%s]" % (
    _plugin, _try(_plugin, None) if _plugin else "none",
    _try("/trusted/planted.txt", "planted"),
    _try("/trusted/asent_assurance/test_contract.py", "def test_other_user_denied():\\n    pass\\n"))


def can_access(user, owner):
    return _REPORT
'''


def _probe_report(result):
    import re
    [denied] = [t for t in result["tests"] if t["name"] == "test_other_user_denied"]
    assert denied["status"] == "FAIL", denied
    found = [m for m in re.findall(r"PROBE\[plugin=([^;]*);plugin_write=([^;]*);trusted_new=([^;]*);trusted_test=([^\]]*)\]",
                                   denied["message"]) if "%s" not in m]  # the report's value, never its format string
    assert found, denied["message"]
    return dict(zip(("plugin", "plugin_write", "trusted_new", "trusted_test"), found[0]))


def test_real_container_trusted_run_resists_head_harness_attacks(docker, tmp_path, monkeypatch):
    """Real container, no host mapping: harness attacks on a broken head give INCONCLUSIVE or REJECT, never a pass;
    writes to /trusted and to the plugin fail read-only; the plugin is mounted read-only at /asent, outside /work."""
    from backend.satra import pytest_runner
    from test_satra_config import BROKEN, gate, project
    from test_satra_harness_isolation import ATTACKS, WRITE_WORK_RESULTS

    monkeypatch.delenv("ASENT_SATRA_REUSE_IMAGES", raising=False)
    commands = []
    real_run = subprocess.run

    def record(cmd, *args, **kwargs):  # records the container commands; they still run in the real engine
        if isinstance(cmd, list) and "pytest" in cmd:
            commands.append(list(cmd))
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(pytest_runner.subprocess, "run", record)

    # 1. Head code that writes to /trusted and to the trusted-run plugin: the gate runs it and rejects.
    status, details, _ = gate(tmp_path / "probe", head_kwargs={"security": PROBE_HEAD})
    assert status == "REJECT", details["reason"]
    assert all(run["backend"] == "docker" for run in details["executions"].values())
    report = _probe_report(details["executions"]["trusted_candidate"])
    assert report == {"plugin": "/asent/asent_satra_trusted_run.py", "plugin_write": "EROFS",
                      "trusted_new": "EROFS", "trusted_test": "EROFS"}, report
    image = details["sandbox_image"]["image"]

    # The plugin's mount, read from the command the engine ran: read-only at /asent, its host folder outside the head's.
    trusted_cmd = next(c for c in commands if "/trusted/pytest.ini" in c)
    mounts = {v.rsplit(":", 2)[1]: (v.rsplit(":", 2)[0], v.rsplit(":", 2)[2]) for f, v in zip(trusted_cmd, trusted_cmd[1:]) if f == "-v"}
    assert mounts["/asent"][1] == "ro" and mounts["/trusted"][1] == "ro" and mounts["/work"][1] == "rw"
    work = Path(mounts["/work"][0])
    for name in ("/asent", "/trusted", "/results"):
        assert work not in Path(mounts[name][0]).parents and Path(mounts[name][0]) != work, name
    assert "PYTHONPATH=/asent" in trusted_cmd and ("-p", "asent_satra_trusted_run") in set(zip(trusted_cmd, trusted_cmd[1:]))

    # 2. Head code that writes a passing /work/results.xml at exit: the real result stands.
    status, details, _ = gate(tmp_path / "results", head_kwargs={"security": WRITE_WORK_RESULTS})
    assert status == "REJECT", details["reason"]
    assert {t["name"]: t["status"] for t in details["executions"]["trusted_candidate"]["tests"]}["test_other_user_denied"] == "FAIL"

    # 3. Harness files: the gate stops at the tripwire, and the trusted run in the real container ignores them anyway.
    for attack in ("root conftest.py forcing passes", "pytest.py", "sitecustomize.py", "pyproject.toml addopts"):
        status, details, _ = gate(tmp_path / attack.split()[0], head_kwargs={"security": BROKEN, "extra": ATTACKS[attack]})
        assert status == "INCONCLUSIVE" and details["reason"].startswith("test-harness tampering suspected"), (attack, details["reason"])
        base = project(tmp_path / attack.split()[0] / "base-direct")
        head = project(tmp_path / attack.split()[0] / "head-direct", security=BROKEN, extra=ATTACKS[attack])
        result = pytest_runner.run_pytest(head, tmp_path / attack.split()[0] / "out", "all", True,
                                          trusted_tests_dir=base / ".asent/satra/trusted_tests", external=True,
                                          pytest_ini=base / ".asent/satra/pytest.ini", image=image)
        assert result["available"] and result["backend"] == "docker" and result["exit_code"] == 1, (attack, result.get("reason"), result.get("stdout"))
        assert {t["name"]: t["status"] for t in result["tests"]} == {"test_owner_allowed": "PASS", "test_other_user_denied": "FAIL"}, attack
