"""Docker-backed checks of the SATRA runner and per-project gate images.

These skip without Docker locally. In CI (satra-ci.yml) every one of them is listed in the
"ran without skips" step, so a skip there fails the job.
"""
import json
import shutil
import subprocess

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
