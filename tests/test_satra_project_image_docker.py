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
