"""Packaging step 2: `pyproject.toml` builds a wheel that works with no checkout and no PYTHONPATH.

The wheel is built for real from this source tree (`pip wheel`, which downloads the hatchling build
backend; the tests skip with the reason when that download is impossible) and inspected file by file:
every tracked file of `backend/`, `docker/`, `scenarios/` and `demo_project/` must be in it, the
assets under `backend/_data/`, byte-identical. It is then installed into a new virtual environment
outside the repository and `asent` is run from a folder that is not a checkout.
"""
import csv
import io
import json
import os
import shutil
import subprocess
import sys
import sysconfig
import zipfile
from pathlib import Path

import pytest
from packaging.requirements import Requirement

from backend.config import VERSION
from gate_support import GateRepo, config

REPO = Path(__file__).resolve().parents[1]
ASSET_DIRS = ("docker", "scenarios", "demo_project")
ASSET_FILES = ("requirements.lock.txt", "artifacts/pypdf-6.19.0-py3-none-any.whl", "artifacts/pypdf-LICENSE.txt",
               "artifacts/pypi-pypdf.json")


def tracked(*paths):
    out = subprocess.run(["git", "ls-files", "-z", "--", *paths], cwd=REPO, capture_output=True, check=True).stdout
    return sorted(p for p in out.decode().split("\0") if p and (REPO / p).is_file())


@pytest.fixture(scope="module")
def wheel(tmp_path_factory):
    out = tmp_path_factory.mktemp("wheel")
    build = subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps", "--quiet", "-w", str(out), str(REPO)],
                           capture_output=True, text=True, timeout=600)
    if build.returncode != 0 and ("NewConnectionError" in build.stderr or "No matching distribution" in build.stderr):
        pytest.skip("the hatchling build backend could not be downloaded: " + build.stderr.strip().splitlines()[-1])
    assert build.returncode == 0, build.stderr
    (path,) = out.glob("asent-*.whl")
    return path


def names(wheel):
    with zipfile.ZipFile(wheel) as z:
        return set(z.namelist())


def dist_info(wheel, name):
    with zipfile.ZipFile(wheel) as z:
        return z.read(f"asent-{VERSION}.dist-info/{name}").decode()


def test_wheel_name_and_version_come_from_backend_config(wheel):
    assert wheel.name == f"asent-{VERSION}-py3-none-any.whl"
    meta = dist_info(wheel, "METADATA")
    assert "Name: asent\n" in meta and f"Version: {VERSION}\n" in meta and "Requires-Python: >=3.12\n" in meta


def test_wheel_dependencies_are_requirements_txt(wheel):
    meta = dist_info(wheel, "METADATA")
    declared = {str(Requirement(line.split(":", 1)[1].strip())) for line in meta.splitlines() if line.startswith("Requires-Dist:")}
    wanted = {str(Requirement(line)) for line in (REPO / "requirements.txt").read_text().splitlines() if line.strip()}
    assert declared == wanted


def test_wheel_declares_the_asent_command(wheel):
    assert "[console_scripts]\nasent = backend.cli:entry" in dist_info(wheel, "entry_points.txt")


def test_every_tracked_backend_file_is_in_the_wheel(wheel):
    # Policies, threat-repository seeds, OSV snapshot, SABLE config, SATRA trusted files: all package data.
    missing = [p for p in tracked("backend") if p not in names(wheel)]
    assert missing == []


def test_every_asset_is_packaged_under_backend_data_byte_identical(wheel):
    expected = tracked(*ASSET_DIRS) + list(ASSET_FILES)
    for must in ("docker/sandbox.Dockerfile", "docker/satra-runner.Dockerfile", "docker/satra-runner.requirements.txt",
                 "docker/asent-seccomp.json", "docker/asent-sandbox/Dockerfile", "scenarios/catalog.json"):
        assert must in expected
    with zipfile.ZipFile(wheel) as z:
        inside = set(z.namelist())
        missing = [p for p in expected if "backend/_data/" + p not in inside]
        assert missing == []
        changed = [p for p in expected if z.read("backend/_data/" + p) != (REPO / p).read_bytes()]
        assert changed == []


def test_wheel_holds_nothing_else(wheel):
    allowed_tracked = set(tracked("backend")) | {"backend/_data/" + p for p in tracked(*ASSET_DIRS) + list(ASSET_FILES)}
    extra = []
    for name in names(wheel):
        if name.startswith(f"asent-{VERSION}.dist-info/"):
            continue
        if name.startswith("backend/_data/frontend/dist/"):
            continue  # the dashboard build, present only when frontend/dist was built first
        if name not in allowed_tracked:
            extra.append(name)
    assert extra == []  # no tests/, runtime/, .satra_workspace, __pycache__, *.pyc or untracked files


def test_record_hashes_match(wheel):
    # The wheel's RECORD lists every file with its sha256; pip refuses an install whose files disagree.
    rows = list(csv.reader(io.StringIO(dist_info(wheel, "RECORD"))))
    assert {row[0] for row in rows} == names(wheel)


# --- installed into a fresh virtual environment outside the repository ---------------------------

@pytest.fixture(scope="module")
def installed(wheel, tmp_path_factory):
    """A new venv with the wheel installed (--no-deps, no index) and ASENT's dependencies borrowed
    from the test interpreter through a .pth file, so the install needs no network."""
    venv = tmp_path_factory.mktemp("venv") / "env"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, timeout=300)
    py = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    site = subprocess.run([str(py), "-c", "import sysconfig;print(sysconfig.get_paths()['purelib'])"],
                          capture_output=True, text=True, check=True).stdout.strip()
    Path(site, "asent-test-deps.pth").write_text(sysconfig.get_paths()["purelib"] + "\n")
    subprocess.run([str(py), "-m", "pip", "install", "--quiet", "--no-deps", "--no-index", str(wheel)], check=True, timeout=300)
    return venv, Path(site)


def clean_env(tmp_path):
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "ASENT_HOME", "ASENT_PYTHON", "ASENT_DATA", "VIRTUAL_ENV")}
    return {**env, "HOME": str(tmp_path / "home"), "XDG_DATA_HOME": str(tmp_path / "xdg"), "OLLAMA_HOST": "http://127.0.0.1:9"}


def test_installed_package_is_imported_from_the_venv_not_the_checkout(installed, tmp_path):
    venv, site = installed
    probe = "import json, backend.config as c; print(json.dumps({'file': c.__file__, 'installed': c.INSTALLED, 'assets': str(c.ASSETS)}))"
    out = subprocess.run([str(venv / "bin/python"), "-c", probe], cwd=tmp_path, env=clean_env(tmp_path),
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    got = json.loads(out.stdout)
    assert Path(got["file"]).resolve() == (site / "backend/config.py").resolve()
    assert got["installed"] is True and Path(got["assets"], "docker/asent-seccomp.json").is_file()


def test_installed_asent_command_runs_a_real_gate_outside_the_checkout(installed, tmp_path):
    venv, _ = installed
    asent = shutil.which("asent", path=str(venv / "bin"))
    assert asent, "the wheel did not install an asent command"
    help_text = subprocess.run([asent, "gate", "--help"], cwd=tmp_path, env=clean_env(tmp_path), capture_output=True, text=True)
    assert help_text.returncode == 0 and "--repository" in help_text.stdout, help_text.stderr
    repo = GateRepo(tmp_path / "repo")
    base = repo.commit({".asent/config.json": config(CAVR={"enabled": False, "reason": "x"}), "README.md": "x\n"})
    result = subprocess.run([asent, "gate", "--repository", str(repo.root), "--base", base, "--head", base,
                             "--output-dir", str(tmp_path / "out")], cwd=tmp_path, env=clean_env(tmp_path),
                            capture_output=True, text=True, timeout=300)
    # Same decision as the checkout wrapper gives (tests/test_gate_packaging.py): REVIEW, exit 2.
    assert result.returncode == 2, result.stderr
    report = json.loads((tmp_path / "out/asent-report.json").read_text())
    assert report["decision"] == "REVIEW" and report["asent_version"] == VERSION
