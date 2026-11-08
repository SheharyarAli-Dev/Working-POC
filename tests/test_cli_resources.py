"""Packaging step 1: ASENT finds its files in a checkout and in an installed wheel.

A checkout keeps every path exactly as before (assets and writable state under the repository).
An installed package reads its non-Python assets (Dockerfiles, seccomp profile, lockfile, demo
project, scenarios, dashboard build) from `backend/_data/` inside the package, and writes state
(run data, advisory cache, SATRA workspace) to a per-user data folder, never into site-packages.
"""
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from backend import config
from backend.cavr import sandbox_runner

REPO = Path(__file__).resolve().parents[1]


def test_layout_of_a_source_tree(tmp_path):
    (tmp_path / "docker").mkdir()
    (tmp_path / "docker/sandbox.Dockerfile").write_text("FROM x\n")
    (tmp_path / "requirements.lock.txt").write_text("")
    assets, state = config.layout(tmp_path, tmp_path / "backend", {})
    assert assets == tmp_path and state == tmp_path


def test_layout_of_an_installed_package_uses_xdg_data_home(tmp_path):
    site = tmp_path / "site-packages"
    assets, state = config.layout(site, site / "backend", {"XDG_DATA_HOME": str(tmp_path / "xdg")})
    assert assets == site / "backend/_data"
    assert state == tmp_path / "xdg/asent"


def test_layout_of_an_installed_package_defaults_to_home_local_share(tmp_path, monkeypatch):
    monkeypatch.setattr(config.Path, "home", classmethod(lambda cls: tmp_path / "home"))
    site = tmp_path / "site-packages"
    _, state = config.layout(site, site / "backend", {})
    assert state == tmp_path / "home/.local/share/asent"


def test_a_dockerfile_alone_is_not_a_source_tree(tmp_path):
    # Both markers are needed, so a stray docker/ folder next to site-packages cannot switch layouts.
    (tmp_path / "docker").mkdir()
    (tmp_path / "docker/sandbox.Dockerfile").write_text("FROM x\n")
    assets, _ = config.layout(tmp_path, tmp_path / "backend", {})
    assert assets == tmp_path / "backend/_data"


def test_this_checkout_keeps_every_path_unchanged():
    assert config.ASSETS == config.ROOT == REPO
    assert config.STATE == REPO and config.INSTALLED is False
    assert config.ADVISORIES == REPO / "advisories"
    assert config.DEMO == REPO / "demo_project/InvoiceHub"


def test_seccomp_profile_is_the_repository_file_and_the_flags_are_unchanged(tmp_path):
    assert sandbox_runner.SECCOMP_PROFILE == REPO / "docker/asent-seccomp.json"
    cmd = sandbox_runner.SandboxRunner().get_docker_command(tmp_path, "r1")
    assert cmd[:cmd.index("-v")] == [
        "docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/scratch:rw,noexec,nosuid,size=64m",
        "--user", "10001:10001", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--security-opt", f"seccomp={REPO / 'docker/asent-seccomp.json'}", "--pids-limit", "64", "--memory", "256m",
        "--cpus", "0.5"]


# Repository-root paths to non-Python assets or writable folders must go through config.ASSETS /
# config.STATE / config.ADVISORIES, otherwise they point into site-packages once installed.
ROOT_ASSET = re.compile(r"ROOT\s*/\s*f?['\"](docker|scenarios|demo_project|frontend|advisories|artifacts)\b"
                        r"|ROOT\s*/\s*rel\b|parents\[2\]\s*/\s*['\"]docker|PROJECT_TOP\s*=\s*Path")


def test_no_module_builds_asset_or_state_paths_from_the_repository_root():
    offenders = []
    for path in sorted((REPO / "backend").rglob("*.py")):
        rel = path.relative_to(REPO).as_posix()
        if "/fixtures/" in rel or "/sample_project/" in rel or rel == "backend/config.py":
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if ROOT_ASSET.search(line):
                offenders.append(f"{rel}:{number}: {line.strip()[:100]}")
    assert offenders == []


def test_every_packaged_asset_the_code_reads_exists_in_the_checkout():
    from backend.satra import project_image
    for path in (sandbox_runner.SECCOMP_PROFILE, project_image.RUNNER_REQUIREMENTS, config.DEMO / "pytest.ini",
                 config.ASSETS / "scenarios/catalog.json", config.ASSETS / "docker/sandbox.Dockerfile",
                 config.ASSETS / "docker/satra-runner.Dockerfile", config.ASSETS / "requirements.lock.txt"):
        assert path.is_file(), path


INSTALLED_PROBE = """
import json, sys
sys.path.insert(0, sys.argv[1])
from backend import config
from backend.cavr import sandbox_runner
from backend.satra import project_image, settings
from backend.integrations import osv_adapter
print(json.dumps({"root": str(config.ROOT), "assets": str(config.ASSETS), "state": str(config.STATE),
                  "installed": config.INSTALLED, "data": str(config.DATA), "advisories": str(config.ADVISORIES),
                  "seccomp": str(sandbox_runner.SECCOMP_PROFILE), "runner": str(project_image.RUNNER_REQUIREMENTS),
                  "workspace": str(settings.load_settings().workspace), "osv_cache": str(osv_adapter.OSV().cache),
                  "backend": config.__file__}))
"""


def test_a_copy_of_the_package_outside_the_checkout_uses_packaged_assets_and_user_state(tmp_path):
    # The same layout a wheel installs: site/backend/... with no pyproject.toml or docker/ beside it.
    site = tmp_path / "site"
    shutil.copytree(REPO / "backend", site / "backend", ignore=shutil.ignore_patterns("__pycache__"))
    env = {"HOME": str(tmp_path / "home"), "XDG_DATA_HOME": str(tmp_path / "xdg"), "PATH": "/usr/bin:/bin",
           "OLLAMA_HOST": "http://127.0.0.1:9"}  # a set host skips the Ollama network probe
    out = subprocess.run([sys.executable, "-I", "-c", INSTALLED_PROBE, str(site)], cwd=tmp_path, env=env,
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    got = json.loads(out.stdout)
    assets, state = site / "backend/_data", tmp_path / "xdg/asent"
    assert got["backend"] == str(site / "backend/config.py")
    assert got["installed"] is True and got["assets"] == str(assets) and got["state"] == str(state)
    assert got["data"] == str(state / "runtime") and got["advisories"] == str(state / "advisories")
    assert got["osv_cache"] == str(state / "advisories")
    assert got["workspace"] == str(state / ".satra_workspace")
    assert got["seccomp"] == str(assets / "docker/asent-seccomp.json")
    assert got["runner"] == str(assets / "docker/satra-runner.requirements.txt")
    # Nothing was written inside the package.
    assert not any(p.name in {"runtime", "advisories", ".satra_workspace"} for p in (site / "backend").rglob("*"))


def test_asent_data_still_overrides_the_installed_data_folder(tmp_path):
    site = tmp_path / "site"
    shutil.copytree(REPO / "backend", site / "backend", ignore=shutil.ignore_patterns("__pycache__"))
    env = {"HOME": str(tmp_path / "home"), "ASENT_DATA": str(tmp_path / "chosen"), "PATH": "/usr/bin:/bin",
           "OLLAMA_HOST": "http://127.0.0.1:9"}
    out = subprocess.run([sys.executable, "-I", "-c", INSTALLED_PROBE, str(site)], cwd=tmp_path, env=env,
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout)["data"] == str(tmp_path / "chosen")
