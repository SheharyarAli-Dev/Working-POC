"""Packaging step 1: ASENT finds its files in a checkout and in an installed wheel.

A checkout keeps every path exactly as before (assets and writable state under the repository).
An installed package reads its non-Python assets (Dockerfiles, seccomp profile, lockfile, demo
project, scenarios, dashboard build) from `backend/_data/` inside the package, and writes state
(run data, advisory cache, SATRA workspace) to a per-user data folder, never into site-packages.
"""
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
