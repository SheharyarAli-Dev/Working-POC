"""Shared helpers for the `asent gate` tests (steps 8 and 9). This file holds no tests.

`GateRepo` is a real git repository in tmp_path. `commit` writes files and commits them, so base and
head are real commits; the gate resolves and exports them like any other repository. PyPI and OSV are
the recorded real answers from `test_cavr_support` (real pypdf 6.19.0 wheel and registry response),
injected through `gate_adapter.SETTINGS`.
"""
import json
import os
import shutil
import subprocess
from pathlib import Path

from backend.cavr import gate_adapter
from test_cavr_support import FakeIndex, INVOICEHUB, POLICY, RECORDED_6_19_0, write_osv_cache

DISABLED = {"enabled": False, "reason": "not part of this test"}


def git(repo, *args):
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True, text=True).stdout.strip()


def config(**modules):
    return json.dumps({"schema_version": 1, "project": {"name": "gate-test"},
                       "modules": {name: section for name, section in modules.items() if section is not None}}, indent=2)


class GateRepo:
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True)
        git(root, "init", "-q", "-b", "main")
        git(root, "config", "user.email", "t@example.invalid")
        git(root, "config", "user.name", "t")

    def commit(self, files: dict, message="change", tag=None) -> str:
        for name, data in files.items():
            path = self.root / name
            if data is None:
                path.unlink()
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data if isinstance(data, bytes) else data.encode())
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "--allow-empty", "-m", message)
        if tag:
            git(self.root, "tag", tag)
        return git(self.root, "rev-parse", "HEAD")


def invoice_app_files() -> dict:
    """The InvoiceHub application code (it calls pypdf under its guard), as files to commit."""
    return {f"app/{p.name}": p.read_text() for p in (INVOICEHUB / "app").glob("*.py")}


def cavr_files(policy=None, requirements="pypdf==6.19.0\n", **modules):
    files = {**invoice_app_files(), "requirements.txt": requirements,
             ".asent/cavr/policy.json": json.dumps(policy or POLICY, indent=2),
             ".asent/config.json": config(CAVR={"enabled": True}, SATRA=modules.get("SATRA", DISABLED),
                                         SABLE=modules.get("SABLE", DISABLED))}
    return files


def recorded_pypi(monkeypatch, tmp_path):
    """Serve the real pypdf 6.19.0 wheel and its recorded registry and OSV answers to gate runs."""
    index = FakeIndex()
    index.add_pypdf()
    osv = tmp_path / "osv"
    write_osv_cache(osv, "pypdf", "6.19.0", RECORDED_6_19_0)
    monkeypatch.setattr(gate_adapter, "SETTINGS", {"transport": index, "osv": None, "advisory_cache_dir": osv, "live_advisories": False})
    return index, osv


def run_cli(repo: GateRepo, base, head, out: Path, *extra):
    from backend import cli
    code = cli.main(["gate", "--repository", str(repo.root), "--base", base, "--head", head, "--output-dir", str(out), *extra])
    report = json.loads((out / "asent-report.json").read_text()) if (out / "asent-report.json").is_file() else None
    summary = (out / "asent-summary.md").read_text() if (out / "asent-summary.md").is_file() else None
    return code, report, summary
