"""Write the extension's test fixtures from real `asent` runs (nothing here is hand-written JSON).

    .venv/bin/python vscode-asent/scripts/make_fixtures.py [--out DIR] [--only NAME ...]

Each scenario builds a throwaway git repository with real base and head commits (the
`tests/gate_support.py` helpers) and runs the real CLI (`backend.cli.main`) on it, exactly as the
extension does: `gate --json`, `init --json`, `doctor --json`, and the line `dashboard --json` prints.

| Scenario       | What happens                                               | Needs        |
|----------------|------------------------------------------------------------|--------------|
| accept         | CAVR-only config, head changes README.md -> ACCEPT          | -            |
| cavr-block     | head adds the denied typosquat `reqeusts==2.31.0` -> BLOCK  | -            |
| review         | head edits `.asent/` (config changed in head) -> REVIEW     | -            |
| sable-block    | head replaces infra/ with scenarios/sable/regressed -> SABLE REGRESSED | - |
| satra-block    | head turns `can_access` into `return True` -> SATRA REJECT  | Docker and the images of scripts/satra_build_sandbox.sh |
| doctor         | `asent doctor --json` on this machine                       | -            |
| init           | `asent init --json` on a fresh repository                   | -            |
| dashboard      | the line `asent dashboard --json` prints (the server is not started) | -   |

CAVR's PyPI and OSV answers are the recorded real answers the gate tests use (real pypdf 6.19.0 wheel
and registry response, `tests/test_cavr_support.py`), so these runs need no network. SATRA runs the
trusted tests in real containers. A scenario whose result is not the expected one is an error and
writes nothing, so a fixture can never carry a decision its name does not say.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

import pytest  # noqa: E402  (MonkeyPatch, the same injection the gate tests use)

from backend import cli  # noqa: E402
from gate_support import DISABLED, GateRepo, cavr_files, config, recorded_pypi, run_cli  # noqa: E402

DEFAULT_OUT = ROOT / "vscode-asent" / "test" / "fixtures"


class ScenarioError(Exception):
    pass


def _expect(report, decision, module=None, result=None):
    if report is None:
        raise ScenarioError("no asent-report.json was written")
    if report["decision"] != decision:
        raise ScenarioError(f"decision {report['decision']}, expected {decision}: {report['reasons']}")
    if module and report["modules"][module]["result"] != result:
        raise ScenarioError(f"{module} result {report['modules'][module]['result']!r}, expected {result!r}: "
                            f"{report['modules'][module]['reason']}")
    return report


def _cavr_repo(work: Path, monkeypatch):
    recorded_pypi(monkeypatch, work)
    repo = GateRepo(work / "repo")
    return repo, repo.commit(cavr_files(), message="project with reviewed .asent/")


def accept(work, monkeypatch):
    repo, base = _cavr_repo(work, monkeypatch)
    head = repo.commit({"README.md": "docs\n"}, message="docs only")
    return _expect(run_cli(repo, base, head, work / "out")[1], "ACCEPT", "CAVR", "pass")


def cavr_block(work, monkeypatch):
    repo, base = _cavr_repo(work, monkeypatch)
    head = repo.commit({"requirements.txt": "pypdf==6.19.0\nreqeusts==2.31.0\n"}, message="typosquat")
    return _expect(run_cli(repo, base, head, work / "out")[1], "BLOCK", "CAVR", "block")


def review(work, monkeypatch):
    repo, base = _cavr_repo(work, monkeypatch)
    head = repo.commit({".asent/README.md": "relaxed\n"}, message="edit .asent/ in the change")
    report = _expect(run_cli(repo, base, head, work / "out")[1], "REVIEW")
    if report["config"]["changed_in_head"] is not True:
        raise ScenarioError("expected config.changed_in_head true")
    return report


def sable_block(work, monkeypatch):
    from test_gate_cli import OBLIGATIONS, infra_files
    repo = GateRepo(work / "repo")
    base = repo.commit({**infra_files(), ".asent/config.json": config(SABLE={"enabled": True}, CAVR=DISABLED, SATRA=DISABLED),
                        ".asent/sable/obligations.json": OBLIGATIONS}, message="infrastructure with its obligation")
    for tf in (repo.root / "infra").rglob("*.tf"):
        tf.unlink()
    head = repo.commit(infra_files(ROOT / "scenarios/sable/regressed"), message="regressed infrastructure")
    return _expect(run_cli(repo, base, head, work / "out")[1], "BLOCK", "SABLE", "block")


def satra_block(work, monkeypatch):
    if shutil.which("docker") is None:
        raise ScenarioError("Docker is not installed; SATRA cannot run the trusted tests (see the manual fixtures workflow)")
    from test_satra_config import BROKEN, CONTRACT, NO_DEPENDENCIES, SECURE, TRUSTED
    repo = GateRepo(work / "repo")
    files = {**NO_DEPENDENCIES, "app/__init__.py": "", "app/security.py": SECURE,
             "app/main.py": "from app.security import can_access\n",
             ".asent/config.json": config(SATRA={"enabled": True, "pytest_ini": "satra/pytest.ini", "source_dirs": ["app"]},
                                          CAVR={"enabled": True}, SABLE=DISABLED),
             ".asent/satra/contract.json": json.dumps(CONTRACT),
             ".asent/satra/pytest.ini": "[pytest]\npythonpath = .\n",
             ".asent/satra/trusted_tests/test_contract.py": TRUSTED}
    base = repo.commit(files, message="secure access check")
    head = repo.commit({"app/security.py": BROKEN}, message="access check always allows")
    return _expect(run_cli(repo, base, head, work / "out")[1], "BLOCK", "SATRA", "block")


def _json_stdout(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = cli.main(argv)
    return code, json.loads(out.getvalue())


def doctor(work, monkeypatch):
    return _json_stdout(["doctor", "--json"])[1]


def init(work, monkeypatch):
    repo = GateRepo(work / "repo")
    repo.commit({"requirements.txt": "pypdf==6.19.0\n"}, message="project")
    code, result = _json_stdout(["init", "--json", "--repository", str(repo.root)])
    if code != 0:
        raise ScenarioError(f"init exited {code}: {result}")
    return result


def dashboard(work, monkeypatch):
    from backend.commands import dashboard as dash
    return json.loads(json.dumps(dash.info(dash.DEFAULT_PORT)))  # cli.dashboard_command prints json.dumps(info(port))


SCENARIOS = {"accept": accept, "cavr-block": cavr_block, "review": review, "sable-block": sable_block, "satra-block": satra_block,
             "doctor": doctor, "init": init, "dashboard": dashboard}
FOLDER = {"doctor": "doctor", "init": "init", "dashboard": "dashboard"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--only", nargs="+", choices=sorted(SCENARIOS))
    args = parser.parse_args(argv)
    failed = False
    for name in args.only or [n for n in SCENARIOS if n != "satra-block"]:
        with tempfile.TemporaryDirectory(prefix=f"asent-fixture-{name}-") as work, pytest.MonkeyPatch.context() as mp:
            try:
                value = SCENARIOS[name](Path(work), mp)
            except ScenarioError as exc:
                print(f"{name}: NOT WRITTEN: {exc}", file=sys.stderr)
                failed = True
                continue
        folder = args.out / FOLDER.get(name, "reports")
        folder.mkdir(parents=True, exist_ok=True)
        target = folder / f"{name}.json"
        target.write_text(json.dumps(value, indent=2, default=str) + "\n", encoding="utf-8")
        print(f"{name}: {target}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
