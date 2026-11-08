"""Packaging step 4b: `asent report` prints the last `asent-report.json`; `--run ID` asks the server.

The local report is the real file a real `asent gate` wrote. `asent report RUN_ID` (the old server
form) is refused with a message that names `--run`.
"""
import json

import pytest

from backend import cli
from gate_support import GateRepo, config

NO_MODULES = config(CAVR={"enabled": False, "reason": "x"})


@pytest.fixture
def gated(tmp_path, monkeypatch, capsys):
    repo = GateRepo(tmp_path / "repo")
    repo.commit({".asent/config.json": NO_MODULES, "README.md": "x\n"})
    (repo.root / "deep").mkdir()
    monkeypatch.chdir(repo.root / "deep")
    cli.main(["gate"])
    capsys.readouterr()
    return repo


def test_report_reads_the_repository_report_from_any_subfolder(gated, capsys):
    assert cli.main(["report"]) == 0
    out = capsys.readouterr().out
    written = json.loads((gated.root / "asent-report.json").read_text())
    assert out.startswith("ASENT gate: REVIEW (exit 2)")
    assert written["base"]["sha"][:12] in out and "refs/heads/main" in out
    for module in ("CAVR", "SATRA", "SABLE"):
        assert module in out
    assert written["reasons"][0][:40] in out and "Report: " + str(gated.root / "asent-report.json") in out


def test_report_json_is_the_file(gated, capsys):
    assert cli.main(["report", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == json.loads((gated.root / "asent-report.json").read_text())


def test_report_file_option(tmp_path, gated, capsys):
    other = tmp_path / "elsewhere.json"
    other.write_text((gated.root / "asent-report.json").read_text())
    assert cli.main(["report", "--file", str(other), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "REVIEW"


def test_missing_report_is_a_plain_message(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["report"]) == 2
    err = capsys.readouterr().err
    assert "No ASENT report at " + str(tmp_path / "asent-report.json") in err and "asent gate" in err
    assert cli.main(["report", "--json"]) == 2
    assert "No ASENT report" in json.loads(capsys.readouterr().out)["error"]


@pytest.mark.parametrize("body", ["{broken", "[1, 2]", json.dumps({"schema": "something.else"})])
def test_a_file_that_is_not_a_gate_report_is_refused(tmp_path, capsys, body):
    path = tmp_path / "asent-report.json"
    path.write_text(body)
    assert cli.main(["report", "--file", str(path)]) == 2
    assert "not an ASENT gate report" in capsys.readouterr().err


def test_the_old_positional_run_id_is_refused_with_the_new_form(capsys):
    assert cli.main(["report", "run-123"]) == 2
    err = capsys.readouterr().err
    assert "asent report --run run-123" in err


def test_run_option_reads_from_the_server(monkeypatch, capsys, tmp_path):
    calls = []

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"schema": "asent.assurance.v1", "run": {"run_id": "r1"}}

    class Client:
        def __init__(self, **kwargs):
            calls.append(kwargs["base_url"])

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def request(self, method, path, json=None):
            calls.append((method, path))
            return Response()

    monkeypatch.setattr(cli.httpx, "Client", Client)
    assert cli.main(["report", "--run", "r1"]) == 0
    assert ("GET", "/api/runs/r1/report") in calls
    assert json.loads(capsys.readouterr().out)["run"]["run_id"] == "r1"
    out = tmp_path / "r.json"
    assert cli.main(["report", "--run", "r1", "--output", str(out)]) == 0
    assert json.loads(out.read_text())["run"]["run_id"] == "r1"
