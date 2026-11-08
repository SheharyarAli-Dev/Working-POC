"""Packaging step 6: the sample repository CI gates with the installed wheel gives the expected decisions.

`scripts/ci/make_sample_repo.sh` is run for real; `asent gate` with no arguments (base: branch main,
head: HEAD) must decide ACCEPT for the docs-only head and BLOCK for the regressed Terraform head,
the same decisions tests/test_gate_cli.py gets for the same inputs.
"""
import json
import subprocess
from pathlib import Path

import pytest

from backend import cli

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts/ci/make_sample_repo.sh"


@pytest.mark.parametrize("mode, decision, code", [("accept", "ACCEPT", 0), ("block", "BLOCK", 1)])
def test_sample_repository_decisions(tmp_path, monkeypatch, capsys, mode, decision, code):
    sample = tmp_path / "sample"
    subprocess.run([str(SCRIPT), str(sample), str(REPO), mode], check=True, capture_output=True, text=True)
    monkeypatch.chdir(sample)
    assert cli.main(["gate", "--json"]) == code
    report = json.loads(capsys.readouterr().out)
    assert report["decision"] == decision and report["base"]["ref"] == "refs/heads/main"
    assert report["modules"]["SABLE"]["assessed"] is True


def test_script_refuses_an_existing_destination_and_an_unknown_mode(tmp_path):
    bad = subprocess.run([str(SCRIPT), str(tmp_path), str(REPO), "accept"], capture_output=True, text=True)
    assert bad.returncode == 2 and "already exists" in bad.stderr
    bad = subprocess.run([str(SCRIPT), str(tmp_path / "x"), str(REPO), "maybe"], capture_output=True, text=True)
    assert bad.returncode == 2 and not (tmp_path / "x").exists()
