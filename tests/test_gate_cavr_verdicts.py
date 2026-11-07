"""Step 9 of docs/dev-env-plan.md: each CAVR pipeline verdict through `asent gate`, one test each.

Real git repositories (base and head commits), the real `asent gate` CLI, the M1 pipeline. PyPI is the
real pypdf 6.19.0 wheel with its recorded registry response; OSV is its recorded answer ("no advisories")
except in the REJECTED case, which writes one hand-written SYNTH- advisory in OSV's cache format (no
recorded advisory affects 6.19.0). Mapping checked end to end:

    VERIFIED -> ACCEPT, exit 0      REJECTED -> BLOCK, exit 1
    BLOCK    -> BLOCK,  exit 1      UNRESOLVED -> REVIEW, exit 2

`test_live_pypi_and_osv` repeats the VERIFIED case against live PyPI and OSV when CAVR_LIVE=1.
"""
import os

import pytest

from backend.cavr import gate_adapter
from backend.cavr.pypi_client import TransportError
from backend.cavr.verdict_cache import KEY_FIELDS
from gate_support import GateRepo, cavr_files, recorded_pypi, run_cli
from test_cavr_support import PYPDF_SHA256, synthetic_advisory, write_osv_cache


def cavr_evidence(report):
    (row,) = [e for e in report["assurance"]["evidence"] if e["analyzer"] == "CAVR" and not e["stale"]]
    return row


def change(tmp_path, head_requirements):
    repo = GateRepo(tmp_path / "repo")
    base = repo.commit(cavr_files(requirements="pypdf==6.19.0\n"))
    head = repo.commit({"requirements.txt": head_requirements, "app/notes.py": "VALUE = 1\n"})
    return repo, base, head


def check_row(report, summary, pipeline_status, module_status, result):
    row = cavr_evidence(report)
    (entry,) = row["details"]["pipeline"]
    assert row["details"]["engine"] == "pipeline"
    assert entry["status"] == pipeline_status and row["status"] == module_status
    assert report["modules"]["CAVR"]["status"] == module_status and report["modules"]["CAVR"]["result"] == result
    line = next(line for line in summary.splitlines() if line.startswith("| CAVR |"))
    assert f"| {result} | {module_status} |" in line
    return row, entry


def test_verified_is_accept_exit_0(tmp_path, monkeypatch):
    recorded_pypi(monkeypatch, tmp_path)
    repo, base, head = change(tmp_path, "pypdf==6.19.0\n")
    code, report, summary = run_cli(repo, base, head, tmp_path / "out")
    assert code == 0 and report["decision"] == "ACCEPT", report["reasons"]
    row, entry = check_row(report, summary, "VERIFIED", "VERIFIED", "pass")
    assert (entry["stage"], entry["rule"]) == ("verdict", "ALL_CHECKS_PASSED")
    (package,) = entry["packages"]
    assert set(package["key_fields"]) == set(KEY_FIELDS)
    assert package["key_fields"]["artifact_sha256"] == PYPDF_SHA256 and package["key_fields"]["name"] == "pypdf"


def test_rejected_is_block_exit_1(tmp_path, monkeypatch):
    _, osv = recorded_pypi(monkeypatch, tmp_path)
    write_osv_cache(osv, "pypdf", "6.19.0", [synthetic_advisory("SYNTH-PYPDF-GATE", "pypdf", introduced="6.0.0", fixed="6.20.0")])
    repo, base, head = change(tmp_path, "pypdf==6.19.0\n")
    code, report, summary = run_cli(repo, base, head, tmp_path / "out")
    assert code == 1 and report["decision"] == "BLOCK"
    _, entry = check_row(report, summary, "REJECTED", "REJECTED", "block")
    assert entry["stage"] == "advisories" and "SYNTH-PYPDF-GATE" in entry["reason"]


def test_block_is_block_exit_1_without_a_download(tmp_path, monkeypatch):
    index, _ = recorded_pypi(monkeypatch, tmp_path)
    repo, base, head = change(tmp_path, "pypdf==6.19.0\nreqeusts==2.31.0\n")
    code, report, summary = run_cli(repo, base, head, tmp_path / "out")
    assert code == 1 and report["decision"] == "BLOCK"
    _, entry = check_row(report, summary, "BLOCK", "REJECTED", "block")
    assert entry["stage"] == "gate" and index.downloads() == []
    assert "BLOCK" in next(line for line in summary.splitlines() if line.startswith("| CAVR |"))


def test_unresolved_is_review_exit_2(tmp_path, monkeypatch):
    index, _ = recorded_pypi(monkeypatch, tmp_path)
    for url in list(index.routes):
        index.routes[url] = TransportError("ConnectError: the network is off")
    repo, base, head = change(tmp_path, "pypdf==6.19.0\n")
    code, report, summary = run_cli(repo, base, head, tmp_path / "out")
    assert code == 2 and report["decision"] == "REVIEW"
    check_row(report, summary, "UNRESOLVED", "UNRESOLVED", "review")
    assert "CAVR: UNRESOLVED" in report["reasons"]


@pytest.mark.skipif(os.environ.get("CAVR_LIVE") != "1", reason="live network test; set CAVR_LIVE=1")
def test_live_pypi_and_osv(tmp_path):
    assert gate_adapter.SETTINGS["transport"] is None and gate_adapter.SETTINGS["live_advisories"] is True
    repo, base, head = change(tmp_path, "pypdf==6.19.0\n")
    code, report, _ = run_cli(repo, base, head, tmp_path / "out")
    status = cavr_evidence(report)["status"]
    # Live advisories can change over time; the exit code must follow whatever CAVR found.
    assert code == {"VERIFIED": 0, "REJECTED": 1}.get(status, 2)
