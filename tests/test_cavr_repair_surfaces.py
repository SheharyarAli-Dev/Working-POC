"""Where the repair proposal is shown (step M2-4): `asent-report.json`, `asent report`, the dashboard, the page.

Offline: the real pypdf 6.19.0 and 6.21.4 wheels with their recorded registry answers, the recorded list of every
pypdf release and the recorded package-wide OSV answer (2026-11-23). Display only: every test also checks that the
decision is the one made without repair.
"""
import json
from pathlib import Path

import pytest

from backend.cavr import api, gate_adapter
from backend.commands.report import render
from gate_support import GateRepo, cavr_files, run_cli
from test_cavr_api import Dashboard
from test_cavr_frontend import FRONTEND, PARTS, render as render_views, run_data
from test_cavr_support import (FakeIndex, PIN_SHA256, RECORDED_6_19_0_NOW, RECORDED_6_21_4, RECORDED_PYPDF_ALL,
                               pypdf_project_response, write_osv_cache, write_package_osv_cache)


def recorded_settings(tmp_path, repair=True) -> dict:
    index = FakeIndex()
    index.add_pin()
    index.add_pypdf()
    index.add_project("pypdf", pypdf_project_response())
    osv = tmp_path / "osv"
    write_osv_cache(osv, "pypdf", "6.21.4", RECORDED_6_21_4)
    write_osv_cache(osv, "pypdf", "6.19.0", RECORDED_6_19_0_NOW)
    write_package_osv_cache(osv, "pypdf", RECORDED_PYPDF_ALL)
    return {"transport": index, "osv": None, "advisory_cache_dir": osv, "live_advisories": False, "repair": repair}


def gate_run(tmp_path, monkeypatch, repair=True):
    """`asent gate` on a repository whose head pins the REJECTED pypdf 6.19.0."""
    monkeypatch.setattr(gate_adapter, "SETTINGS", recorded_settings(tmp_path, repair))
    repo = GateRepo(tmp_path / "repo")
    repo.commit(cavr_files(), tag="base")
    repo.commit({"requirements.txt": "pypdf==6.19.0\n"}, tag="head")
    return run_cli(repo, "base", "head", tmp_path / "out")


def cavr_rows(report) -> list:
    record = next(e for e in report["assurance"]["evidence"] if e["evidence_id"] == report["modules"]["CAVR"]["evidence_id"])
    return [package for entry in record["details"]["pipeline"] for package in entry["packages"]]


def test_asent_gate_report_carries_the_repair_block_and_the_same_decision(tmp_path, monkeypatch):
    code, report, summary = gate_run(tmp_path / "on", monkeypatch, repair=True)
    code_off, report_off, _ = gate_run(tmp_path / "off", monkeypatch, repair=False)
    assert code == code_off == 1 and report["decision"] == report_off["decision"] == "BLOCK"
    assert report["reasons"] == report_off["reasons"]
    assert report["modules"]["CAVR"]["result"] == report_off["modules"]["CAVR"]["result"]
    (row,), (row_off,) = cavr_rows(report), cavr_rows(report_off)
    assert row["status"] == row_off["status"] == "REJECTED" and row_off["repair"] is None
    block = row["repair"]
    assert block["result"] == "PROPOSED" and block["applied"] is False and block["gate_decision_changed"] is False
    assert block["pin"]["requirement"] == "pypdf==6.21.4" and block["pin"]["recheck"]["status"] == "VERIFIED"
    assert block["pin"]["recheck"]["package"]["sha256"] == PIN_SHA256
    assert json.loads((tmp_path / "on" / "out" / "asent-report.json").read_text()) == report


def test_asent_report_text_lists_the_proposal(tmp_path, monkeypatch):
    _, report, _ = gate_run(tmp_path, monkeypatch)
    text = render(report, Path("asent-report.json"))
    assert "CAVR repair proposals (not applied; for a person to approve):" in text
    assert "  pypdf==6.19.0 (REJECTED advisories KNOWN_VULNERABILITY) in requirements.txt: PROPOSED REPAIR_PROPOSED" in text
    assert f"      pin pypdf==6.21.4: re-check VERIFIED ALL_CHECKS_PASSED, wheel sha256 {PIN_SHA256[:12]} (registry {PIN_SHA256[:12]})" in text
    assert "          -pypdf==6.19.0\n          +pypdf==6.21.4\n" in text
    assert "        lockfile: none in the project" in text
    assert "        policy approved_requirements: no change needed" in text
    assert "removal not proposed: the project uses it: imported at app/pdf_adapter.py:" in text
    assert "      limitation: project tests were not run on the proposal (Q10: waiting for SATRA's project image builder)" in text
    assert text.index("CAVR repair proposals") < text.index("Reasons:")   # the decision lines come first, unchanged


def test_asent_report_text_without_a_block_has_no_repair_section(tmp_path, monkeypatch):
    _, report, _ = gate_run(tmp_path, monkeypatch, repair=False)
    assert "CAVR repair proposals" not in render(report, Path("asent-report.json"))
    assert "CAVR repair proposals" not in render({"schema": "asent.gate.v1", "modules": {}}, Path("x"))


# --- the dashboard -------------------------------------------------------------------------------------------------

@pytest.fixture
def dashboard(tmp_path, monkeypatch):
    board = Dashboard(tmp_path, monkeypatch)
    board.index.add_project("pypdf", pypdf_project_response())
    write_package_osv_cache(board.world.osv_dir, "pypdf", RECORDED_PYPDF_ALL)
    return board


def test_dashboard_rejected_run_has_the_proposal_and_keeps_its_verdict(dashboard):
    run_id, verdict = dashboard.run("known_vulnerable")
    assert verdict["status"] == "REJECTED"
    decided = dashboard.payload(run_id, "verdict_computed")
    assert (decided["verdict"], decided["policy_state"]) == ("BLOCK", "REJECTED")
    repair = decided["repair"]
    assert repair["result"] == "PROPOSED" and repair["pin"]["requirement"] == "pypdf==6.21.4"
    assert repair["pin"]["pip_command"] == "pip install pypdf==6.21.4" and repair["pin"]["requirements_diff"] is None
    assert repair["pin"]["policy"]["changed"] is False          # the sample policy approves pypdf>=5,<7
    proof = api.get_proof(run_id)
    assert proof["repair"] == repair and proof["cavr_verdict"] == verdict and proof["policy_state"] == "REJECTED"


def test_dashboard_verified_run_has_no_repair(dashboard):
    run_id, verdict = dashboard.run("verified")
    assert verdict["status"] == "VERIFIED" and dashboard.payload(run_id, "verdict_computed")["repair"] is None
    assert api.get_proof(run_id)["repair"] is None


def test_dashboard_network_off_is_unresolved_and_gets_no_repair(dashboard):
    run_id, verdict = dashboard.run("network_off")
    assert verdict["status"] == "UNRESOLVED" and dashboard.payload(run_id, "verdict_computed")["repair"] is None


def test_dashboard_tampered_wheel_run_gets_no_proposal(dashboard):
    """The tampered chip is pypdf 6.21.4: its upgrades are the 7.x releases, which the offline index does not serve,
    so each is skipped (RELEASE_NOT_FOUND) and nothing is proposed. The tampering itself is covered by
    tests/test_cavr_repair.py::test_tampered_candidate_is_skipped."""
    run_id, verdict = dashboard.run("tampered_wheel")
    assert (verdict["status"], verdict["rule"]) == ("REJECTED", "HASH_MISMATCH")
    repair = dashboard.payload(run_id, "verdict_computed")["repair"]
    assert (repair["result"], repair["pin"], repair["removal"]) == ("NO_REPAIR_FOUND", None, None)
    assert [c["version"] for c in repair["candidates_tried"]] == ["7.0.0", "7.0.1", "7.1.0", "7.1.1"]
    assert all((c["outcome"], c["rule"]) == ("SKIPPED", "RELEASE_NOT_FOUND") for c in repair["candidates_tried"])


def test_the_repair_tab_prints_the_proposal_of_the_run(dashboard, tmp_path):
    data = run_data(dashboard, "known_vulnerable")
    (tab,) = render_views(tmp_path, {"view": "repair", **data})
    text = " ".join(tab)
    assert "Pin pypdf==6.21.4" in tab and "Result:" in tab and "PROPOSED" in tab
    assert "VERIFIED" in tab and f"Wheel sha256 {PIN_SHA256}; registry sha256 {PIN_SHA256}." in text
    assert "Command: pip install pypdf==6.21.4" in text and "Lockfile: none in the project" in text
    assert "Applied: false. Gate decision changed: false." in text
    assert any("project tests were not run" in piece for piece in tab)
    assert "Record approval" in text


def test_the_repair_tab_without_a_block(dashboard, tmp_path):
    data = run_data(dashboard, "verified")
    (tab,) = render_views(tmp_path, {"view": "repair", **data})
    assert "Not run: repair is looked for only when a package is REJECTED." in tab


def test_no_old_repair_fixture_field_is_left_in_the_page():
    texts = {path.name: path.read_text(encoding="utf-8") for path in [FRONTEND / "src" / "components" / "CavrModule.tsx", *PARTS]}
    for old in ("chosen_candidate", "ranked_candidates", "cost_breakdown", "dependency_diff", "repair_engine.py", "reverifier.py"):
        assert [name for name, text in texts.items() if old in text] == [], old
