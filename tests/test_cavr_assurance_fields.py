"""PR 19: the orchestrator's assurance fields that read the retired lab now read the deep result.

`gate_adapter.assurance_fields(cavr_evidence)` gives the seven fields of `asent.assurance.v1` that used to read the
LOCAL lab (`n.static`, `n.runtime`, `n.causal_graph`, the `cavr.trigger_found` / `cavr.counterfactual_started` events;
nothing fills them since Step M2-18, so they were always empty). Each is one entry per package: the package's real
deep data, or `not_available` with the reason. Never an empty list, never a value of its own.
"""
import pytest

from backend.cavr import gate_adapter, sandbox_image
from backend.cavr.gate_adapter import ASSURANCE_FIELDS, assurance_fields
from backend.cavr.pipeline import ESCALATION
from gate_support import run_cli
from test_cavr_sandbox_deep import BENIGN, IDENTITY, Sandbox, gate_repo, recorded_run

DEEP = {"status": "REJECTED", "rule": "DEEP_CONTRACT_VIOLATION", "reason": "r", "elapsed_seconds": 3.5, "image_id": "sha256:i",
        "triggers": [{"id": "t1", "predicate": "(CI == 'true')", "outcome": "explored", "run": 2,
                      "activation": {"env": {"CI": "true"}}},
                     {"id": "t2", "predicate": "(sys.platform == 'win32')", "outcome": "not run: unsimulable", "run": None}],
        "runs": [{"n": 1, "kind": "canary-only", "spec_id": "spec-canaries", "activation": None, "rule": "DEEP_NOT_JUDGED",
                  "completed": True, "elapsed_seconds": 1.0, "container": "c1"},
                 {"n": 2, "kind": "counterfactual", "spec_id": "spec-t1", "activation": {"env": {"CI": "true"}},
                  "rule": "DEEP_NOT_JUDGED", "completed": True, "elapsed_seconds": 2.0, "container": "c2"}],
        "key_events": [{"type": "NETWORK_CONNECT", "run": 2, "rule": "CONTRACT_VIOLATION"}],
        "residual": {"rule": "TRIGGER_UNSIMULABLE", "unsimulable": ["t2"]}, "unexplored_guards": [{"id": "g"}],
        "not_exercised": ["trigger x"], "causal": {"digest": "d" * 64, "counts": {"nodes": 5}, "cause": "caused by CI=true",
                                                  "error": None}}


def evidence(*rows, deep_stage=None):
    return [{"analyzer": "CAVR", "details": {"nodes": list(rows), **({"deep_stage": deep_stage} if deep_stage else {})}}]


def test_a_package_with_a_deep_result_gives_its_real_data_in_every_field():
    fields = assurance_fields(evidence({"name": "demo", "version": "1.0", "status": "REJECTED", "deep": DEEP}))
    assert set(fields) == set(ASSURANCE_FIELDS)
    (triggers,) = fields["discovered_triggers"]
    assert triggers == {"package": "demo==1.0", "triggers": DEEP["triggers"]}
    (triggered,) = fields["triggered_conditions"]
    assert triggered["package"] == "demo==1.0" and [t["id"] for t in triggered["conditions"]] == ["t1"]
    assert triggered["conditions"][0]["activation"] == "CI=true"
    (exercised,) = fields["exercised_conditions"]
    assert [(r["n"], r["kind"], r["activation"]) for r in exercised["runs"]] == [(1, "canary-only", None), (2, "counterfactual", "CI=true")]
    (unresolved,) = fields["unresolved_conditions"]
    assert unresolved["residual"] == DEEP["residual"] and unresolved["unexplored_guards"] == [{"id": "g"}]
    assert unresolved["not_exercised"] == ["trigger x"]
    assert fields["execution_modes"] == [{"package": "demo==1.0", "mode": "CAVR sandbox (deep stage)", "image_id": "sha256:i",
                                          "runs": 2, "elapsed_seconds": 3.5}]
    assert fields["observed_security_events"] == [{"package": "demo==1.0", "events": DEEP["key_events"]}]
    assert fields["causal_evidence"] == [{"package": "demo==1.0", **DEEP["causal"]}]


def test_a_package_the_fast_gate_did_not_escalate_is_not_available_with_the_reason():
    fields = assurance_fields(evidence({"name": "pypdf", "version": "6.21.4", "status": "VERIFIED", "rule": "ALL_CHECKS_PASSED",
                                        "escalation": None, "deep": None}))
    for name in ASSURANCE_FIELDS:
        (entry,) = fields[name]
        assert entry == {"package": "pypdf==6.21.4",
                         "not_available": "the deep stage did not run: the fast gate did not escalate this package "
                                          "(VERIFIED ALL_CHECKS_PASSED)"}, name


def test_an_escalated_package_without_a_deep_stage_names_why_the_stage_was_off():
    fields = assurance_fields(evidence({"name": "demo", "version": "1.0", "status": "UNRESOLVED", "escalation": ESCALATION,
                                        "deep": None},
                                       deep_stage={"enabled": False, "reason": "deep stage off: no image"}))
    assert fields["causal_evidence"] == [{"package": "demo==1.0",
                                          "not_available": "the deep stage did not run: escalated, but deep stage off: no image"}]


def test_no_cavr_row_at_all_is_one_not_available_entry_never_an_empty_list():
    for given in ([], [{"analyzer": "SATRA", "details": {"nodes": [{"name": "x"}]}}], evidence()):
        fields = assurance_fields(given)
        assert all(fields[name] == [{"not_available": "CAVR checked no package in this run"}] for name in ASSURANCE_FIELDS)


def test_unresolved_conditions_list_only_what_was_left_open():
    clean = {**DEEP, "residual": {"rule": "FRONTIER_COMPLETE", "verified_possible": True, "unsimulable": [], "unexplored": []},
             "unexplored_guards": [], "not_exercised": []}
    fields = assurance_fields(evidence({"name": "demo", "version": "1.0", "deep": clean}))
    assert fields["unresolved_conditions"] == [{"package": "demo==1.0", "residual": clean["residual"], "unexplored_guards": [],
                                                "not_exercised": []}]


@pytest.mark.parametrize("broken", [None, "text", {"triggers": "x", "runs": None, "key_events": 5}])
def test_a_malformed_deep_row_never_raises(broken):
    fields = assurance_fields(evidence({"name": "demo", "version": "1.0", "deep": broken}))
    assert set(fields) == set(ASSURANCE_FIELDS) and all(len(fields[name]) == 1 for name in ASSURANCE_FIELDS)


def test_the_report_of_a_gate_run_carries_the_deep_fields(tmp_path, monkeypatch):
    """End to end: asent gate with a (fake) sandbox; the orchestrator's assurance report has the deep data."""
    repo, settings = gate_repo(tmp_path, BENIGN)
    monkeypatch.setattr(sandbox_image, "image_identity", lambda: dict(IDENTITY))
    Sandbox(monkeypatch, [recorded_run("events-probe")])
    monkeypatch.setattr(gate_adapter, "SETTINGS", {**settings, "deep": "sandbox"})
    code, report, _ = run_cli(repo, "base", "head", tmp_path / "out")
    assurance = report["assurance"]
    record = next(e for e in assurance["evidence"] if e["evidence_id"] == report["modules"]["CAVR"]["evidence_id"])
    (row,) = [p for entry in record["details"]["pipeline"] for p in entry["packages"]]
    assert code == 1 and row["deep"]["rule"] == "DEEP_CONTRACT_VIOLATION"
    (modes,) = assurance["execution_modes"]
    assert modes == {"package": "demo==1.0", "mode": "CAVR sandbox (deep stage)", "image_id": row["deep"]["image_id"],
                     "runs": len(row["deep"]["runs"]), "elapsed_seconds": row["deep"]["elapsed_seconds"]}
    (events,) = assurance["observed_security_events"]
    assert events["events"] == row["deep"]["key_events"] and events["events"]
    (causal,) = assurance["causal_evidence"]
    assert causal["digest"] == row["deep"]["causal"]["digest"]
    for name in ASSURANCE_FIELDS:
        assert assurance[name], name


def test_the_report_of_a_fast_gate_run_says_not_available(tmp_path, monkeypatch):
    repo, settings = gate_repo(tmp_path, BENIGN)
    monkeypatch.setattr(sandbox_image, "image_identity", lambda: {"ok": False, "rule": "IMAGE_MISSING", "reason": "no image"})
    monkeypatch.setattr(gate_adapter, "SETTINGS", {**settings, "deep": "sandbox"})
    _, report, _ = run_cli(repo, "base", "head", tmp_path / "out")
    (entry,) = report["assurance"]["causal_evidence"]
    assert entry["package"] == "demo==1.0" and entry["not_available"].startswith("the deep stage did not run: escalated, but deep stage off")
