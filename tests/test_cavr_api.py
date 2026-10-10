"""The dashboard API on top of the pipeline (plan step 13). Offline.

What is real here: the pipeline, the shipped dashboard project (`backend/cavr/sample_project`),
the shipped policy (`backend/cavr/project_policy.json`), the pypdf 6.19.0 wheel with its recorded
registry response, and the recorded OSV answers for pypdf 6.19.0 and 5.1.0.
What is synthetic and labelled so: the wheel served as "pypdf 5.1.0" is built in the test (the
real one is not in the repository); only its advisories are real. `SYNTH-` advisories are hand-written.
"""
import ast
import asyncio
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.cavr import api, requirement_gate
from backend.cavr.assurance import certificate_for_verdict, generate_printable_html_certificate, verify_chain
from backend.cavr.pipeline import ESCALATION
from backend.cavr.pypi_client import FILES_HOST, TransportError, registry_url
from backend.cavr.storage import CavrStorage
from test_cavr_support import PYPDF_SHA256, PYPDF_WHEEL, REPO, UNGUARDED, World, synthetic_advisory

RECORDED_5_1_0 = json.loads((REPO / "tests" / "test_cavr_data" / "osv-pypdf-5.1.0.json").read_text())["response"]["vulns"]
SCENARIOS = {scenario["id"]: scenario for scenario in api.SCENARIOS}
DENYLISTED = {"package": "requests-security", "version": "2.31.0"}   # on the denylist of the shipped policy


class Dashboard:
    """The API module pointed at an offline index, with its own database and empty run state."""

    def __init__(self, tmp_path, monkeypatch):
        self.world = World(tmp_path)
        self.index = self.world.index
        # A stand-in file for pypdf 5.1.0 (synthetic), with the real recorded advisories for that version.
        self.world.add("pypdf", "5.1.0", {"pypdf/__init__.py": "PdfReader = apply_configuration = None\n"}, lock=False)
        self.world.advisories("pypdf", "5.1.0", RECORDED_5_1_0)
        self.store = CavrStorage(tmp_path / "dashboard.sqlite3")
        self.quarantine = tmp_path / "dashboard-quarantine"
        for name, value in (("TRANSPORT", self.index), ("QUARANTINE_DIR", self.quarantine), ("LIVE_ADVISORIES", False),
                            ("ADVISORY_CACHE_DIR", self.world.osv_dir), ("storage", self.store)):
            monkeypatch.setattr(api, name, value)
        for runs in (api.RUN_EVENTS, api.RUN_PROOFS, api.RUN_CHAINS, api.RUN_CERTIFICATES, api.RUN_FINISHED):
            runs.clear()
        self.count = 0

    def run(self, scenario=None, **body):
        """One run without HTTP. Returns (run id, verdict)."""
        if scenario:
            chosen = SCENARIOS[scenario]
            body = {"package": chosen["package"], "version": chosen["version"], "scenario_type": chosen["condition"] or chosen["id"]}
        self.count += 1
        run_id = f"run-{self.count}"
        api.RUN_EVENTS[run_id] = []
        api.RUN_CHAINS[run_id] = api.EvidenceChain(run_id)
        return run_id, asyncio.run(api.run_verification(run_id, api.InterceptRequest(**body)))

    def events(self, run_id, event_type=None):
        return [event for event in api.RUN_EVENTS[run_id] if event_type in (None, event["type"])]

    def payload(self, run_id, event_type):
        (event,) = self.events(run_id, event_type)
        return event["payload"]


@pytest.fixture
def dashboard(tmp_path, monkeypatch):
    return Dashboard(tmp_path, monkeypatch)


def outcome(verdict):
    return verdict["status"], verdict["stage"], verdict["rule"]


def shape(dashboard, run_id):
    return [(event["step_index"], event["type"]) for event in dashboard.events(run_id)]


# --- the six scenario chips are real requests ------------------------------------------------------------------

def test_scenario_list_is_six_real_requests():
    listed = api.list_scenarios()
    assert [(s["id"], s["request"], s["condition"], s["expected_status"]) for s in listed] == [
        ("verified", "pip install pypdf==6.19.0", None, "VERIFIED"),
        ("verified_again", "pip install pypdf==6.19.0", None, "VERIFIED"),
        ("known_vulnerable", "pip install pypdf==5.1.0", None, "REJECTED"),
        ("not_on_allowlist", "pip install left-pad==1.0", None, "BLOCK"),
        ("tampered_wheel", "pip install pypdf==6.19.0", "tampered_wheel", "REJECTED"),
        ("network_off", "pip install pypdf==6.19.0", "network_off", "UNRESOLVED"),
    ]
    assert all("source_code" not in scenario for scenario in listed)
    # What a chip shows comes from this list: a label, a sentence, and the request it sends.
    assert all(s["display_name"] and s["description"] and s["package"] and s["version"] for s in listed)
    assert [s["display_name"][:2] for s in listed] == ["1.", "2.", "3.", "4.", "5.", "6."]


def test_every_scenario_gives_the_verdict_its_chip_names(dashboard):
    """The six chips in order, each through `run_verification`: (status, stage, rule, cache_hit)."""
    seen = [dashboard.run(scenario["id"])[1] for scenario in api.SCENARIOS]
    assert [(v["status"], v["stage"], v["rule"], v["cache_hit"]) for v in seen] == [
        ("VERIFIED", "verdict", "ALL_CHECKS_PASSED", False),
        ("VERIFIED", "verdict", "ALL_CHECKS_PASSED", True),
        ("REJECTED", "advisories", "KNOWN_VULNERABILITY", False),
        ("BLOCK", "gate", "NOT_ON_ALLOWLIST", False),
        ("REJECTED", "artifact", "HASH_MISMATCH", False),
        ("UNRESOLVED", "artifact", "REGISTRY_UNAVAILABLE", False),
    ]
    assert [v["status"] for v in seen] == [scenario["expected_status"] for scenario in api.SCENARIOS]


def test_the_again_chip_is_the_same_request_and_hits_the_cache_only_when_an_analysis_is_stored(dashboard):
    first, again = SCENARIOS["verified"], SCENARIOS["verified_again"]
    assert (again["package"], again["version"], again["condition"]) == (first["package"], first["version"], first["condition"])
    # Clicked first, on an empty cache, it is an ordinary miss: nothing makes it a hit.
    run_id, verdict = dashboard.run("verified_again")
    assert verdict["status"] == "VERIFIED" and verdict["cache_hit"] is False
    assert dashboard.payload(run_id, "cache_result")["result"] == "MISS"
    run_id, verdict = dashboard.run("verified_again")
    assert verdict["cache_hit"] is True and dashboard.payload(run_id, "cache_result")["result"] == "HIT"


def test_left_pad_is_blocked_as_not_on_the_allowlist_before_any_download(dashboard):
    run_id, verdict = dashboard.run("not_on_allowlist")
    assert outcome(verdict) == ("BLOCK", "gate", "NOT_ON_ALLOWLIST")
    assert dashboard.index.calls == [] and not dashboard.quarantine.exists()
    assert shape(dashboard, run_id) == [(0, "state_change"), (1, "requirement_gate_evaluated"), (1, "verdict_computed"), (1, "state_change")]
    gate = dashboard.payload(run_id, "requirement_gate_evaluated")
    assert (gate["result"], gate["matched_rule"]) == ("BLOCK", "NOT_ON_ALLOWLIST") and "left-pad" in gate["reason"]
    assert api.get_proof(run_id)["request"] == "pip install left-pad==1.0"


def test_pypdf_6_19_0_is_verified_for_the_shipped_project_and_policy(dashboard):
    run_id, verdict = dashboard.run("verified")
    assert outcome(verdict) == ("VERIFIED", "verdict", "ALL_CHECKS_PASSED"), verdict["reason"]
    assert verdict["project"]["project_dir"] == str(api.PROJECT_DIR) and verdict["lockfile"]["present"] is False
    assert shape(dashboard, run_id) == [(0, "state_change"), (1, "requirement_gate_evaluated"), (2, "package_resolved"),
                                        (3, "cache_result"), (4, "action_completed"), (4, "verdict_computed"), (4, "state_change")]
    assert run_id in api.RUN_FINISHED
    # The hash on the dashboard is the SHA-256 of the downloaded bytes, next to the registry's.
    resolution = dashboard.payload(run_id, "package_resolved")["resolution"]
    assert resolution["sha256"] == resolution["registry_sha256"] == PYPDF_SHA256 and resolution["hash_rule"] == "HASH_MATCH"
    assert resolution["tree"]["nodes"] == [{"name": "pypdf", "version": "6.19.0", "sha256": PYPDF_SHA256,
                                            "filename": "pypdf-6.19.0-py3-none-any.whl"}]
    assert resolution["vulnerability_count"] == 0 and resolution["known_risk_signals"] == []
    assert dashboard.payload(run_id, "cache_result")["result"] == "MISS"
    assert all("demo_condition" in event["payload"] and event["payload"]["demo_condition"] is None for event in dashboard.events(run_id))
    action = dashboard.payload(run_id, "action_completed")
    assert action["capability_contract"]["rule"] == "CONTRACT_INFERRED"
    assert [(c["file"], c["symbol"]) for c in action["capability_contract"]["call_sites"]] == [
        ("invoice_extractor/reader.py", "pypdf.apply_configuration"), ("invoice_extractor/reader.py", "pypdf.PdfReader"),
        ("invoice_extractor/reader.py", "pypdf.apply_configuration"), ("invoice_extractor/reader.py", "pypdf.PdfReader")]
    assert [(s["file"], s["line"], s["verdict"]) for s in action["reachability"]["sinks"]] == [
        ("pypdf/filters.py", 774, "GUARD_DISABLED"), ("pypdf/filters.py", 804, "GUARD_DISABLED")]
    assert action["scan"][0]["rule"] == "SCAN_COMPLETE" and action["scan"][0]["python_files"] == 59
    decided = dashboard.payload(run_id, "verdict_computed")
    assert (decided["verdict"], decided["policy_state"], decided["status"]) == ("ALLOW", "VERIFIED", "VERIFIED")
    assert decided["fast_gate_ms"] == verdict["fast_gate_ms"] > 0
    assert (decided["cache_hit"], decided["escalated"], decided["escalation"]) == (False, False, None)
    # Stages that do not exist on this path are null, not filled in.
    assert decided["causal_graph"] is None and decided["repair"] is None and decided["reverification"] is None
    assert "not a claim that the package is safe" in decided["honesty_wording"]
    proof = api.get_proof(run_id)
    assert proof["cavr_verdict"] == verdict and proof["hash_comparison"] == {
        "declared_or_expected": PYPDF_SHA256, "actual_sha256": PYPDF_SHA256, "rule": "HASH_MATCH", "matches": True}
    assert proof["docker_command"] == api.NOT_RUN and proof["counterfactual_runs"] == []
    assert len(dashboard.index.downloads()) == 1


def test_pypdf_5_1_0_is_rejected_by_osv_with_the_recorded_advisory_ids(dashboard):
    run_id, verdict = dashboard.run("known_vulnerable")
    assert outcome(verdict) == ("REJECTED", "advisories", "KNOWN_VULNERABILITY")
    assert verdict["gate"]["result"] == "PERMITTED"  # the policy allows it; OSV is what rejects it
    resolution = dashboard.payload(run_id, "package_resolved")["resolution"]
    ids = [signal["cve"] for signal in resolution["known_risk_signals"]]
    assert "GHSA-7hfw-26vp-jp8m" in ids and resolution["vulnerability_count"] == len(ids) == len(RECORDED_5_1_0) == 97
    decided = dashboard.payload(run_id, "verdict_computed")
    assert (decided["verdict"], decided["policy_state"]) == ("BLOCK", "REJECTED") and "GHSA-" in decided["reason"]
    assert decided["demo_condition"] is None
    # One line for a person: the count and the first three ids. The whole list stays in the event and in the proof.
    assert resolution["first_advisory_ids"] == ids[:3] == sorted(ids)[:3]
    assert resolution["advisory_summary"] == f"97 advisories affect pypdf 5.1.0: {ids[0]}, {ids[1]}, {ids[2]} and 94 more"
    assert decided["reason"] == f"pypdf==5.1.0: pypdf 5.1.0 is affected by 97 known advisories: {ids[0]}, {ids[1]}, {ids[2]} and 94 more"
    in_proof = api.get_proof(run_id)["cavr_verdict"]["packages"][0]["evidence"]["advisories"][0]["affected"]
    assert [entry["id"] for entry in in_proof] == ids


def test_advisory_summary_is_null_when_no_advisory_affects_the_version(dashboard):
    resolution = dashboard.payload(dashboard.run("verified")[0], "package_resolved")["resolution"]
    assert (resolution["vulnerability_count"], resolution["first_advisory_ids"], resolution["advisory_summary"]) == (0, [], None)


def test_denylisted_name_is_blocked_before_any_download(dashboard):
    run_id, verdict = dashboard.run(**DENYLISTED)
    assert outcome(verdict) == ("BLOCK", "gate", "DENYLIST")
    assert dashboard.index.calls == [] and not dashboard.quarantine.exists()
    assert shape(dashboard, run_id) == [(0, "state_change"), (1, "requirement_gate_evaluated"), (1, "verdict_computed"), (1, "state_change")]
    gate = dashboard.payload(run_id, "requirement_gate_evaluated")
    assert (gate["result"], gate["matched_rule"], gate["rule_checked"]) == ("BLOCK", "DENYLIST", "Explicit project denylist")
    decided = dashboard.payload(run_id, "verdict_computed")
    assert (decided["verdict"], decided["policy_state"]) == ("BLOCK", "BLOCK") and "Nothing was downloaded" in decided["honesty_wording"]
    assert api.get_proof(run_id)["hash_comparison"] == {"declared_or_expected": None, "actual_sha256": None, "rule": None,
                                                        "matches": None}
    certificate = api.RUN_CERTIFICATES[run_id]
    assert (certificate["status"], certificate["verdict"], certificate["rule"]) == ("BLOCK", "BLOCK", "DENYLIST")
    assert "Nothing was downloaded" in certificate["bounded_trust_claim"]
    assert certificate["subject"]["package"] == "requests-security" and certificate["subject"]["artifact_sha256"] is None
    checks = certificate["security_checks"]
    assert checks["requirement_gate"] == "DENYLIST"
    assert {checks[key] for key in ("artifact_sha256", "dependency_tree", "osv_advisories", "capability_contract", "ast_scan",
                                    "sink_reachability")} == {"NOT_REACHED"}


def test_tampered_wheel_is_rejected_on_the_hash_of_the_bytes_that_arrived(dashboard):
    run_id, verdict = dashboard.run("tampered_wheel")
    assert outcome(verdict) == ("REJECTED", "artifact", "HASH_MISMATCH")
    proof = api.get_proof(run_id)
    comparison = proof["hash_comparison"]
    assert comparison["declared_or_expected"] == PYPDF_SHA256 != comparison["actual_sha256"] and comparison["matches"] is False
    assert comparison["rule"] == "HASH_MISMATCH"
    assert proof["demo_condition"] == {"id": "tampered_wheel", "description": api.CONDITIONS["tampered_wheel"]}
    # The file kept in quarantine is the real wheel with exactly one bit changed, and its hash is the one reported.
    artifact = verdict["packages"][0]["evidence"]["artifact"]
    arrived, original = Path(artifact["path"]).read_bytes(), PYPDF_WHEEL.read_bytes()
    differing = [(a, b) for a, b in zip(arrived, original) if a != b]
    assert len(arrived) == len(original) and len(differing) == 1 and bin(differing[0][0] ^ differing[0][1]).count("1") == 1
    assert artifact["path"].endswith(".rejected") and comparison["actual_sha256"] == artifact["sha256"]
    # Nothing after the hash check ran, and every event says the run was under a demo condition.
    assert shape(dashboard, run_id) == [(0, "state_change"), (1, "requirement_gate_evaluated"), (2, "package_resolved"),
                                        (2, "verdict_computed"), (2, "state_change")]
    assert all(event["payload"]["demo_condition"]["id"] == "tampered_wheel" for event in dashboard.events(run_id))
    assert verdict["logged"] is False
    assert api.RUN_CERTIFICATES[run_id]["demo_condition"]["id"] == "tampered_wheel"
    assert (api.RUN_CERTIFICATES[run_id]["status"], api.RUN_CERTIFICATES[run_id]["verdict"]) == ("REJECTED", "BLOCK")


def test_network_off_is_unresolved_and_the_real_transport_is_never_asked(dashboard):
    run_id, verdict = dashboard.run("network_off")
    assert outcome(verdict) == ("UNRESOLVED", "artifact", "REGISTRY_UNAVAILABLE")
    assert dashboard.index.calls == []
    decided = dashboard.payload(run_id, "verdict_computed")
    assert (decided["verdict"], decided["policy_state"]) == ("NEEDS_REVIEW", "UNRESOLVED")
    assert "Unknown is not treated as a pass" in decided["honesty_wording"]
    # No hash was computed, so the comparison says "not computed" (None), not "does not match".
    assert api.get_proof(run_id)["hash_comparison"] == {"declared_or_expected": None, "actual_sha256": None,
                                                        "rule": "REGISTRY_UNAVAILABLE", "matches": None}


def test_what_the_pipeline_is_given_under_each_condition(dashboard, monkeypatch):
    seen = []
    real = api.verify_request

    def recording(request, project_dir, policy, store, **options):
        seen.append((project_dir, store, options))
        return real(request, project_dir, policy, store, **options)

    monkeypatch.setattr(api, "verify_request", recording)
    monkeypatch.setattr(api, "LIVE_ADVISORIES", True)
    monkeypatch.setattr(api, "ADVISORY_CACHE_DIR", dashboard.world.tmp_path / "no-advisories")
    for scenario in ("not_on_allowlist", "network_off", "tampered_wheel"):
        dashboard.run(scenario)
    plain, offline, tampered = (options for _, _, options in seen)
    assert all(project_dir == api.PROJECT_DIR for project_dir, _, _ in seen)
    # Only the plain run gets the store: a run under a demo condition is neither logged nor cached.
    assert [store for _, store, _ in seen] == [dashboard.store, None, None]
    assert plain["transport"] is dashboard.index and plain["live_advisories"] is True
    assert isinstance(offline["transport"], api.OfflineTransport) and offline["live_advisories"] is False  # OSV is not asked live
    assert isinstance(tampered["transport"], api.TamperingTransport) and tampered["transport"].inner is dashboard.index
    assert tampered["live_advisories"] is True


def test_runs_under_a_demo_condition_are_not_in_the_log_the_cache_or_the_metrics(dashboard):
    """Their outcome was arranged by the demo, so they must not count in the report numbers."""
    for scenario in ("tampered_wheel", "network_off"):
        run_id, verdict = dashboard.run(scenario)
        assert verdict["logged"] is False and verdict["status"] in ("REJECTED", "UNRESOLVED")
        assert api.get_proof(run_id)["cavr_verdict"]["logged"] is False
    assert dashboard.store.get_verdict_log() == [] and dashboard.store.list_cached_verdicts() == []
    assert api.get_metrics()["verdicts"] == 0 and api.get_cache() == []
    # A plain run of the same request is logged and cached, and a demo run afterwards does not read that cache.
    assert dashboard.run("verified")[1]["logged"] is True
    assert len(dashboard.store.get_verdict_log()) == 1 and len(dashboard.store.list_cached_verdicts()) == 1
    dashboard.run("network_off")
    assert api.get_metrics()["verdicts"] == 1 and api.get_metrics()["by_status"] == {"VERIFIED": 1}


# --- the page's timeline: which stage ran and what it computed -------------------------------------------------

STAGE_IDS = ["capture", "gate", "artifact", "cache", "analysis", "verdict"]


def stages(run_id):
    listed = api.get_proof(run_id)["stages"]
    assert [stage["id"] for stage in listed] == STAGE_IDS and all(stage["title"] for stage in listed)
    return {stage["id"]: stage for stage in listed}


def values(stage):
    return {item["label"]: item["value"] for item in stage["values"]}


def ran(by_id):
    return [stage_id for stage_id in STAGE_IDS if by_id[stage_id]["ran"]]


def test_timeline_of_a_verified_run_copies_the_verdict(dashboard):
    run_id, verdict = dashboard.run("verified")
    by_id = stages(run_id)
    evidence = verdict["packages"][0]["evidence"]
    assert ran(by_id) == STAGE_IDS
    assert values(by_id["capture"]) == {"source": verdict["request"]["source"], "requirements captured": 1, "complete": True}
    assert values(by_id["gate"]) == {"result": "PERMITTED", "rule": "ALLOWED", "policy version": verdict["policy_version"]}
    assert values(by_id["artifact"]) == {
        "hash check": "HASH_MATCH", "file": "pypdf-6.19.0-py3-none-any.whl", "sha256 of the download": PYPDF_SHA256,
        "registry sha256": PYPDF_SHA256, "dependency tree": "TREE_BUILT", "files in the tree": 1,
        "advisories": "NO_KNOWN_VULNERABILITY", "advisories that affect it": 0}
    assert values(by_id["cache"]) == {"lookup": "MISS", "stored": True, "key": verdict["packages"][0]["cache"]["key"]}
    assert values(by_id["analysis"]) == {
        "contract": "CONTRACT_INFERRED", "call sites": 4, "AST scan": "SCAN_COMPLETE", "Python files scanned": 59,
        "sink judgement": evidence["reachability"]["rule"], "sink calls judged": 2, "analysis from the cache": False}
    assert values(by_id["verdict"]) == {
        "status": "VERIFIED", "decided at": "verdict / ALL_CHECKS_PASSED", "fast_gate_ms": verdict["fast_gate_ms"],
        "cache_hit": False, "escalated": False, "escalation": None}
    # A second run: the lookup is a hit and the analysis is the stored one.
    by_id = stages(dashboard.run("verified_again")[0])
    assert values(by_id["cache"])["lookup"] == "HIT" and values(by_id["cache"])["stored"] is False
    assert values(by_id["analysis"])["analysis from the cache"] is True and values(by_id["verdict"])["cache_hit"] is True


@pytest.mark.parametrize("scenario, expected_ran", [
    ("not_on_allowlist", ["capture", "gate", "verdict"]),
    ("tampered_wheel", ["capture", "gate", "artifact", "verdict"]),
    ("network_off", ["capture", "gate", "artifact", "verdict"]),
    ("known_vulnerable", ["capture", "gate", "artifact", "cache", "analysis", "verdict"]),
])
def test_a_stage_that_did_not_run_has_no_value_at_all(dashboard, scenario, expected_ran):
    by_id = stages(dashboard.run(scenario)[0])
    assert ran(by_id) == expected_ran
    for stage_id in STAGE_IDS:
        if stage_id not in expected_ran:
            assert set(values(by_id[stage_id]).values()) == {None}, stage_id


def test_timeline_values_of_the_failing_scenarios(dashboard):
    blocked = stages(dashboard.run("not_on_allowlist")[0])
    assert values(blocked["gate"])["result"] == "BLOCK" and values(blocked["gate"])["rule"] == "NOT_ON_ALLOWLIST"
    assert values(blocked["verdict"])["decided at"] == "gate / NOT_ON_ALLOWLIST"
    tampered = values(stages(dashboard.run("tampered_wheel")[0])["artifact"])
    assert tampered["hash check"] == "HASH_MISMATCH" and tampered["registry sha256"] == PYPDF_SHA256 != tampered["sha256 of the download"]
    offline = values(stages(dashboard.run("network_off")[0])["artifact"])
    assert offline["hash check"] == "REGISTRY_UNAVAILABLE" and offline["sha256 of the download"] is None and offline["file"] is None
    vulnerable = stages(dashboard.run("known_vulnerable")[0])
    assert values(vulnerable["artifact"])["advisories"] == "KNOWN_VULNERABILITY"
    assert values(vulnerable["artifact"])["advisories that affect it"] == 97
    # The contract was inferred and the cache was looked up, but the scan never ran: OSV rejected the request first.
    analysis = values(vulnerable["analysis"])
    assert analysis["contract"] == "CONTRACT_INFERRED" and analysis["AST scan"] is None and analysis["sink judgement"] is None
    assert analysis["Python files scanned"] is None and analysis["sink calls judged"] is None


def test_no_stage_carries_a_time_of_its_own(dashboard):
    """The pipeline measures one time per request (`fast_gate_ms`). The timeline must not show a time per stage."""
    by_id = stages(dashboard.run("verified")[0])
    labels = [item["label"] for stage in by_id.values() for item in stage["values"]]
    assert [label for label in labels if "ms" in label or "time" in label.lower()] == ["fast_gate_ms"]
    assert all(set(stage) == {"id", "title", "ran", "values"} for stage in by_id.values())


@pytest.mark.parametrize("verdict", [{}, {"status": "UNRESOLVED", "packages": [{}]}, {"request": 7, "gate": "x", "packages": "y"},
                                     {"status": "VERIFIED", "packages": [{"evidence": {"artifact": 3, "advisories": [None], "scan": "z"}}]}])
def test_timeline_of_a_verdict_without_evidence_claims_nothing(verdict):
    listed = api.stage_summary(verdict)
    assert [stage["id"] for stage in listed] == STAGE_IDS
    computed = {item["label"]: item["value"] for stage in listed[:-1] for item in stage["values"] if item["value"] is not None}
    assert computed == {} and not any(stage["ran"] for stage in listed[:-1])
    assert values(listed[-1])["status"] == verdict.get("status")


def test_a_pipeline_fault_shows_only_the_verdict_stage(dashboard, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(api, "verify_request", broken)
    by_id = stages(dashboard.run("verified")[0])
    assert ran(by_id) == ["verdict"] and values(by_id["verdict"])["fast_gate_ms"] is None
    assert values(by_id["verdict"])["decided at"] == "internal / INTERNAL_ERROR"


# --- a condition or a scenario name can never improve a verdict ------------------------------------------------

def test_expected_status_of_a_scenario_is_not_used(dashboard):
    dashboard.world.advisories("pypdf", "6.19.0", [synthetic_advisory("SYNTH-1301", "pypdf")])
    _, verdict = dashboard.run("verified")
    assert outcome(verdict) == ("REJECTED", "advisories", "KNOWN_VULNERABILITY") and "SYNTH-1301" in verdict["reason"]


@pytest.mark.parametrize("scenario_type", ["tampered_wheel", "network_off", "verified", "approved_benign", "custom", ""])
def test_no_scenario_type_turns_a_block_into_anything_else(dashboard, scenario_type):
    _, verdict = dashboard.run(package="requests-security", version="2.31.0", scenario_type=scenario_type)
    assert outcome(verdict) == ("BLOCK", "gate", "DENYLIST") and dashboard.index.calls == []


@pytest.mark.parametrize("scenario_type, condition", [("tampered_wheel", "tampered_wheel"), ("network_off", "network_off"),
                                                      ("verified", None), ("approved_benign", None), ("TAMPERED_WHEEL", None)])
def test_only_the_two_named_conditions_change_the_transport(scenario_type, condition):
    found = api.demo_condition(api.InterceptRequest(package="pypdf", version="6.19.0", scenario_type=scenario_type))
    assert (found or {}).get("id") == condition


def test_tampering_transport_flips_one_bit_of_files_only():
    class Inner:
        def stream(self, url):
            yield b"abcd"
            yield b"efgh"

    transport = api.TamperingTransport(Inner())
    assert b"".join(transport.stream(f"https://{FILES_HOST}/packages/x.whl")) == b"abceefgh"   # 'd' ^ 1 == 'e'
    assert b"".join(transport.stream("https://pypi.org/pypi/x/1/json")) == b"abcdefgh"
    assert b"".join(transport.stream(f"https://{FILES_HOST}.example.invalid/x.whl")) == b"abcdefgh"
    with pytest.raises(TransportError):
        list(api.OfflineTransport().stream("https://pypi.org/pypi/x/1/json"))


# --- other verdicts and the metric fields ------------------------------------------------------------------------

def test_second_run_is_a_cache_hit(dashboard):
    dashboard.run("verified")
    run_id, verdict = dashboard.run("verified")
    assert verdict["status"] == "VERIFIED" and verdict["cache_hit"] is True
    assert dashboard.payload(run_id, "cache_result")["result"] == "HIT"
    assert dashboard.payload(run_id, "verdict_computed")["cache_hit"] is True
    assert dashboard.payload(run_id, "action_completed")["analysis_from_cache"] is True


def test_reader_outside_the_guard_is_unresolved_with_the_escalation(dashboard, tmp_path, monkeypatch):
    project = tmp_path / "unguarded_project"
    shutil.copytree(api.PROJECT_DIR, project)
    reader = project / "invoice_extractor" / "reader.py"
    reader.write_text(reader.read_text() + UNGUARDED)
    monkeypatch.setattr(api, "PROJECT_DIR", project)
    run_id, verdict = dashboard.run("verified")
    assert outcome(verdict) == ("UNRESOLVED", "reachability", "SINK_REACHABLE")
    decided = dashboard.payload(run_id, "verdict_computed")
    assert (decided["verdict"], decided["policy_state"], decided["escalated"], decided["escalation"]) == (
        "NEEDS_REVIEW", "UNRESOLVED", True, ESCALATION)
    certificate = api.RUN_CERTIFICATES[run_id]
    assert certificate["escalated"] is True and certificate["escalation"] == ESCALATION
    assert certificate["security_checks"]["sink_reachability"] == "SINK_REACHABLE"


@pytest.mark.parametrize("policy_text, rule", [(None, "POLICY_MISSING"), ("{broken", "POLICY_INVALID")])
def test_missing_or_broken_policy_is_shown_as_unresolved_not_rejected(dashboard, tmp_path, monkeypatch, policy_text, rule):
    path = tmp_path / "policy.json"
    if policy_text is not None:
        path.write_text(policy_text)
    monkeypatch.setattr(requirement_gate, "POLICY_PATH", path)
    run_id, verdict = dashboard.run("verified")
    assert outcome(verdict) == ("UNRESOLVED", "gate", rule) and dashboard.index.calls == []
    gate = dashboard.payload(run_id, "requirement_gate_evaluated")
    assert (gate["result"], gate["matched_rule"]) == ("UNRESOLVED", rule)
    assert dashboard.payload(run_id, "verdict_computed")["policy_state"] == "UNRESOLVED"


def test_a_pipeline_fault_is_an_unresolved_run_that_still_finishes(dashboard, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(api, "verify_request", broken)
    run_id, verdict = dashboard.run("verified")
    assert outcome(verdict) == ("UNRESOLVED", "internal", "INTERNAL_ERROR") and "disk on fire" in verdict["reason"]
    assert run_id in api.RUN_FINISHED and dashboard.payload(run_id, "verdict_computed")["verdict"] == "NEEDS_REVIEW"


# --- how the request is built --------------------------------------------------------------------------------------

def test_package_and_version_are_one_requirement_token():
    assert api.pip_request(api.InterceptRequest(package=" pypdf ", version=" 6.19.0 ")) == ["pip", "install", "pypdf==6.19.0"]
    assert api.pip_request(api.InterceptRequest(package="pypdf")) == ["pip", "install", "pypdf"]
    injected = api.pip_request(api.InterceptRequest(package="pypdf", version="6.19.0 --index-url https://example.invalid/simple"))
    assert injected == ["pip", "install", "pypdf==6.19.0 --index-url https://example.invalid/simple"]
    assert api.pip_request(api.InterceptRequest(request="pip install a==1 b==2")) == "pip install a==1 b==2"


@pytest.mark.parametrize("body, status, rule", [
    ({"package": "pypdf", "version": "6.19.0 --index-url https://example.invalid/simple"}, "UNRESOLVED", "CAPTURE_INCOMPLETE"),
    ({"package": "pypdf --no-deps", "version": "6.19.0"}, "UNRESOLVED", "CAPTURE_INCOMPLETE"),
    ({"package": "pypdf", "version": ""}, "BLOCK", "NOT_PINNED"),
    ({"package": "", "version": ""}, "UNRESOLVED", "CAPTURE_INCOMPLETE"),
    ({"package": "pdf-clean-extractor", "version": "1.0.0", "scenario_type": "approved_benign"}, "UNRESOLVED", "RELEASE_NOT_FOUND"),
    ({"package": "dormant-exfil", "version": "1.2.0", "scenario_type": "trigger_dependent"}, "BLOCK", "NOT_ON_ALLOWLIST"),
    ({"request": "pip install pypdf==6.19.0 --index-url https://example.invalid/simple"}, "UNRESOLVED", "CAPTURE_INCOMPLETE"),
    ({"request": "rm -rf /"}, "UNRESOLVED", "CAPTURE_INCOMPLETE"),
])
def test_requests_that_are_not_a_permitted_pinned_install(dashboard, body, status, rule):
    """The `approved_benign` and `trigger_dependent` rows are what two chips of the old dashboard send: real verdicts too."""
    run_id, verdict = dashboard.run(**body)
    assert (verdict["status"], verdict["rule"]) == (status, rule)
    assert dashboard.index.downloads() == [] and run_id in api.RUN_FINISHED


def test_a_marker_in_the_version_field_does_not_change_what_is_reported(dashboard):
    run_id, verdict = dashboard.run(package="pypdf", version='6.19.0; python_version > "1"')
    assert verdict["status"] == "VERIFIED"
    proof = api.get_proof(run_id)
    assert (proof["package"], proof["version"]) == ("pypdf", "6.19.0") and proof["request"] == 'pip install pypdf==6.19.0; python_version > "1"'


def test_url_passwords_are_not_in_events_proof_or_log(dashboard):
    run_id, _ = dashboard.run(request="pip install pypdf==6.19.0 --index-url https://alice:hunter2@example.invalid/simple")
    everything = json.dumps([api.RUN_EVENTS[run_id], api.get_proof(run_id), api.RUN_CERTIFICATES[run_id],
                             dashboard.store.get_verdict_log(), api.get_evidence_records(run_id)])
    assert "hunter2" not in everything and "***@example.invalid" in everything


# --- the evidence chain and the certificate ---------------------------------------------------------------------------

def test_every_event_is_in_the_hash_chain_and_tampering_is_detected(dashboard):
    run_id, _ = dashboard.run("verified")
    chain = api.RUN_CHAINS[run_id]
    assert len(chain.records) == len(api.RUN_EVENTS[run_id]) == 7
    assert [record["data"] for record in chain.records] == [event["payload"] for event in api.RUN_EVENTS[run_id]]
    assert api.verify_run_evidence(run_id)["intact"] is True
    records = api.get_evidence_records(run_id)
    assert [r["sha256"] for r in records] == [r["sha256"] for r in chain.records] and records[1]["prev_hash"] == records[0]["sha256"]
    # The certificate carries the chain hash as it was before the final event (which contains the certificate).
    assert api.RUN_CERTIFICATES[run_id]["evidence_chain_root"] == chain.records[-2]["sha256"]
    chain.records[2]["data"]["resolution"]["sha256"] = "0" * 64
    broken = verify_chain(chain.records)
    assert broken["intact"] is False and broken["broken_link_seq"] == 3


def test_certificate_copies_the_verdict_and_invents_nothing(dashboard):
    run_id, verdict = dashboard.run("verified")
    certificate = api.RUN_CERTIFICATES[run_id]
    evidence = verdict["packages"][0]["evidence"]
    assert certificate["subject"] == {"package": "pypdf", "version": "6.19.0", "artifact_sha256": PYPDF_SHA256,
                                      "registry_sha256": PYPDF_SHA256, "subtree_digest": evidence["tree"]["subtree_digest"],
                                      "contract_digest": evidence["contract"]["digest"], "other_packages_in_request": []}
    assert (certificate["status"], certificate["verdict"], certificate["rule"]) == ("VERIFIED", "ALLOW", "ALL_CHECKS_PASSED")
    assert certificate["security_checks"] == {
        "requirement_gate": "ALLOWED", "artifact_sha256": "HASH_MATCH", "dependency_tree": "TREE_BUILT",
        "osv_advisories": ["NO_KNOWN_VULNERABILITY"], "capability_contract": "CONTRACT_INFERRED", "ast_scan": ["SCAN_COMPLETE"],
        "sink_reachability": "NO_DENIED_SINK_REACHABLE", "sandbox_execution": "NOT_RUN (M2)"}
    assert certificate["capability_obligations"] == [
        {"obligation": row["capability"], "status": row["status"], "evidence": row["evidence"]}
        for row in evidence["contract"]["contract_rows"]]
    assert {key: certificate[key] for key in ("fast_gate_ms", "cache_hit", "escalated", "escalation")} == {
        key: verdict[key] for key in ("fast_gate_ms", "cache_hit", "escalated", "escalation")}
    assert any("not executed" in item["predicate"] for item in certificate["residual_uncertainty"])
    assert "safe" not in certificate["bounded_trust_claim"].replace("not a claim that the package is safe", "")


@pytest.mark.parametrize("verdict", [{}, {"status": "UNRESOLVED"}, {"status": "VERIFIED", "packages": []},
                                     {"status": "UNRESOLVED", "request": {"requirements": ["pypdf==6.19.0"]}, "packages": []}])
def test_certificate_of_a_verdict_without_evidence_claims_no_check(verdict):
    certificate = certificate_for_verdict("run-x", verdict, "0" * 64)
    assert certificate["subject"]["artifact_sha256"] is None and certificate["capability_obligations"] == []
    checks = dict(certificate["security_checks"], sandbox_execution="NOT_REACHED")
    assert set(checks.values()) == {"NOT_REACHED"}


def test_printable_certificate_shows_the_real_values_and_escapes_them(dashboard):
    run_id, _ = dashboard.run("verified")
    page = api.get_certificate_html(run_id)
    assert PYPDF_SHA256 in page and "VERIFIED" in page and "HASH_MATCH" in page and "NOT_RUN (M2)" in page
    hostile = certificate_for_verdict("run-x", {"status": "UNRESOLVED", "reason": "<script>alert(1)</script>"}, "0" * 64)
    assert "<script>" not in generate_printable_html_certificate(hostile)


# --- over HTTP -------------------------------------------------------------------------------------------------------------

@pytest.fixture
def client(dashboard):
    app = FastAPI()
    app.include_router(api.cavr_router)
    with TestClient(app) as test_client:
        yield test_client


def stream_events(client, stream_url):
    text = client.get(stream_url).text
    return [json.loads(line[len("data: "):]) for line in text.splitlines() if line.startswith("data: ")]


def test_intercept_then_stream_then_proof_over_http(dashboard, client):
    started = client.post("/api/cavr/intercept", json={"package": "pypdf", "version": "6.19.0", "scenario_type": "verified"}).json()
    assert started["status"] == "INTERCEPTED" and started["request"] == "pip install pypdf==6.19.0" and started["demo_condition"] is None
    events = stream_events(client, started["stream_url"])  # the stream ends by itself after the last event
    assert [event["type"] for event in events] == ["state_change", "requirement_gate_evaluated", "package_resolved", "cache_result",
                                                   "action_completed", "verdict_computed", "state_change"]
    assert [event["seq"] for event in events] == list(range(1, 8)) and events[-1]["payload"]["state"] == "DECIDED"
    assert events[5]["payload"]["policy_state"] == "VERIFIED"
    run_id = started["run_id"]
    # A client that connects after the run has finished still gets every event.
    assert stream_events(client, started["stream_url"]) == events
    proof = client.get(f"/api/cavr/proof/{run_id}").json()
    assert proof["cavr_verdict"]["status"] == "VERIFIED" and proof["hash_comparison"]["actual_sha256"] == PYPDF_SHA256
    assert client.get(f"/api/cavr/evidence/{run_id}/verify").json()["intact"] is True
    assert client.get(f"/api/cavr/evidence/{run_id}/certificate.json").json()["subject"]["artifact_sha256"] == PYPDF_SHA256
    assert len(client.get(f"/api/cavr/evidence/{run_id}/records").json()) == 7


def test_scenario_endpoint_and_unknown_runs_over_http(dashboard, client):
    started = client.post("/api/cavr/run", params={"scenario": "tampered_wheel"}).json()
    assert started["demo_condition"]["id"] == "tampered_wheel"
    events = stream_events(client, started["stream_url"])
    assert events[-2]["payload"]["rule"] == "HASH_MISMATCH" and events[-2]["payload"]["policy_state"] == "REJECTED"
    assert client.post("/api/cavr/run", params={"scenario": "nope"}).status_code == 404
    assert client.get("/api/cavr/stream/nope").status_code == 404
    assert client.get("/api/cavr/proof/nope").status_code == 404
    assert client.get("/api/cavr/evidence/nope/records").status_code == 404
    assert [scenario["id"] for scenario in client.get("/api/cavr/scenarios").json()] == list(SCENARIOS)


def test_metrics_come_from_the_verdict_log(dashboard, client):
    empty = client.get("/api/cavr/metrics").json()
    no_rows = {"count": 0, "p50": None, "p95": None}
    assert empty == {
        "verdicts": 0, "cache_hits": 0, "cache_hit_rate": None, "cache_lookups": 0, "cache_hit_rate_of_lookups": None,
        "by_status": {}, "recent": [],
        "fast_gate_ms": {"by_status": {status: no_rows for status in ("VERIFIED", "REJECTED", "BLOCK", "UNRESOLVED")},
                         "by_cache_lookup": {found: no_rows for found in ("HIT", "MISS", "NOT_REACHED")},
                         "by_status_and_cache_lookup": []}}
    miss, hit = dashboard.run("verified")[1], dashboard.run("verified_again")[1]
    rejected, blocked = dashboard.run("known_vulnerable")[1], dashboard.run("not_on_allowlist")[1]
    denied = dashboard.run(**DENYLISTED)[1]
    dashboard.run("network_off")      # demo runs: not counted
    dashboard.run("tampered_wheel")
    report = client.get("/api/cavr/metrics").json()
    assert report["verdicts"] == 5 and report["cache_hits"] == 1 and report["cache_hit_rate"] == 0.2
    assert report["cache_lookups"] == 3 and report["cache_hit_rate_of_lookups"] == pytest.approx(1 / 3)
    assert report["by_status"] == {"BLOCK": 2, "REJECTED": 1, "VERIFIED": 2}
    close = lambda value: pytest.approx(value, abs=0.01)
    by_status = report["fast_gate_ms"]["by_status"]
    verified = sorted([miss["fast_gate_ms"], hit["fast_gate_ms"]])
    assert by_status["VERIFIED"] == {"count": 2, "p50": close(verified[0]), "p95": close(verified[1])}
    assert by_status["REJECTED"] == {"count": 1, "p50": close(rejected["fast_gate_ms"]), "p95": close(rejected["fast_gate_ms"])}
    assert by_status["BLOCK"]["count"] == 2 and by_status["UNRESOLVED"] == no_rows
    assert by_status["BLOCK"]["p95"] == close(max(blocked["fast_gate_ms"], denied["fast_gate_ms"]))
    assert {found: row["count"] for found, row in report["fast_gate_ms"]["by_cache_lookup"].items()} == {
        "HIT": 1, "MISS": 2, "NOT_REACHED": 2}
    assert [(row["status"], row["cache_lookup"], row["count"]) for row in report["fast_gate_ms"]["by_status_and_cache_lookup"]] == [
        ("BLOCK", "NOT_REACHED", 2), ("REJECTED", "MISS", 1), ("VERIFIED", "HIT", 1), ("VERIFIED", "MISS", 1)]
    assert "fast_gate_ms_p50" not in report and "fast_gate_ms_p95" not in report
    assert [(row["status"], row["cache_lookup"]) for row in report["recent"]] == [
        ("BLOCK", "NOT_REACHED"), ("BLOCK", "NOT_REACHED"), ("REJECTED", "MISS"), ("VERIFIED", "HIT"), ("VERIFIED", "MISS")]
    assert report["recent"][1]["requested"] == "pip install left-pad==1.0"


def test_cache_endpoint_lists_the_real_verdict_cache_and_no_seed_rows(dashboard, client):
    assert client.get("/api/cavr/cache").json() == []            # nothing analysed yet: no built-in "trusted" packages
    _, verdict = dashboard.run("verified")
    (row,) = client.get("/api/cavr/cache").json()
    assert (row["name"], row["version"], row["sha256"], row["status"], row["source"]) == (
        "pypdf", "6.19.0", PYPDF_SHA256, "VERIFIED", "CAVR verdict cache")
    assert row["key_fields"] == verdict["packages"][0]["key_fields"] and isinstance(row["capabilities"], str)
    dashboard.run("not_on_allowlist")                            # a BLOCK analyses nothing, so it adds no row
    assert len(client.get("/api/cavr/cache").json()) == 1
    with dashboard.store.connect() as connection:               # a row that was edited is not shown
        connection.execute("UPDATE verdict_cache SET status='REJECTED'")
        connection.commit()
    assert client.get("/api/cavr/cache").json() == []


@pytest.mark.parametrize("method, path, status", [
    ("get", "/simple/", 404), ("get", "/simple/requests/", 404), ("get", "/simple/%3Cimg%20src=x%3E/", 404),
    ("get", "/simple/requests/requests-2.31.0-py3-none-any.whl", 404), ("post", "/api/cavr/cache?name=x&version=1&sha256=0", 405),
    ("get", "/api/cavr/dialog/cache", 404), ("get", "/api/cavr/dialog/action", 404), ("get", "/api/cavr/dialog/environment", 404),
])
def test_endpoints_of_the_old_trusted_package_list_are_gone(client, method, path, status):
    """They served a seeded list as "PyPI Verified", let anyone add to it, and put the URL into an HTML page unescaped."""
    assert getattr(client, method)(path).status_code == status


def test_old_runs_are_dropped(dashboard, client, monkeypatch):
    monkeypatch.setattr(api, "MAX_RUNS", 2)
    ids = []
    for _ in range(3):
        started = client.post("/api/cavr/intercept", json={"package": "requests-security", "version": "2.31.0"}).json()
        stream_events(client, started["stream_url"])
        ids.append(started["run_id"])
    assert list(api.RUN_EVENTS) == ids[1:] and ids[0] not in api.RUN_PROOFS and ids[0] not in api.RUN_CHAINS
    assert client.get(f"/api/cavr/stream/{ids[0]}").status_code == 404


# --- the fixture modules are out of the verdict path ---------------------------------------------------------------------------

def test_api_imports_none_of_the_fixture_or_simulation_modules():
    tree = ast.parse(Path(api.__file__).read_text(encoding="utf-8"))
    imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    imported |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    gone = {"backend.cavr.fixtures.scenarios", "backend.cavr.fixtures", "backend.cavr.resolver", "backend.cavr.reverifier",
            "backend.cavr.reconstructor", "backend.cavr.counterfactual", "backend.cavr.triggers", "backend.cavr.normalizer",
            "backend.cavr.causal_graph", "backend.cavr.repair_engine", "hashlib"}
    assert not imported & gone and "backend.cavr.pipeline" in imported
    source = Path(api.__file__).read_text(encoding="utf-8")
    assert "source_code" not in source and "sha256(" not in source


def test_the_running_app_loads_none_of_the_fixture_or_simulation_modules(tmp_path):
    """Everything the page can call is a route of `backend.main:app`. A module that importing the app
    does not load cannot be reached from any route, whatever the route imports indirectly."""
    code = ("import json, sys, backend.main\n"
            "print(json.dumps(sorted(name for name in sys.modules if name.startswith('backend.cavr'))))")
    done = subprocess.run([sys.executable, "-c", code], cwd=REPO, env={**os.environ, "ASENT_DATA": str(tmp_path / "data")},
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    loaded = set(json.loads(done.stdout.strip().splitlines()[-1]))
    assert {"backend.cavr.api", "backend.cavr.pipeline"} <= loaded
    assert not loaded & {"backend.cavr.fixtures", "backend.cavr.fixtures.scenarios", "backend.cavr.resolver",
                         "backend.cavr.reverifier", "backend.cavr.reconstructor", "backend.cavr.triggers",
                         "backend.cavr.repair_engine", "backend.cavr.counterfactual"}
