"""Repair proposal (PR 15 and the fast-gate part of PR 16 of docs/cavr-m2-plan.md).

For a REJECTED package (advisory or hash mismatch) `repair_proposal.propose_repair` looks for a newer release of the
same package that passes `verify_request` with the patch applied to a temporary copy of the project, and for a
removal when the project never imports the package. It only proposes (Q9): nothing is written to the project,
nothing is applied, and the verdict and the gate decision stay what they were.

Data: the real pypdf 5.1.0, 6.19.0 and 6.21.4 wheels with their recorded registry answers; the recorded list of every
pypdf release and every pypdf advisory (2026-11-23); synthetic wheels (`build_wheel`, real zip files with real
digests) and SYNTH- advisories where a test needs a situation the real data does not have.
"""
import copy
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from backend.cavr import gate_adapter, repair_proposal
from backend.cavr.repair_proposal import propose_repair
from test_cavr_gate_adapter import Gate
from test_cavr_support import (CLEAN_DEMO, PIN_SHA256, PIN_VERSION, PYPDF_SHA256, RECORDED_5_1_0, RECORDED_6_19_0_NOW,
                               RECORDED_PYPDF_ALL,
                               USES_DEMO, V5_SHA256, V5_WHEEL, World, build_wheel, file_entry, project_response,
                               pypdf_project_response, synthetic_advisory, v5_registry_response, write_osv_cache,
                               write_package_osv_cache)

REQUIREMENTS = "requirements.txt"
LOCKFILE = "dependencies.lock.json"


# --- helpers ---------------------------------------------------------------------------------------------------

def set_pin(world, name, version, sha256):
    """Pin `name==version` in the project's requirements.txt and lockfile (the lockfile entry carries `sha256`)."""
    (world.project / REQUIREMENTS).write_text(f"{name}=={version}\n")
    path = world.project / LOCKFILE
    lockfile = json.loads(path.read_text())
    lockfile["packages"] = [entry for entry in lockfile["packages"] if entry["name"] != name]
    lockfile["packages"].append({"name": name, "version": version, "ecosystem": "PyPI", "sha256": sha256})
    path.write_text(json.dumps(lockfile))


def judged(world):
    """The verdict of the whole requirements file, and its first package."""
    verdict = world.verify(f"pip install -r {REQUIREMENTS}")
    return verdict, verdict["packages"][0]


def repair(world, verdict, package, **overrides):
    args = {"project_dir": world.project, "policy": world.policy, "requirements_file": REQUIREMENTS,
            "transport": world.index, "advisory_cache_dir": world.osv_dir, "live_advisories": False,
            "work_dir": world.tmp_path / "repair-work"}
    args.update(overrides)
    return propose_repair(verdict, package, **args)


def pypdf_world(tmp_path):
    world = World(tmp_path)
    world.index.add_project("pypdf", pypdf_project_response())
    write_package_osv_cache(world.osv_dir, "pypdf", RECORDED_PYPDF_ALL)
    return world


def demo_world(tmp_path, versions=("1.0", "1.1", "1.2"), used=True, rejected_fixed="1.1", project_files=None):
    """A project with a synthetic package `demo`. `demo 1.0` is affected by one SYNTH- advisory (fixed in
    `rejected_fixed`); every other version has a recorded "no advisory" answer and is served by the index."""
    world = World(tmp_path)
    wheels = {}
    for version in versions:
        wheels[version] = world.add("demo", version, files=CLEAN_DEMO, lock=False)
    advisory = synthetic_advisory("SYNTH-REPAIR-1", "demo", introduced="0", fixed=rejected_fixed)
    world.advisories("demo", "1.0", [advisory])
    write_package_osv_cache(world.osv_dir, "demo", [advisory])
    world.index.add_project("demo", project_response("demo", {v: [file_entry(w)] for v, w in wheels.items()}))
    if used:
        world.write("app/uses_demo.py", USES_DEMO)
    for relative, text in (project_files or {}).items():
        world.write(relative, text)
    set_pin(world, "demo", "1.0", hashlib.sha256(wheels["1.0"].read_bytes()).hexdigest())
    world.policy["approved_requirements"].append("demo>=1,<3")
    world.wheels = wheels
    return world


def project_state(root: Path) -> dict:
    """Every entry under `root` (not following links): its kind, bytes digest or link target, and mtime."""
    state = {}
    for base, directories, names in os.walk(root, followlinks=False):
        for name in directories + names:
            path = Path(base) / name
            info = path.lstat()
            if path.is_symlink():
                state[str(path.relative_to(root))] = ("link", os.readlink(path), info.st_mtime_ns)
            elif path.is_file():
                state[str(path.relative_to(root))] = ("file", hashlib.sha256(path.read_bytes()).hexdigest(), info.st_mtime_ns)
            else:
                state[str(path.relative_to(root))] = ("dir", None, None)
    return state


def tried(block):
    return [(c["version"], c["outcome"], c["rule"]) for c in block["candidates_tried"]]


# --- the two real cases -----------------------------------------------------------------------------------------

def test_6_19_0_proposes_6_21_4(tmp_path):
    world = pypdf_world(tmp_path)
    set_pin(world, "pypdf", "6.19.0", PYPDF_SHA256)
    verdict, package = judged(world)
    assert (package["status"], package["stage"]) == ("REJECTED", "advisories")
    block = repair(world, verdict, package)
    assert (block["result"], block["rule"]) == ("PROPOSED", "REPAIR_PROPOSED"), block["reason"]
    pin = block["pin"]
    assert pin["requirement"] == "pypdf==6.21.4" and pin["version"] == PIN_VERSION
    assert "-pypdf==6.19.0\n" in pin["requirements_diff"] and "+pypdf==6.21.4\n" in pin["requirements_diff"]
    assert pin["requirements_diff"].startswith("--- a/requirements.txt\n+++ b/requirements.txt\n")
    assert pin["lockfile_entry"]["before"]["version"] == "6.19.0"
    assert pin["lockfile_entry"]["after"] == {"name": "pypdf", "version": PIN_VERSION, "ecosystem": "PyPI", "sha256": PIN_SHA256}
    # The world's policy already approves pypdf==6.21.4: no policy change is needed.
    assert pin["policy"]["changed"] is False and pin["policy"]["added"] == [] and pin["policy"]["removed"] == []
    recheck = pin["recheck"]
    assert (recheck["status"], recheck["rule"], recheck["escalated"]) == ("VERIFIED", "ALL_CHECKS_PASSED", False)
    assert recheck["package"]["sha256"] == recheck["package"]["registry_sha256"] == PIN_SHA256
    assert recheck["request"].startswith("requirements edit of requirements.txt")
    # Every 6.x release between 6.19.0 and 6.21.4 is affected by a recorded advisory; 6.21.4 is the first one tried.
    assert tried(block) == [(PIN_VERSION, "PROPOSED", "ALL_CHECKS_PASSED")]
    excluded = {entry["version"]: entry["rule"] for entry in block["excluded"]}
    assert excluded["6.20.0"] == excluded["6.21.3"] == "ADVISORY_AFFECTED"
    assert "7.0.0" not in excluded and "7.0.0" in block["not_tried"]   # same major first
    assert block["applied"] is False and block["gate_decision_changed"] is False
    assert not any("major version change" in item for item in block["limitations"])
    assert any("project tests were not run" in item for item in block["limitations"])
    assert block["removal"] is None and "imported" in block["removal_reason"]


def test_5_1_0_proposes_6_21_4_with_the_major_version_limitation(tmp_path):
    world = pypdf_world(tmp_path)
    world.index.add("pypdf", "5.1.0", V5_WHEEL, response=v5_registry_response())
    world.advisories("pypdf", "5.1.0", RECORDED_5_1_0)
    set_pin(world, "pypdf", "5.1.0", V5_SHA256)
    world.policy["approved_requirements"] = ["pypdf==5.1.0"]
    verdict, package = judged(world)
    assert (package["status"], package["stage"], package["rule"]) == ("REJECTED", "advisories", "KNOWN_VULNERABILITY")
    block = repair(world, verdict, package)
    assert block["result"] == "PROPOSED", block["reason"]
    pin = block["pin"]
    assert pin["requirement"] == "pypdf==6.21.4" and pin["recheck"]["status"] == "VERIFIED"
    # No 5.x release is safe; 6.21.4 is the smallest upgrade of the next major version.
    excluded = {entry["version"]: entry["rule"] for entry in block["excluded"]}
    assert all(excluded[v] == "ADVISORY_AFFECTED" for v in ("5.2.0", "5.9.0", "6.0.0", "6.21.3"))
    assert tried(block) == [(PIN_VERSION, "PROPOSED", "ALL_CHECKS_PASSED")]
    # The approved pin moves with the proposal; the re-check ran under exactly that policy.
    assert pin["policy"]["approved_requirements"] == {"before": ["pypdf==5.1.0"], "after": ["pypdf==6.21.4"]}
    assert pin["policy"]["added"] == ["pypdf==6.21.4"] and pin["policy"]["removed"] == ["pypdf==5.1.0"]
    assert pin["recheck"]["policy_version"] != verdict["policy_version"]
    assert "major version change (5 -> 6), may break the project; project tests not run" in block["limitations"]
    assert world.policy["approved_requirements"] == ["pypdf==5.1.0"]   # the caller's policy is untouched


# --- candidates that are skipped ----------------------------------------------------------------------------------

def test_tampered_candidate_is_skipped(tmp_path):
    world = demo_world(tmp_path)
    url = next(u for u in world.index.routes if u.endswith("demo-1.1-py3-none-any.whl"))
    body = bytearray(world.index.routes[url]); body[60] ^= 1; world.index.routes[url] = bytes(body)
    verdict, package = judged(world)
    block = repair(world, verdict, package)
    assert tried(block) == [("1.1", "SKIPPED", "HASH_MISMATCH"), ("1.2", "PROPOSED", "ALL_CHECKS_PASSED")]
    assert block["candidates_tried"][0]["status"] == "REJECTED" and block["pin"]["version"] == "1.2"


def test_yanked_version_is_skipped(tmp_path):
    world = demo_world(tmp_path)
    response = json.loads(world.index.routes["https://pypi.org/pypi/demo/json"])
    for entry in response["releases"]["1.1"]:
        entry.update(yanked=True, yanked_reason="broken build")
    world.index.add_project("demo", response)
    verdict, package = judged(world)
    block = repair(world, verdict, package)
    assert {"version": "1.1", "rule": "YANKED", "reason": "yanked: broken build"} in block["excluded"]
    assert tried(block) == [("1.2", "PROPOSED", "ALL_CHECKS_PASSED")]


def test_release_without_a_wheel_is_excluded(tmp_path):
    world = demo_world(tmp_path)
    response = json.loads(world.index.routes["https://pypi.org/pypi/demo/json"])
    for entry in response["releases"]["1.1"]:
        entry.update(packagetype="sdist", filename="demo-1.1.tar.gz")
    world.index.add_project("demo", response)
    verdict, package = judged(world)
    block = repair(world, verdict, package)
    assert any(e["version"] == "1.1" and e["rule"] == "NO_WHEEL" for e in block["excluded"])
    assert block["pin"]["version"] == "1.2"


def test_candidate_without_an_osv_answer_is_skipped(tmp_path):
    world = demo_world(tmp_path)
    for path in world.osv_dir.glob("*.json"):
        if json.loads(path.read_text())["query"].get("version") == "1.1":
            path.unlink()
    verdict, package = judged(world)
    block = repair(world, verdict, package)
    assert tried(block) == [("1.1", "SKIPPED", "ADVISORIES_UNAVAILABLE"), ("1.2", "PROPOSED", "ALL_CHECKS_PASSED")]
    assert block["candidates_tried"][0]["status"] == "UNRESOLVED"


def test_escalated_candidate_is_skipped(tmp_path, monkeypatch):
    world = demo_world(tmp_path)
    verdict, package = judged(world)
    real = repair_proposal.verify_request

    def escalated(*args, **kwargs):
        result = real(*args, **kwargs)
        if any(p["version"] == "1.1" for p in result["packages"]):
            result = {**result, "status": "UNRESOLVED", "rule": "SINK_NOT_ALLOWED", "escalated": True,
                      "escalation": "deep analysis required (M2)"}
        return result

    monkeypatch.setattr(repair_proposal, "verify_request", escalated)
    block = repair(world, verdict, package)
    assert tried(block)[0] == ("1.1", "SKIPPED", "SINK_NOT_ALLOWED") and block["candidates_tried"][0]["escalated"] is True
    assert block["pin"]["version"] == "1.2"


def test_no_safe_version_gives_no_repair_found(tmp_path):
    world = demo_world(tmp_path, rejected_fixed=None)   # the advisory affects every version
    verdict, package = judged(world)
    block = repair(world, verdict, package)
    assert (block["result"], block["rule"]) == ("NO_REPAIR_FOUND", "NO_SAFE_CANDIDATE")
    assert block["pin"] is None and block["removal"] is None and block["candidates_tried"] == []
    assert {e["version"] for e in block["excluded"]} == {"1.1", "1.2"}
    assert package["status"] == "REJECTED"          # the package stays as judged


# --- removal -----------------------------------------------------------------------------------------------------

def test_unused_package_gets_a_removal(tmp_path):
    world = demo_world(tmp_path, used=False)
    verdict, package = judged(world)
    assert package["status"] == "REJECTED"
    block = repair(world, verdict, package)
    assert block["result"] == "PROPOSED", block["reason"]
    removal = block["removal"]
    assert removal["requirements_diff"].endswith("-demo==1.0\n") and "+demo" not in removal["requirements_diff"]
    assert removal["lockfile_entry"]["before"]["name"] == "demo" and removal["lockfile_entry"]["after"] is None
    assert removal["policy"]["changed"] is False
    assert (removal["recheck"]["status"], removal["recheck"]["rule"]) == ("VERIFIED", "NOTHING_TO_VERIFY")
    # A newer demo is not proposed: the project never uses it, so no contract can be inferred for it.
    assert block["pin"] is None and all(c["rule"] == "NO_CALL_SITE_AUTHORITY" for c in block["candidates_tried"])


def test_used_package_never_gets_a_removal(tmp_path):
    world = demo_world(tmp_path, used=True)
    verdict, package = judged(world)
    block = repair(world, verdict, package)
    assert block["removal"] is None and "app/uses_demo.py" in block["removal_reason"]


def test_removal_is_not_proposed_when_a_locked_package_depends_on_it(tmp_path):
    world = demo_world(tmp_path, used=False)
    path = world.project / LOCKFILE
    lockfile = json.loads(path.read_text())
    lockfile["packages"].append({"name": "other-tool", "version": "3.0", "ecosystem": "PyPI"})
    lockfile["edges"] = [{"source": "other-tool", "target": "Demo"}]   # any spelling of the name
    path.write_text(json.dumps(lockfile))
    verdict, package = judged(world)
    block = repair(world, verdict, package)
    assert block["removal"] is None and "other-tool" in block["removal_reason"]


def test_removal_is_not_proposed_when_the_lockfile_records_no_dependencies(tmp_path):
    world = demo_world(tmp_path, used=False)
    path = world.project / LOCKFILE
    lockfile = json.loads(path.read_text())
    lockfile.pop("edges")
    path.write_text(json.dumps(lockfile))   # pypdf and demo locked, nothing says which depends on which
    verdict, package = judged(world)
    block = repair(world, verdict, package)
    assert block["removal"] is None and "dependencies" in block["removal_reason"]


def test_hash_mismatch_is_repaired_but_never_removed(tmp_path):
    world = demo_world(tmp_path, used=False)
    url = next(u for u in world.index.routes if u.endswith("demo-1.0-py3-none-any.whl"))
    body = bytearray(world.index.routes[url]); body[60] ^= 1; world.index.routes[url] = bytes(body)
    verdict, package = judged(world)
    assert (package["status"], package["rule"]) == ("REJECTED", "HASH_MISMATCH")
    block = repair(world, verdict, package)
    assert block["result"] != "NOT_ATTEMPTED"
    assert block["removal"] is None and "hash" in block["removal_reason"]


# --- what repair never does ---------------------------------------------------------------------------------------

def test_repair_never_writes_the_project(tmp_path):
    world = demo_world(tmp_path)
    verdict, package = judged(world)
    before, policy = project_state(world.project), copy.deepcopy(world.policy)
    verdict_before = copy.deepcopy(verdict)
    block = repair(world, verdict, package)
    assert block["pin"]["version"] == "1.1"
    assert project_state(world.project) == before
    assert world.policy == policy and verdict == verdict_before
    assert not (world.tmp_path / "repair-work").exists() or not any((world.tmp_path / "repair-work").iterdir())


def test_recheck_is_neither_logged_nor_cached(tmp_path):
    world = demo_world(tmp_path)
    verdict, package = judged(world)
    rows, cache = len(world.store.get_verdict_log()), world.cache_rows()
    repair(world, verdict, package)
    assert len(world.store.get_verdict_log()) == rows and world.cache_rows() == cache


def test_exception_inside_repair_gives_no_repair_found(tmp_path, monkeypatch):
    world = demo_world(tmp_path)
    verdict, package = judged(world)

    def broken(*args, **kwargs):
        raise RuntimeError("registry client exploded")

    monkeypatch.setattr(repair_proposal, "fetch_releases", broken)
    block = repair(world, verdict, package)
    assert (block["result"], block["rule"]) == ("NO_REPAIR_FOUND", "INTERNAL_ERROR")
    assert "RuntimeError: registry client exploded" in block["reason"] and block["pin"] is None


def test_budget_limits_the_number_of_candidates(tmp_path):
    versions = ("1.0",) + tuple(f"1.{n}" for n in range(1, 8))
    world = demo_world(tmp_path, versions=versions)
    for path in world.osv_dir.glob("*.json"):   # no per-version answer: every candidate is UNRESOLVED and skipped
        if json.loads(path.read_text())["query"].get("version") not in (None, "1.0"):
            path.unlink()
    verdict, package = judged(world)
    block = repair(world, verdict, package)
    assert [c["version"] for c in block["candidates_tried"]] == ["1.1", "1.2", "1.3", "1.4", "1.5"]
    assert block["budget"]["max_candidates"] == 5 and block["budget"]["stopped_by"] == "candidates"
    assert block["not_tried"] == ["1.6", "1.7"] and block["result"] == "NO_REPAIR_FOUND"


def test_budget_limits_the_time(tmp_path):
    world = demo_world(tmp_path, versions=("1.0", "1.1", "1.2", "1.3"))
    for path in world.osv_dir.glob("*.json"):
        if json.loads(path.read_text())["query"].get("version") not in (None, "1.0"):
            path.unlink()
    verdict, package = judged(world)
    ticks = iter(range(0, 1000, 40))   # every reading of the clock is 40 s later than the one before
    block = repair(world, verdict, package, budget_seconds=60, clock=lambda: next(ticks))
    assert block["budget"]["stopped_by"] == "time" and len(block["candidates_tried"]) < 3
    assert block["result"] == "NO_REPAIR_FOUND"


def test_package_wide_osv_answer_is_stale_after_24_hours(tmp_path):
    world = demo_world(tmp_path)
    verdict, package = judged(world)
    later = datetime.now(timezone.utc) + timedelta(hours=25)
    block = repair(world, verdict, package, now=lambda: later)
    assert (block["result"], block["rule"]) == ("NO_REPAIR_FOUND", "ADVISORIES_STALE")
    fresh = repair(world, verdict, package, now=lambda: datetime.now(timezone.utc) + timedelta(hours=23))
    assert fresh["result"] == "PROPOSED"


def test_policy_range_that_already_covers_the_candidate_needs_no_policy_change(tmp_path):
    world = demo_world(tmp_path)   # demo>=1,<3 is approved
    verdict, package = judged(world)
    block = repair(world, verdict, package)
    assert block["pin"]["policy"]["changed"] is False
    assert block["pin"]["policy"]["approved_requirements"]["after"] == world.policy["approved_requirements"]


def test_package_that_is_not_rejected_is_not_repaired(tmp_path):
    world = pypdf_world(tmp_path)
    verdict, package = judged(world)
    assert package["status"] == "VERIFIED"
    block = repair(world, verdict, package)
    assert (block["result"], block["rule"]) == ("NOT_ATTEMPTED", "NOT_REJECTED") and world.index.calls.count(
        "https://pypi.org/pypi/pypdf/json") == 0


# --- symbolic links in the project copy ---------------------------------------------------------------------------

def test_symlink_to_a_file_outside_the_project_is_not_copied(tmp_path):
    outside = tmp_path / "outside" / "secret.txt"
    outside.parent.mkdir()
    outside.write_text("do not read\n")
    world = demo_world(tmp_path)
    os.symlink(outside, world.project / "notes.txt")
    os.symlink(REQUIREMENTS, world.project / "requirements-link.txt")   # inside the project: kept as a link
    verdict, package = judged(world)
    state = project_state(world.project)
    block = repair(world, verdict, package)
    assert block["result"] == "PROPOSED", block["reason"]
    assert block["project_copy"]["skipped_symlinks"] == [{"path": "notes.txt", "reason": "points outside the project"}]
    assert block["project_copy"]["symlinks_kept"] == ["requirements-link.txt"]
    assert outside.read_text() == "do not read\n" and project_state(world.project) == state


def test_copy_that_reads_differently_from_the_project_gives_no_repair_found(tmp_path):
    """A `.py` link out of the project leaves the project's source not fully read. Skipping it would make the copy
    read better than the project did, so the re-check would be on another project: no repair."""
    outside = tmp_path / "outside" / "helper.py"
    outside.parent.mkdir()
    outside.write_text("X = 1\n")
    world = demo_world(tmp_path)
    os.symlink(outside, world.project / "app" / "helper.py")
    verdict, package = judged(world)
    assert verdict["project"]["result"] == "UNRESOLVED" and package["status"] == "REJECTED"
    block = repair(world, verdict, package)
    assert (block["result"], block["rule"]) == ("NO_REPAIR_FOUND", "COPY_DIFFERS")


# --- in a gate run ------------------------------------------------------------------------------------------------

def rejected_gate(tmp_path, monkeypatch, repair_on):
    gate = Gate(tmp_path, monkeypatch, head_requirements="pypdf==6.19.0\n")
    gate.index.add_pypdf()
    gate.index.add_project("pypdf", pypdf_project_response())
    write_osv_cache(gate.osv, "pypdf", "6.19.0", RECORDED_6_19_0_NOW)
    write_package_osv_cache(gate.osv, "pypdf", RECORDED_PYPDF_ALL)
    monkeypatch.setattr(gate_adapter, "SETTINGS", {**gate_adapter.SETTINGS, "repair": repair_on})
    return gate


def test_gate_decision_is_unchanged_with_or_without_a_proposal(tmp_path, monkeypatch):
    on = rejected_gate(tmp_path / "on", monkeypatch, True)
    status_on, details_on, uncertainty_on = on.analyze()
    off = rejected_gate(tmp_path / "off", monkeypatch, False)
    status_off, details_off, uncertainty_off = off.analyze()
    assert status_on == status_off == "REJECTED" and uncertainty_on == uncertainty_off
    (row_on,), (row_off,) = details_on["nodes"], details_off["nodes"]
    assert row_on["repair"]["result"] == "PROPOSED" and row_on["repair"]["pin"]["requirement"] == "pypdf==6.21.4"
    assert row_off["repair"] is None
    assert details_on["reason"] == details_off["reason"]
    assert (row_on["status"], row_on["mapped"], row_on["rule"]) == (row_off["status"], row_off["mapped"], row_off["rule"])
    assert [e[0] for e in on.events] == [e[0] for e in off.events]   # no new event kinds
    # The gate's project had no lockfile: the proposal says so instead of inventing one.
    assert row_on["repair"]["pin"]["lockfile_entry"] is None
    assert row_on["repair"]["pin"]["policy"]["changed"] is False   # POLICY already approves pypdf==6.21.4


def test_gate_row_of_a_verified_package_has_no_repair(tmp_path, monkeypatch):
    status, details, _ = Gate(tmp_path, monkeypatch).analyze()
    assert status == "VERIFIED" and details["nodes"][0]["repair"] is None


def test_exception_in_the_gate_wiring_keeps_the_verdict(tmp_path, monkeypatch):
    gate = rejected_gate(tmp_path, monkeypatch, True)

    def broken(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(gate_adapter, "propose_repair", broken)
    status, details, _ = gate.analyze()
    assert status == "REJECTED"
    assert (details["nodes"][0]["repair"]["result"], details["nodes"][0]["repair"]["rule"]) == ("NO_REPAIR_FOUND", "INTERNAL_ERROR")
