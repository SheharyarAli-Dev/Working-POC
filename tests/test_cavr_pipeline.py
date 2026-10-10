"""The single verify_request pipeline (plan step 11). Offline.

What is real here: the pypdf 6.19.0 wheel and its recorded registry response, the recorded OSV
answer for pypdf 6.19.0 (no advisories), the InvoiceHub demo project's source, every tmp-built
wheel (a real zip, served with a digest computed from its bytes) and the SQLite cache file.
What is synthetic and labelled so: advisories whose id starts with "SYNTH-".
"""
import json
import shutil

import pytest

from backend.cavr import pipeline
from backend.cavr.manifest_parser import snapshot_requirements
from backend.cavr.pipeline import ESCALATION, metrics, verify_request
from backend.cavr.pypi_client import TransportError, registry_url
from backend.cavr.verdict_cache import lookup
from backend.threat_repo.repository import seeds
from test_cavr_support import (CLEAN_DEMO, PYPDF_SHA256, PYPDF_WHEEL, RECORDED_6_19_0, UNGUARDED, USES_DEMO, World, build_wheel,
                               sha256_file, synthetic_advisory)

@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


def outcome(verdict):
    return verdict["status"], verdict["stage"], verdict["rule"]


def only(verdict):
    assert len(verdict["packages"]) == 1
    return verdict["packages"][0]


def assert_metric_fields(verdict):
    for item in [verdict, *verdict["packages"]]:
        assert isinstance(item["fast_gate_ms"], float) and item["fast_gate_ms"] >= 0
        assert isinstance(item["cache_hit"], bool) and isinstance(item["escalated"], bool)
        assert item["escalated"] is (item["escalation"] is not None)
    json.dumps(verdict)  # the whole verdict is plain JSON


# --- end to end: the real pypdf wheel in the InvoiceHub project -------------------------------------------

def test_pypdf_6_19_0_is_verified_with_the_guard_evidence(world):
    verdict = world.verify()
    assert outcome(verdict) == ("VERIFIED", "verdict", "ALL_CHECKS_PASSED"), verdict["reason"]
    assert_metric_fields(verdict)
    assert verdict["cache_hit"] is False and verdict["escalated"] is False and verdict["escalation"] is None
    assert verdict["fast_gate_ms"] > 0
    package = only(verdict)
    assert (package["package"], package["version"], package["status"]) == ("pypdf", "6.19.0", "VERIFIED")
    evidence = package["evidence"]
    # C1 / C2
    assert verdict["request"]["source"] == "pip_command" and verdict["gate"]["result"] == "PERMITTED"
    # C3a: the real SHA-256 of the downloaded file against the registry digest
    assert evidence["artifact"]["rule"] == "HASH_MATCH"
    assert evidence["artifact"]["sha256"] == evidence["artifact"]["registry_sha256"] == PYPDF_SHA256
    assert sha256_file(evidence["artifact"]["path"]) == PYPDF_SHA256
    # C3b: the tree and its digest
    assert evidence["tree"]["rule"] == "TREE_BUILT" and len(evidence["tree"]["subtree_digest"]) == 64
    assert [(n["name"], n["version"], n["sha256"]) for n in evidence["tree"]["nodes"]] == [("pypdf", "6.19.0", PYPDF_SHA256)]
    # C4: the contract from the project's call sites
    assert evidence["contract"]["rule"] == "CONTRACT_INFERRED"
    assert [(c["file"], c["line"], c["symbol"]) for c in evidence["contract"]["call_sites"]] == [
        ("app/pdf_adapter.py", 7, "pypdf.apply_configuration"), ("app/pdf_adapter.py", 8, "pypdf.PdfReader")]
    # OSV
    assert [(a["name"], a["version"], a["rule"]) for a in evidence["advisories"]] == [("pypdf", "6.19.0", "NO_KNOWN_VULNERABILITY")]
    # AST scan and the guard evidence
    assert [(s["package"], s["rule"], s["python_files"]) for s in evidence["scan"]] == [("pypdf", "SCAN_COMPLETE", 59)]
    reachability = evidence["reachability"]
    assert [(s["file"], s["line"], s["sink"], s["verdict"]) for s in reachability["sinks"]] == [
        ("pypdf/filters.py", 774, "subprocess.run", "GUARD_DISABLED"), ("pypdf/filters.py", 804, "subprocess.run", "GUARD_DISABLED")]
    proof = reachability["proofs"][0]
    assert proof["id"] == "pypdf-jbig2dec-disabled" and proof["accepted"] is True and proof["guard_result"] == [774, 804]
    # The verdict is now in the cache under the 8-field key.
    assert package["cache"]["lookup"] == "MISS" and package["cache"]["stored"] is True
    fields = package["key_fields"]
    assert fields == {"ecosystem": "PyPI", "name": "pypdf", "version": "6.19.0", "artifact_sha256": PYPDF_SHA256,
                      "subtree_digest": evidence["tree"]["subtree_digest"], "contract_digest": evidence["contract"]["digest"],
                      "policy_version": verdict["policy_version"], "analyzer_version": verdict["analyzer_version"]}
    assert lookup(world.store, fields)["hit"] is True
    assert len(world.index.downloads()) == 1


def test_the_same_project_with_a_reader_outside_the_guard_is_unresolved_and_escalated(world):
    adapter = world.project / "app" / "pdf_adapter.py"
    adapter.write_text(adapter.read_text() + UNGUARDED)
    verdict = world.verify()
    assert outcome(verdict) == ("UNRESOLVED", "reachability", "SINK_REACHABLE")
    assert_metric_fields(verdict)
    assert verdict["escalation"] == ESCALATION == "deep analysis required (M2)" and verdict["escalated"] is True
    package = only(verdict)
    assert package["escalation"] == ESCALATION and package["escalated"] is True
    assert [s["verdict"] for s in package["evidence"]["reachability"]["sinks"]] == ["REACHABLE", "REACHABLE"]
    assert package["evidence"]["reachability"]["proofs"][0]["accepted"] is False
    assert "pypdf/filters.py:774" in verdict["reason"]
    # UNRESOLVED is never cached.
    assert package["cache"]["stored"] is False and world.cache_rows() == []


def test_verified_then_guard_removed_is_not_served_from_the_cache(world):
    """The fail-open this design must not have: an old VERIFIED reused after the project changed."""
    assert world.verify()["status"] == "VERIFIED"
    adapter = world.project / "app" / "pdf_adapter.py"
    adapter.write_text(adapter.read_text().replace("jbig2dec_binary=None", "jbig2dec_binary='/usr/bin/jbig2dec'"))
    verdict = world.verify()
    assert outcome(verdict) == ("UNRESOLVED", "reachability", "SINK_REACHABLE")
    assert verdict["cache_hit"] is False and verdict["escalated"] is True


# --- C2: BLOCK before any download -------------------------------------------------------------------------

@pytest.mark.parametrize("request_text, rule", [
    ("pip install reqeusts==2.31.0", "DENYLIST"),
    ("pip install left-pad==1.0", "NOT_ON_ALLOWLIST"),
    ("pip install pypdf", "NOT_PINNED"),
    ("pip install pypdf>=6", "NOT_PINNED"),
    ("pip install pypdf==5.1.0", "NOT_ON_ALLOWLIST"),
    ("pip install pypdf==6.19.0 reqeusts==1.0", "DENYLIST"),
    ("python -m pip install demo==1.0", "NOT_IN_LOCKFILE"),
])
def test_gate_block_makes_zero_downloads(world, request_text, rule):
    verdict = world.verify(request_text)
    assert outcome(verdict) == ("BLOCK", "gate", rule)
    assert world.index.calls == []  # not even the registry was asked
    assert verdict["packages"] == [] and world.cache_rows() == []
    assert not (world.tmp_path / "quarantine").exists()
    assert_metric_fields(verdict)
    assert verdict["cache_hit"] is False and verdict["escalated"] is False


@pytest.mark.parametrize("policy, rule", [(None, "POLICY_MISSING"), ({"approved_requirements": "pypdf"}, "POLICY_INVALID"), ([], "POLICY_INVALID")])
def test_missing_or_invalid_policy_is_unresolved_with_zero_downloads(world, policy, rule):
    verdict = world.verify(policy=policy)
    assert outcome(verdict) == ("UNRESOLVED", "gate", rule)
    assert world.index.calls == []
    assert_metric_fields(verdict)


@pytest.mark.parametrize("request_value, rule", [
    (None, "REQUEST_INVALID"), (5, "REQUEST_INVALID"), ({}, "REQUEST_INVALID"), ({"requirements": "pypdf"}, "CAPTURE_INCOMPLETE"),
    ("ls -la", "CAPTURE_INCOMPLETE"), ("pip download pypdf==6.19.0", "CAPTURE_INCOMPLETE"),
    ("pip install https://example.invalid/pypdf-6.19.0-py3-none-any.whl", "CAPTURE_INCOMPLETE"),
    ("pip install pypdf==6.19.0 --index-url https://example.invalid/simple", "CAPTURE_INCOMPLETE"),
    ("pip install -r missing.txt", "CAPTURE_INCOMPLETE"), ("pip install 'pypdf==6.19.0", "CAPTURE_INCOMPLETE"),
    ("pip install", "CAPTURE_INCOMPLETE"),
])
def test_requests_that_cannot_be_captured_are_unresolved_with_zero_downloads(world, request_value, rule):
    verdict = world.verify(request_value)
    assert verdict["status"] == "UNRESOLVED" and verdict["stage"] in ("capture", "gate") and verdict["rule"] == rule
    assert world.index.calls == [] and verdict["packages"] == []
    assert_metric_fields(verdict)


# --- C3a: hash mismatch -> REJECTED --------------------------------------------------------------------------

def test_one_flipped_byte_is_rejected(world):
    response = world.index.add_pypdf()
    url = next(entry["url"] for entry in response["urls"] if entry["filename"].endswith(".whl"))
    data = bytearray(PYPDF_WHEEL.read_bytes())
    data[len(data) // 2] ^= 0x01
    world.index.routes[url] = bytes(data)
    verdict = world.verify()
    assert outcome(verdict) == ("REJECTED", "artifact", "HASH_MISMATCH")
    assert_metric_fields(verdict)
    artifact = only(verdict)["evidence"]["artifact"]
    assert artifact["registry_sha256"] == PYPDF_SHA256 and artifact["sha256"] != PYPDF_SHA256
    assert artifact["sha256"] == sha256_file(artifact["path"]) and artifact["path"].endswith(".rejected")
    # Nothing after the download ran, and nothing was cached.
    assert only(verdict)["evidence"]["scan"] == [] and world.cache_rows() == []


# --- OSV: affected -> REJECTED ---------------------------------------------------------------------------------

def test_known_vulnerability_is_rejected_with_the_advisory_id(world):
    world.add("demo", "1.0", CLEAN_DEMO)
    world.write("app/uses_demo.py", USES_DEMO)
    world.advisories("demo", "1.0", [synthetic_advisory("SYNTH-0001", "demo", fixed="2.0")])
    verdict = world.verify("pip install demo==1.0")
    assert outcome(verdict) == ("REJECTED", "advisories", "KNOWN_VULNERABILITY")
    assert_metric_fields(verdict)
    assert "SYNTH-0001" in verdict["reason"]
    advisory = only(verdict)["evidence"]["advisories"][0]
    assert [match["id"] for match in advisory["affected"]] == ["SYNTH-0001"]
    # An advisory verdict is not cached: advisories change while the artifact does not.
    assert world.cache_rows() == []


def test_known_vulnerability_is_rejected_even_when_the_project_never_imports_the_package(world):
    world.add("demo", "1.0", CLEAN_DEMO)
    assert outcome(world.verify("pip install demo==1.0")) == ("UNRESOLVED", "contract", "NO_CALL_SITE_AUTHORITY")
    world.advisories("demo", "1.0", [synthetic_advisory("SYNTH-0002", "demo")])
    assert outcome(world.verify("pip install demo==1.0")) == ("REJECTED", "advisories", "KNOWN_VULNERABILITY")


def test_vulnerable_dependency_rejects_the_request(world):
    world.add("top", "1.0", {"top/__init__.py": "import helper\n\n\ndef run():\n    return helper.work()\n"}, requires=["helper>=2"])
    world.add("helper", "2.0", {"helper/__init__.py": "def work():\n    return 1\n"})
    world.write("app/uses_top.py", "import top\n\ntop.run()\n")
    clean = world.verify("pip install top==1.0")
    assert outcome(clean) == ("VERIFIED", "verdict", "ALL_CHECKS_PASSED"), clean["reason"]
    assert [(a["name"], a["rule"]) for a in only(clean)["evidence"]["advisories"]] == [
        ("helper", "NO_KNOWN_VULNERABILITY"), ("top", "NO_KNOWN_VULNERABILITY")]
    assert [s["package"] for s in only(clean)["evidence"]["scan"]] == ["helper", "top"]
    world.advisories("helper", "2.0", [synthetic_advisory("SYNTH-0003", "helper")])
    verdict = world.verify("pip install top==1.0")
    assert outcome(verdict) == ("REJECTED", "advisories", "KNOWN_VULNERABILITY") and "helper" in verdict["reason"]
    assert verdict["cache_hit"] is True


# --- UNRESOLVED on network loss ----------------------------------------------------------------------------------

def test_registry_unreachable_is_unresolved(world):
    world.index.routes[registry_url("pypdf", "6.19.0")] = TransportError("ConnectError: network is unreachable")
    verdict = world.verify()
    assert outcome(verdict) == ("UNRESOLVED", "artifact", "REGISTRY_UNAVAILABLE")
    assert_metric_fields(verdict)
    assert world.index.downloads() == [] and world.cache_rows() == []


def test_download_cut_off_is_unresolved(world):
    response = world.index.add_pypdf()
    url = next(entry["url"] for entry in response["urls"] if entry["filename"].endswith(".whl"))
    world.index.routes[url] = TransportError("ReadTimeout: timed out")
    assert outcome(world.verify()) == ("UNRESOLVED", "artifact", "DOWNLOAD_FAILED")


def test_advisories_unavailable_is_unresolved(world):
    shutil.rmtree(world.osv_dir)
    verdict = world.verify()
    assert outcome(verdict) == ("UNRESOLVED", "advisories", "ADVISORIES_UNAVAILABLE")
    assert_metric_fields(verdict)
    assert world.cache_rows() == []


def test_everything_offline_is_unresolved_not_an_exception(world):
    class Offline:
        def stream(self, url):
            raise TransportError("ConnectError: network is unreachable")
            yield b""

    verdict = world.verify(transport=Offline(), advisory_cache_dir=world.tmp_path / "empty")
    assert verdict["status"] == "UNRESOLVED" and verdict["stage"] == "artifact"


# --- the cache ------------------------------------------------------------------------------------------------------

class CountingOSV:
    """The real adapter, counting how often it is asked."""

    def __init__(self, cache_dir):
        from backend.integrations.osv_adapter import OSV
        self.real, self.calls = OSV(cache_dir), []

    def query(self, name, version, ecosystem="PyPI", live=False, max_age_days=30):
        self.calls.append((name, version))
        return self.real.query(name, version, ecosystem, live=live, max_age_days=max_age_days)


def test_second_run_is_a_cache_hit_that_still_checks_osv(world, monkeypatch):
    scans = []
    real_scan = pipeline.scan_wheel
    monkeypatch.setattr(pipeline, "scan_wheel", lambda path, knowledge=None: scans.append(str(path)) or real_scan(path, knowledge))
    osv = CountingOSV(world.osv_dir)
    first = world.verify(osv=osv)
    second = world.verify(osv=osv)
    assert outcome(first) == outcome(second) == ("VERIFIED", "verdict", "ALL_CHECKS_PASSED")
    assert (first["cache_hit"], second["cache_hit"]) == (False, True)
    assert_metric_fields(second)
    assert len(scans) == 1                                   # the AST scan ran once
    assert osv.calls == [("pypdf", "6.19.0")] * 2            # OSV was asked both times
    assert len(world.index.downloads()) == 2                 # the artifact was downloaded and hashed both times
    package = only(second)
    assert package["cache"]["lookup"] == "HIT" and package["key_fields"] == only(first)["key_fields"]
    # The cached part is marked; the fresh parts are from this run.
    assert package["evidence"]["reachability"] == only(first)["evidence"]["reachability"]
    assert package["evidence"]["analysis_from_cache"] is True and only(first)["evidence"]["analysis_from_cache"] is False
    assert package["evidence"]["artifact"]["sha256"] == PYPDF_SHA256


def test_cached_verified_turns_rejected_when_the_advisory_data_changes(world):
    assert world.verify()["status"] == "VERIFIED"
    world.advisories("pypdf", "6.19.0", [synthetic_advisory("SYNTH-0004", "pypdf", introduced="6.0", fixed="6.20.0")])
    verdict = world.verify()
    assert outcome(verdict) == ("REJECTED", "advisories", "KNOWN_VULNERABILITY")
    assert verdict["cache_hit"] is True and "SYNTH-0004" in verdict["reason"]
    assert_metric_fields(verdict)
    # The stored analysis is untouched, so the verdict follows the advisory data back.
    assert [row["status"] for row in world.cache_rows()] == ["VERIFIED"]
    world.advisories("pypdf", "6.19.0", RECORDED_6_19_0)
    again = world.verify()
    assert again["status"] == "VERIFIED" and again["cache_hit"] is True


def test_cache_hit_with_advisories_unavailable_is_unresolved(world):
    assert world.verify()["status"] == "VERIFIED"
    shutil.rmtree(world.osv_dir)
    verdict = world.verify()
    assert outcome(verdict) == ("UNRESOLVED", "advisories", "ADVISORIES_UNAVAILABLE") and verdict["cache_hit"] is True


def test_policy_change_is_a_cache_miss(world):
    first = world.verify()
    world.policy["approved_requirements"].append("another==1.0")
    second = world.verify()
    assert second["status"] == "VERIFIED" and second["cache_hit"] is False
    assert second["policy_version"] != first["policy_version"] and len(world.cache_rows()) == 2


def test_rule_change_is_a_cache_miss(world):
    first = world.verify()
    records = json.loads(json.dumps(seeds()))
    next(r for r in records if r["id"] == "BEH-PROCESS_EXEC")["data"]["python_sinks"].append("os.popen")
    second = world.verify(knowledge={"records": records})
    assert second["cache_hit"] is False and second["analyzer_version"] != first["analyzer_version"]


def test_another_project_does_not_share_the_verdict(world, tmp_path):
    assert world.verify()["status"] == "VERIFIED"
    other = tmp_path / "other_project"
    shutil.copytree(world.project, other)
    (other / "app" / "pdf_adapter.py").write_text((other / "app" / "pdf_adapter.py").read_text() + UNGUARDED)
    verdict = world.verify(project_dir=other)
    assert outcome(verdict) == ("UNRESOLVED", "reachability", "SINK_REACHABLE") and verdict["cache_hit"] is False


def test_tampered_cache_row_is_ignored_and_the_package_is_analysed_again(world):
    assert world.verify()["status"] == "VERIFIED"
    with world.store.connect() as connection:
        connection.execute("UPDATE verdict_cache SET stored_at='2020-01-01T00:00:00+00:00'")
        connection.commit()
    verdict = world.verify()
    assert verdict["status"] == "VERIFIED" and verdict["cache_hit"] is False
    assert only(verdict)["cache"]["lookup"] == "ROW_TAMPERED"


def test_without_a_store_every_run_is_a_full_analysis(world):
    first, second = world.verify(store=None), world.verify(store=None)
    assert first["status"] == second["status"] == "VERIFIED"
    assert (first["cache_hit"], second["cache_hit"]) == (False, False)
    assert only(second)["cache"]["lookup"] == "CACHE_UNAVAILABLE" and second["logged"] is False


# --- the metric fields on every status ---------------------------------------------------------------------------------

def test_metric_fields_are_present_on_every_status(world):
    world.add("demo", "1.0", CLEAN_DEMO)
    world.advisories("demo", "1.0", [synthetic_advisory("SYNTH-0005", "demo")])
    seen = {}
    for request_text in ("pip install pypdf==6.19.0", "pip install reqeusts==1.0", "pip install demo==1.0", "pip install -r nowhere.txt"):
        verdict = world.verify(request_text)
        assert_metric_fields(verdict)
        assert {"fast_gate_ms", "cache_hit", "escalated", "escalation"} <= set(verdict)
        seen[verdict["status"]] = verdict
    adapter = world.project / "app" / "pdf_adapter.py"
    adapter.write_text(adapter.read_text() + UNGUARDED)
    escalated = world.verify()
    assert_metric_fields(escalated)
    assert sorted(seen) == ["BLOCK", "REJECTED", "UNRESOLVED", "VERIFIED"] and escalated["escalated"] is True
    assert set(seen["BLOCK"]) == set(seen["VERIFIED"]) == set(seen["REJECTED"]) == set(seen["UNRESOLVED"]) == set(escalated)


def test_verdicts_are_logged_and_the_report_numbers_come_from_the_log(world):
    assert metrics(world.store) == {"verdicts": 0, "cache_hits": 0, "cache_hit_rate": None, "fast_gate_ms_p50": None,
                                    "fast_gate_ms_p95": None, "by_status": {}}
    verdicts = [world.verify(), world.verify(), world.verify("pip install reqeusts==1.0"), world.verify()]
    assert all(verdict["logged"] for verdict in verdicts)
    report = metrics(world.store)
    assert report["verdicts"] == 4 and report["cache_hits"] == 2 and report["cache_hit_rate"] == 0.5
    assert report["by_status"] == {"BLOCK": 1, "VERIFIED": 3}
    times = sorted(verdict["fast_gate_ms"] for verdict in verdicts)
    assert report["fast_gate_ms_p50"] == pytest.approx(times[1], abs=0.01) and report["fast_gate_ms_p95"] == pytest.approx(times[3], abs=0.01)
    log = world.store.get_verdict_log()
    assert [row["status"] for row in log] == ["VERIFIED", "BLOCK", "VERIFIED", "VERIFIED"]  # newest first
    assert log[0]["requested"] == "pip install pypdf==6.19.0" and log[0]["cache_hit"] == 1 and log[0]["escalated"] == 0


# --- sinks judged by the contract and by reachability --------------------------------------------------------------------

NETWORK = "import socket\n\n\ndef send(data):\n    socket.create_connection(('example.invalid', 443))\n"


def test_unreachable_sink_is_evidence_and_the_package_is_verified(world):
    world.add("demo", "1.0", {**CLEAN_DEMO, "demo/cli.py": NETWORK})
    world.write("app/uses_demo.py", USES_DEMO)
    verdict = world.verify("pip install demo==1.0")
    assert outcome(verdict) == ("VERIFIED", "verdict", "ALL_CHECKS_PASSED"), verdict["reason"]
    sinks = only(verdict)["evidence"]["reachability"]["sinks"]
    assert [(s["file"], s["line"], s["capability"], s["verdict"]) for s in sinks] == [("demo/cli.py", 5, "NETWORK_CONNECT", "UNREACHABLE")]
    assert verdict["escalated"] is False


def test_reachable_denied_sink_is_unresolved_and_escalated(world):
    world.add("demo", "1.0", {"demo/__init__.py": "from .net import send\n\n\ndef run():\n    return 1\n", "demo/net.py": NETWORK})
    world.write("app/uses_demo.py", USES_DEMO)
    verdict = world.verify("pip install demo==1.0")
    assert outcome(verdict) == ("UNRESOLVED", "reachability", "SINK_REACHABLE")
    assert verdict["escalation"] == ESCALATION and verdict["escalated"] is True and world.cache_rows() == []


def test_sink_granted_without_a_scope_limit_is_evidence(world):
    world.policy.update(project_task_description="Billing dashboard", allowed_scopes=["NETWORK_CONNECT:*"])
    world.add("demo", "1.0", {"demo/__init__.py": NETWORK + "\n\ndef run():\n    return 1\n"})
    world.write("app/uses_demo.py", USES_DEMO)
    verdict = world.verify("pip install demo==1.0")
    assert outcome(verdict) == ("VERIFIED", "verdict", "ALL_CHECKS_PASSED"), verdict["reason"]
    assert [s["verdict"] for s in only(verdict)["evidence"]["reachability"]["sinks"]] == ["ALLOWED"]


def test_sink_under_a_scoped_grant_is_unresolved_and_escalated(world):
    world.policy.update(project_task_description="Billing dashboard", allowed_scopes=["NETWORK_CONNECT:billing.example.com"])
    world.add("demo", "1.0", {"demo/__init__.py": NETWORK + "\n\ndef run():\n    return 1\n"})
    world.write("app/uses_demo.py", USES_DEMO)
    verdict = world.verify("pip install demo==1.0")
    assert outcome(verdict) == ("UNRESOLVED", "reachability", "SINK_REACHABLE") and verdict["escalated"] is True


def test_pages_read_after_the_guard_block_are_unresolved_and_escalated(world):
    """pypdf decodes a page when it is read, so a reader that leaves the block is not covered by the guard."""
    world.write("app/pdf_adapter.py", "from pypdf import PdfReader, apply_configuration\n\n\ndef extract(path):\n"
                "    with apply_configuration(jbig2dec_binary=None):\n        reader = PdfReader(path)\n"
                "    return [page.extract_text() for page in reader.pages]\n")
    verdict = world.verify()
    assert outcome(verdict) == ("UNRESOLVED", "reachability", "SINK_REACHABLE") and verdict["escalation"] == ESCALATION
    assert "used outside the guard" in only(verdict)["evidence"]["reachability"]["proofs"][0]["reason"]


def test_native_code_is_unresolved_without_escalation(world):
    world.add("native", "1.0", {"native/__init__.py": "def run():\n    return 1\n", "native/_speed.so": b"\x7fELF"})
    world.write("app/uses_native.py", "import native\n\nnative.run()\n")
    verdict = world.verify("pip install native==1.0")
    assert outcome(verdict) == ("UNRESOLVED", "scan", "COMPILED_CODE_NOT_SCANNED")
    assert verdict["escalated"] is False and verdict["escalation"] is None and world.cache_rows() == []


def test_unpinned_dependency_makes_the_tree_unresolved(world):
    world.add("top", "1.0", {"top/__init__.py": "def run():\n    return 1\n"}, requires=["helper>=2"])
    world.add("helper", "2.0", lock=False)
    world.write("app/uses_top.py", "import top\n\ntop.run()\n")
    assert outcome(world.verify("pip install top==1.0")) == ("UNRESOLVED", "tree", "CHILD_NOT_PINNED")


def test_lockfile_hash_that_differs_from_the_download_is_unresolved(world):
    lockfile = json.loads((world.project / "dependencies.lock.json").read_text())
    lockfile["packages"][0]["sha256"] = "0" * 64
    (world.project / "dependencies.lock.json").write_text(json.dumps(lockfile))
    assert outcome(world.verify()) == ("UNRESOLVED", "tree", "LOCKFILE_HASH_MISMATCH")


def test_project_without_a_lockfile(world):
    (world.project / "dependencies.lock.json").unlink()
    verdict = world.verify()
    # pypdf has no dependency on this interpreter, so nothing needs a pin; the missing lockfile is stated.
    assert verdict["status"] == "VERIFIED" and verdict["lockfile"] == {"path": str(world.project / "dependencies.lock.json"), "present": False}
    (world.project / "dependencies.lock.json").write_text("{not json")
    assert outcome(world.verify()) == ("UNRESOLVED", "gate", "LOCKFILE_INVALID")


def test_artifact_changed_between_hashing_and_scanning_is_unresolved(world, monkeypatch):
    real_build = pipeline.build_tree

    def build_then_swap(*args, **kwargs):
        tree = real_build(*args, **kwargs)
        wheel = build_wheel(world.tmp_path / "swap", "pypdf", "6.19.0", files={"pypdf/__init__.py": "x = 1\n"})
        shutil.copy(wheel, tree["nodes"][0]["path"])
        return tree

    monkeypatch.setattr(pipeline, "build_tree", build_then_swap)
    verdict = world.verify()
    assert outcome(verdict) == ("UNRESOLVED", "scan", "ARTIFACT_CHANGED") and world.cache_rows() == []


def test_project_that_cannot_be_read_is_unresolved(world):
    world.write("app/broken.py", "def broken(:\n")
    assert outcome(world.verify()) == ("UNRESOLVED", "contract", "SOURCE_NOT_PARSED")
    assert outcome(world.verify(project_dir=world.tmp_path / "nowhere")) == ("UNRESOLVED", "contract", "PROJECT_MISSING")


def test_local_version_is_unresolved_before_any_download(world):
    """The gate permits `6.19.0+local` under `pypdf==6.19.0` (PEP 440) when there is no lockfile; PyPI has no such file."""
    (world.project / "dependencies.lock.json").unlink()
    verdict = world.verify("pip install pypdf==6.19.0+local")
    assert outcome(verdict) == ("UNRESOLVED", "tree", "INVALID_REQUEST") and world.index.calls == []
    assert_metric_fields(verdict)


def test_a_fault_inside_a_stage_is_unresolved_not_an_exception(world, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(pipeline, "build_tree", broken)
    verdict = world.verify()
    assert outcome(verdict) == ("UNRESOLVED", "internal", "INTERNAL_ERROR") and "disk on fire" in verdict["reason"]
    assert_metric_fields(verdict)
    assert set(only(verdict)) == set(only(World(world.tmp_path / "second").verify())) and world.cache_rows() == []


@pytest.mark.parametrize("project_dir", [None, 5])
def test_project_directory_that_is_not_a_path_is_unresolved(world, project_dir):
    verdict = verify_request("pip install pypdf==6.19.0", project_dir, world.policy, world.store, transport=world.index)
    assert outcome(verdict) == ("UNRESOLVED", "capture", "REQUEST_INVALID") and world.index.calls == []
    assert_metric_fields(verdict)


# --- several requirements, requirements files and edits -------------------------------------------------------------------

def test_several_requirements_the_worst_one_decides(world):
    world.add("demo", "1.0", CLEAN_DEMO)
    world.write("app/uses_demo.py", USES_DEMO)
    both = world.verify("pip install pypdf==6.19.0 demo==1.0")
    assert outcome(both) == ("VERIFIED", "verdict", "ALL_CHECKS_PASSED"), both["reason"]
    assert [(p["package"], p["status"]) for p in both["packages"]] == [("pypdf", "VERIFIED"), ("demo", "VERIFIED")]
    world.advisories("demo", "1.0", [synthetic_advisory("SYNTH-0006", "demo")])
    mixed = world.verify("pip install pypdf==6.19.0 demo==1.0")
    assert outcome(mixed) == ("REJECTED", "advisories", "KNOWN_VULNERABILITY")
    assert [(p["package"], p["status"], p["cache_hit"]) for p in mixed["packages"]] == [("pypdf", "VERIFIED", True), ("demo", "REJECTED", True)]
    assert mixed["cache_hit"] is True and "demo" in mixed["reason"]


def test_requirements_file_with_the_right_hash_and_with_a_wrong_one(world):
    world.write("reqs.txt", f"pypdf==6.19.0 --hash=sha256:{PYPDF_SHA256}\n")
    assert world.verify("pip install -r reqs.txt")["status"] == "VERIFIED"
    world.write("reqs.txt", f"pypdf==6.19.0 --hash=sha256:{'0' * 64}\n")
    verdict = world.verify("pip install -r reqs.txt")
    assert outcome(verdict) == ("UNRESOLVED", "artifact", "REQUEST_HASH_MISMATCH")


def test_requirements_edit_is_verified_through_the_same_path(world):
    path = world.project / "requirements.txt"
    path.write_text("")
    before = snapshot_requirements(path)
    path.write_text("pypdf==6.19.0\n")
    verdict = world.verify({"requirements_edit": {"before": before, "after": snapshot_requirements(path)}})
    assert outcome(verdict) == ("VERIFIED", "verdict", "ALL_CHECKS_PASSED"), verdict["reason"]
    assert verdict["request"]["source"] == "requirements_edit" and only(verdict)["package"] == "pypdf"


def test_requirements_edit_that_only_removes_lines_has_nothing_to_verify(world):
    path = world.project / "requirements.txt"
    before = snapshot_requirements(path)
    path.write_text("")
    verdict = world.verify({"requirements_edit": {"before": before, "after": snapshot_requirements(path)}})
    assert outcome(verdict) == ("VERIFIED", "gate", "NOTHING_TO_VERIFY")
    assert verdict["packages"] == [] and world.index.calls == [] and verdict["cache_hit"] is False


@pytest.mark.parametrize("edit", [{}, {"before": {}, "after": {}}, {"before": None, "after": None}, "text",
                                  {"before": {"path": "a", "sha256": None, "exists": False, "error": None, "content": ""},
                                   "after": {"path": "b", "sha256": None, "exists": False, "error": None, "content": ""}}])
def test_bad_requirements_snapshots_are_unresolved_not_an_exception(world, edit):
    verdict = world.verify({"requirements_edit": edit})
    assert outcome(verdict) == ("UNRESOLVED", "capture", "CAPTURE_FAILED")
    assert world.index.calls == []


def test_a_captured_record_can_be_passed_in(world):
    from backend.cavr.capture import parse_pip_command
    record = parse_pip_command("pip install pypdf==6.19.0", cwd=world.project)
    assert world.verify(record)["status"] == "VERIFIED"
    # The record is input: one that claims to be complete but lists an unsupported entry is not trusted.
    record["unsupported"].append({"raw": "-e .", "reason": "editable", "origin": "command"})
    assert outcome(world.verify(record)) == ("UNRESOLVED", "gate", "CAPTURE_INCOMPLETE")


# --- nothing is installed or run -----------------------------------------------------------------------------------------

def test_verifying_does_not_install_or_run_the_package(world):
    marker = world.tmp_path / "ran"
    source = f"open({str(marker)!r}, 'w').close()\n\n\ndef run():\n    return 1\n"
    world.add("demo", "1.0", {"demo/__init__.py": source})
    world.write("app/uses_demo.py", USES_DEMO)
    verdict = world.verify("pip install demo==1.0")
    assert verdict["status"] == "VERIFIED", verdict["reason"]
    assert not marker.exists()
    import importlib.util
    assert importlib.util.find_spec("demo") is None  # not installed into this interpreter
    exec(compile(source, "demo/__init__.py", "exec"), {})  # really running it does create the marker
    assert marker.exists()


# --- step 12: items deferred from the batch 9-11 review ------------------------------------------------------------------

def test_the_same_line_twice_is_verified_once(world):
    verdict = world.verify("pip install pypdf==6.19.0 pypdf==6.19.0")
    assert outcome(verdict) == ("VERIFIED", "verdict", "ALL_CHECKS_PASSED"), verdict["reason"]
    assert only(verdict)["package"] == "pypdf" and len(world.index.downloads()) == 1


@pytest.mark.parametrize("lines", [
    f"pypdf==6.19.0 --hash=sha256:{PYPDF_SHA256}\npypdf==6.19.0 --hash=sha256:{'0' * 64}\n",   # the second hash is wrong
    f"pypdf==6.19.0\npypdf==6.19.0 --hash=sha256:{'0' * 64}\n",
    "pypdf==6.19.0\npypdf[crypto]==6.19.0\n",                                                 # the second line adds an extra
])
def test_one_release_asked_for_twice_in_different_ways_is_unresolved(world, lines):
    """Before step 12 the second line was skipped, so its hash and its extra were never checked."""
    world.write("reqs.txt", lines)
    verdict = world.verify("pip install -r reqs.txt")
    assert verdict["status"] == "UNRESOLVED"
    assert [(p["status"], p["rule"]) for p in verdict["packages"]] == [("VERIFIED", "ALL_CHECKS_PASSED"), ("UNRESOLVED", "DUPLICATE_REQUIREMENT")]
    assert outcome(verdict) == ("UNRESOLVED", "capture", "DUPLICATE_REQUIREMENT")
    assert_metric_fields(verdict)
    assert set(verdict["packages"][0]) == set(verdict["packages"][1])


def test_a_caller_made_record_with_an_odd_command_is_still_logged(world):
    from backend.cavr.capture import parse_pip_command
    for command in (5, None, "pip install pypdf==6.19.0", {"a": 1}):
        record = parse_pip_command("pip install pypdf==6.19.0", cwd=world.project)
        record["command"] = command
        verdict = world.verify(record)
        assert verdict["status"] == "VERIFIED" and verdict["logged"] is True
    assert len(world.store.get_verdict_log()) == 4


def test_url_passwords_do_not_reach_the_verdict_log(world):
    from backend.cavr.capture import parse_pip_command
    captured = world.verify("pip install pypdf==6.19.0 --index-url https://alice:hunter2@example.invalid/simple")
    assert captured["status"] == "UNRESOLVED" and "hunter2" not in json.dumps(captured)
    record = parse_pip_command("pip install pypdf==6.19.0", cwd=world.project)
    record["command"] = ["pip", "install", "pypdf==6.19.0", "--proxy", "http://bob:hunter2@proxy.invalid:8080"] + ["x" * 600]
    assert world.verify(record)["logged"] is True
    log = world.store.get_verdict_log()
    assert "hunter2" not in json.dumps(log) and "***@proxy.invalid" in log[0]["requested"]
    assert all(len(row["requested"]) <= pipeline.MAX_LOGGED_REQUEST for row in log)


@pytest.mark.parametrize("stored", [{"status": "VERIFIED"}, {"status": "VERIFIED", "stage": "verdict", "rule": "X", "reason": "y", "escalation": None},
                                    {"status": "REJECTED", "scan": [], "reachability": None}])
def test_a_cache_row_that_is_not_a_complete_analysis_is_a_miss_and_is_replaced(world, stored):
    from backend.cavr.verdict_cache import store as store_verdict
    first = world.verify(store=None)
    fields = only(first)["key_fields"]
    assert store_verdict(world.store, fields, stored)["stored"] is True and lookup(world.store, fields)["hit"] is True
    verdict = world.verify()
    assert outcome(verdict) == ("VERIFIED", "verdict", "ALL_CHECKS_PASSED") and verdict["cache_hit"] is False
    package = only(verdict)
    assert package["cache"]["lookup"] == "ROW_INCOMPLETE" and package["cache"]["stored"] is True
    assert package["evidence"]["analysis_from_cache"] is False and package["evidence"]["scan"] != []
    again = world.verify()
    assert again["cache_hit"] is True and only(again)["cache"]["lookup"] == "HIT"
