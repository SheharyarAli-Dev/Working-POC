"""Phase 5b (reduced PR 21) evaluation script: scripts/eval/cavr_eval.py. Offline: no Docker, no network.

What is tested: the corpus loader and its refusals, the recording transport, the stage timer, the OSV-only column,
the expected-vs-actual comparison, the summary numbers on a small hand-made raw file (clearly a fixture: its rows are
not results), CSV / markdown / SVG output, the clean-tree refusal, and one real `asent gate` run of the script's own
path on a local index with a seeded OSV cache (deep stage off), so the plumbing that the live run uses is exercised.
"""
from __future__ import annotations

import copy
import csv
import gzip
import io
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts" / "eval"))

import cavr_eval as ev  # noqa: E402
from backend.cavr.pypi_client import TransportError  # noqa: E402
from test_cavr_m2_wheels import WHEELS  # noqa: E402
from test_cavr_support import FakeIndex, build_wheel, write_osv_cache  # noqa: E402


# --- corpus -------------------------------------------------------------------------------------------------------

def corpus_file(tmp_path, items):
    path = tmp_path / "corpus.json"
    path.write_text(json.dumps({"schema": ev.CORPUS_SCHEMA, "items": items}))
    return path


def real_item(**change):
    item = {"id": "idna-3.20", "set": "clean", "kind": "pypi", "requirement": "idna==3.20", "reason": "r", "lock": {},
            "policy": {"project_task_description": "Domain names", "allowed_scopes": []}, "app": "import idna\n",
            "expected": {"status": "VERIFIED", "rule": "ALL_CHECKS_PASSED", "deep": False, "repair": None,
                         "decision": "ACCEPT", "exit_code": 0}}
    item.update(change)
    return item


def wheel_item(name="env_ci", **change):
    status, rule, decision, code = WHEELS[name][3]
    item = {"id": name, "set": "attack", "label": "attack", "kind": "wheel", "reason": "r",
            "expected": {"status": status, "rule": rule, "deep": True, "repair": None, "decision": decision, "exit_code": code}}
    item.update(change)
    return item


def test_shipped_corpus_loads_and_has_the_planned_shape():
    corpus = ev.load_corpus()
    items = corpus["items"]
    real = [i for i in items if i["kind"] == "pypi"]
    wheels = [i for i in items if i["kind"] == "wheel"]
    assert len(real) == 13 and sorted(i["id"] for i in wheels) == sorted(WHEELS)
    assert {ev.group_of(i) for i in items} == set(ev.GROUPS)
    assert sum(1 for i in real if i["set"] == "vulnerable") == 5 and sum(1 for i in real if i["set"] == "clean") == 8
    # Every child a real item's wheel needs is pinned in its lockfile, by one version.
    assert all(all("==" not in v for v in i["lock"].values()) for i in real)


@pytest.mark.parametrize("change, message", [
    ({"requirement": "idna>=3"}, "pinned with =="),
    ({"requirement": "idna==3.*"}, "pinned with =="),
    ({"requirement": "not a requirement!"}, "bad requirement"),
    ({"set": "attack"}, "synthetic wheels only"),
    ({"set": "unknown"}, "unknown set"),
    ({"reason": " "}, "needs a reason"),
    ({"lock": {"x": ""}}, "lock must map"),
    ({"policy": {"allowed_scopes": []}}, "project_task_description"),
    ({"app": None}, "needs an app file"),
    ({"expected": {"status": "VERIFIED"}}, "expected needs"),
    ({"expected": {"status": "PASS", "rule": None, "deep": False, "repair": None, "decision": "ACCEPT", "exit_code": 0}},
     "unknown expected status"),
])
def test_loader_refuses_an_ambiguous_real_item(tmp_path, change, message):
    with pytest.raises(ValueError, match=message):
        ev.load_corpus(corpus_file(tmp_path, [real_item(**change)]), wheels=WHEELS)


def test_loader_refuses_duplicates_unknown_wheels_and_changed_wheel_expectations(tmp_path):
    with pytest.raises(ValueError, match="duplicate"):
        ev.load_corpus(corpus_file(tmp_path, [real_item(), real_item()]), wheels=WHEELS)
    with pytest.raises(ValueError, match="not a wheel"):
        ev.load_corpus(corpus_file(tmp_path, [wheel_item("env_ci", id="not_a_wheel")]), wheels=WHEELS)
    changed = wheel_item()
    changed["expected"]["status"] = "UNRESOLVED"
    with pytest.raises(ValueError, match="differs from the tested"):
        ev.load_corpus(corpus_file(tmp_path, [changed]), wheels=WHEELS)
    with pytest.raises(ValueError, match="label"):
        ev.load_corpus(corpus_file(tmp_path, [wheel_item(label="clean")]), wheels=WHEELS)
    with pytest.raises(ValueError, match="not a cavr.eval-corpus.v1"):
        ev.load_corpus(_bad_schema(tmp_path), wheels=WHEELS)


def _bad_schema(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"schema": "other", "items": []}))
    return path


def test_pinned_canonicalises_the_name():
    assert ev.pinned({"requirement": "PyYAML==5.3.1"}) == ("pyyaml", "5.3.1")


# --- recording transport and stage timer ---------------------------------------------------------------------------

class Inner:
    def __init__(self, routes):
        self.routes = routes

    def stream(self, url):
        body = self.routes[url]
        if isinstance(body, Exception):
            raise body
        yield from (body[i:i + 3] for i in range(0, len(body), 3))


def test_recording_transport_passes_bytes_through_and_keeps_only_registry_bodies():
    registry, wheel = "https://pypi.org/pypi/x/1.0/json", "https://files.pythonhosted.org/packages/x-1.0-py3-none-any.whl"
    transport = ev.RecordingTransport(Inner({registry: b'{"a": 1}', wheel: b"\x00\x01wheel-bytes"}))
    transport.run = 1
    assert b"".join(transport.stream(registry)) == b'{"a": 1}'
    assert b"".join(transport.stream(wheel)) == b"\x00\x01wheel-bytes"
    record = transport.recording()
    first, second = record["fetches"]
    assert first["outcome"] == second["outcome"] == "ok" and first["run"] == 1
    assert record["bodies"] == {first["sha256"]: {"text": '{"a": 1}'}}  # the wheel is kept as its hash only
    assert second["sha256"] not in record["bodies"] and second["bytes"] == 13


def test_recording_transport_passes_errors_through_and_marks_an_early_stop():
    url = "https://pypi.org/pypi/x/9/json"
    transport = ev.RecordingTransport(Inner({url: TransportError("HTTP 404", status=404),
                                             "https://pypi.org/big": b"0123456789"}))
    with pytest.raises(TransportError):
        list(transport.stream(url))
    stream = transport.stream("https://pypi.org/big")
    next(stream)
    stream.close()  # the reader stopped (a size cap): the body is not whole and is not kept
    error, early = transport.fetches
    assert (error["outcome"], error["status"]) == ("error", 404)
    assert early["outcome"] == "incomplete" and transport.bodies == {}


def test_recording_transport_keeps_a_non_utf8_registry_body_as_base64():
    url = "https://pypi.org/pypi/x/1.0/json"
    transport = ev.RecordingTransport(Inner({url: b"\xff\xfe"}))
    list(transport.stream(url))
    assert list(transport.bodies.values()) == [{"base64": "//4="}]


def test_stage_timer_counts_nested_calls_inside_repair_as_repair_only():
    timer = ev.StageTimer()
    calls = []
    tree = timer.wrap("tree", lambda: calls.append("tree"))
    repair = timer.wrap("repair", lambda: tree())
    tree()
    repair()
    assert calls == ["tree", "tree"] and timer.calls == {"tree": 1, "repair": 1}
    ms = timer.milliseconds()
    assert ms["tree"] is not None and ms["repair"] is not None and ms["deep"] is None


def test_stage_timer_restores_the_stage_functions():
    originals = [getattr(module, name) for module, name, _ in ev.STAGE_TARGETS]
    with ev.StageTimer().installed():
        assert all(getattr(module, name).__wrapped__ is original
                   for (module, name, _), original in zip(ev.STAGE_TARGETS, originals))
    assert [getattr(module, name) for module, name, _ in ev.STAGE_TARGETS] == originals


# --- OSV-only column and comparison --------------------------------------------------------------------------------

def answer(name, version, vulns):
    query = {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
    body = {"vulns": vulns, "pages": [{"vulns": vulns}]}
    return {"query": query, "response": body, "response_sha256": ev.digest(body)}


def test_osv_only_from_recorded_answers():
    snapshot = {"a.json": answer("root", "1.0", []), "b.json": answer("child", "2.0", [{"id": "GHSA-1"}]),
                "c.json": answer("gone", "1.0", [{"id": "GHSA-2", "withdrawn": "2026-01-01"}]),
                "pkg.json": {"query": {"package": {"name": "root", "ecosystem": "PyPI"}}, "response": {"vulns": [{"id": "X"}]}}}
    assert ev.osv_only([("root", "1.0")], snapshot)["result"] == "PASS"   # the package-wide answer is not a version answer
    assert ev.osv_only([("Root", "1.0"), ("child", "2.0")], snapshot)["result"] == "VULNERABLE"  # a child counts
    assert ev.osv_only([("gone", "1.0")], snapshot)["result"] == "PASS"   # withdrawn advisories are not counted
    assert ev.osv_only([("root", "1.0"), ("missing", "1.0")], snapshot)["result"] == "NO_ANSWER"
    assert ev.osv_only([("child", "2.0"), ("missing", "1.0")], snapshot)["result"] == "VULNERABLE"
    assert ev.osv_only([], snapshot)["result"] == "NO_ANSWER"


def result(status="VERIFIED", rule="ALL_CHECKS_PASSED", stage="verdict", decision="ACCEPT", exit_code=0, deep=None,
           repair=None, cache_hit=False, timing=None, nodes=(("idna", "3.20"),), run=1):
    """One run's recorded fields, in the shape `extract` writes. A fixture, not a result."""
    timing = {stage: None for stage in ev.STAGES} | {"verify_request": 100.0, "gate_run": 1000.0} | (timing or {})
    return {"run": run, "status": status, "stage": stage, "rule": rule, "reason": "fixture", "decision": decision,
            "exit_code": exit_code, "cache_hit": cache_hit, "analysis_from_cache": cache_hit,
            "fast": {"status": status, "stage": stage, "rule": rule, "escalated": deep is not None},
            "deep": deep, "repair": repair, "artifact": {}, "advisories": [],
            "tree": {"result": "OK", "rule": "TREE_BUILT", "nodes": [{"name": n, "version": v, "sha256": None} for n, v in nodes]},
            "timing_ms": timing}


def test_compare_reports_every_difference_and_accepts_an_unpredicted_rule():
    item = real_item()
    assert ev.compare(item, result(), result(run=2)) == []
    got = ev.compare(item, result("REJECTED", "KNOWN_VULNERABILITY", decision="BLOCK", exit_code=1,
                                  repair={"result": "PROPOSED"}))
    assert any("status REJECTED" in p for p in got) and any("rule KNOWN_VULNERABILITY" in p for p in got)
    assert any("repair PROPOSED" in p for p in got) and any("decision BLOCK" in p for p in got)
    unpredicted = real_item(expected={**real_item()["expected"], "rule": None})
    assert ev.compare(unpredicted, result(rule="ANYTHING")) == []
    assert ev.compare(item, result(), result("UNRESOLVED", "X", run=2)) == [
        "run 2 gave UNRESOLVED X, run 1 VERIFIED ALL_CHECKS_PASSED"]
    assert ev.compare(item, {"run": 1, "error": "boom"}) == ["run 1 failed: boom"]
    deep = {"status": "UNRESOLVED", "rule": "X", "runs": 1, "frontier": 0, "explored": 0, "from_cache": False}
    assert ev.compare(item, result(deep=deep)) == ["deep stage ran: True != expected False"]


# --- summary on a hand-made raw file --------------------------------------------------------------------------------

def deep_of(runs, seconds, rule="DEEP_CONTRACT_VIOLATION", status="REJECTED", from_cache=False):
    return {"status": status, "rule": rule, "elapsed_seconds": seconds, "runs": runs, "frontier": runs - 1,
            "explored": runs - 1, "budget_seconds": seconds, "stop": "violation", "cause": "caused by CI=true",
            "image_id": "sha256:fixture", "budget": None, "from_cache": from_cache}


def row(name, group, first, second=None, osv="PASS"):
    item_set = "attack" if group in ev.ATTACK_LABELS else group
    return {"id": name, "set": item_set, "group": group, "kind": "wheel" if item_set == "attack" else "pypi",
            "requirement": f"{name}==1.0", "reason": "fixture",
            "expected": {"status": first["status"], "rule": first["rule"], "deep": False, "repair": None,
                         "decision": first["decision"], "exit_code": first["exit_code"]},
            "runs": [first, second or result(first["status"], first["rule"], run=2)],
            "osv_only": {"result": osv, "nodes": []}, "mismatches": []}


def fixture_raw():
    scanned = {"scan": 5.0, "tree": 50.0, "advisories": 30.0}
    items = [
        row("c-ok", "clean", result(timing=scanned), result(cache_hit=True, run=2, timing={"gate_run": 250.0})),
        row("c-native", "clean", result("UNRESOLVED", "COMPILED_CODE_NOT_SCANNED", "scan", "REVIEW", 2, timing=scanned)),
        row("c-pth", "clean", result("UNRESOLVED", "PTH_EXECUTES_CODE", "scan", "REVIEW", 2, timing=scanned)),
        row("c-deep", "clean", result("UNRESOLVED", "DEEP_SINK_NOT_EXERCISED", "deep", "REVIEW", 2,
                                      deep=deep_of(2, 8.0, "DEEP_SINK_NOT_EXERCISED", "UNRESOLVED"),
                                      timing={**scanned, "deep": 8000.0, "gate_run": 9000.0})),
        row("v-1", "vulnerable", result("REJECTED", "KNOWN_VULNERABILITY", "advisories", "BLOCK", 1,
                                        repair={"result": "PROPOSED"}, timing={"repair": 2000.0}), osv="VULNERABLE"),
        row("a-1", "attack", result("REJECTED", "DEEP_CONTRACT_VIOLATION", "deep", "BLOCK", 1, deep=deep_of(2, 9.0),
                                    timing={**scanned, "deep": 9000.0, "gate_run": 10000.0}),
            result("REJECTED", "DEEP_CONTRACT_VIOLATION", "deep", "BLOCK", 1, cache_hit=True, run=2,
                   deep=deep_of(2, 9.0, from_cache=True), timing={"gate_run": 1000.0})),
        row("a-2", "attack", result("UNRESOLVED", "TRIGGER_UNSIMULABLE", "deep", "REVIEW", 2,
                                    deep=deep_of(1, 6.0, "TRIGGER_UNSIMULABLE", "UNRESOLVED"), timing={**scanned, "deep": 6000.0})),
        row("b-1", "benign_control", result("UNRESOLVED", "DEEP_RUN_BUDGET_EXHAUSTED", "deep", "REVIEW", 2,
                                            deep=deep_of(8, 40.0, "DEEP_RUN_BUDGET_EXHAUSTED", "UNRESOLVED"),
                                            timing={**scanned, "deep": 40000.0})),
        row("b-2", "benign_control", result(timing=scanned)),
    ]
    return {"schema": ev.RAW_SCHEMA, "recorded_at": "fixture", "commit": "f" * 40, "expectations_commit": "e" * 40,
            "working_tree": "clean (tracked files)", "corpus_sha256": "0" * 64, "image_id": "sha256:fixture",
            "docker_version": "fixture", "platform": "fixture", "python": "fixture", "containers_left": [],
            "command": "fixture", "subset": None, "items": items}


def test_summary_counts_detection_and_the_clean_set_cost():
    summary = ev.summarise(fixture_raw())
    assert summary["counts"]["clean"] == {"VERIFIED": 1, "REJECTED": 0, "UNRESOLVED": 3, "BLOCK": 0, "total": 4, "error": 0}
    assert summary["detection"]["vulnerable"] == {"rejected": 1, "total": 1}
    assert summary["detection"]["attack"] == {"rejected": 1, "unresolved": 1, "passed": 0, "total": 2}
    assert summary["detection"]["benign_control"] == {"verified": 1, "total": 2}
    assert summary["clean"] | {} == {"total": 4, "false_rejected": 0, "unresolved": 3, "verified": 1,
                                     "false_rejected_rate": 0.0, "unresolved_rate": 0.75}
    assert summary["unresolved_by_reason"]["clean"] == {"compiled code": 1, ".pth file": 1, "unsimulable trigger": 0,
                                                        "sink not exercised": 1, "budget": 0, "other": 0}
    assert summary["unresolved_by_reason"]["overall"]["unsimulable trigger"] == 1
    assert summary["unresolved_by_reason"]["overall"]["budget"] == 1
    assert summary["osv_only"]["vulnerable"]["VULNERABLE"] == 1 and summary["osv_only"]["attack"]["PASS"] == 2


def test_summary_timing_deep_and_cache():
    summary = ev.summarise(fixture_raw())
    deep_times = summary["timing_ms"][1]["deep"]
    assert deep_times == {"count": 4, "p50": 8000.0, "p95": 40000.0}  # nearest rank over 6000, 8000, 9000, 40000
    assert summary["timing_ms"][1]["repair"]["count"] == 1 and summary["timing_ms"][1]["cache_lookup"]["count"] == 0
    deep = summary["deep"]
    assert (deep["activated"], deep["reached_scan"]) == (4, 8) and deep["activation_rate"] == round(4 / 9, 4)
    assert (deep["runs_used"], deep["runs_limit"], deep["runs_max"]) == (13, 32, 8)
    cache = summary["cache"]
    assert cache["hits"] == 2 and cache["speedup_p50_hits"] == 4.0   # 1000/250 and 10000/1000 -> nearest-rank median 4.0
    assert cache["speedup_p50_misses"] == 1.0


def test_summary_leaves_out_items_whose_first_run_failed():
    raw = fixture_raw()
    raw["items"].append({**row("broken", "clean", result()), "runs": [{"run": 1, "error": "boom"}, {"run": 2, "error": "boom"}],
                         "mismatches": ["run 1 failed: boom"]})
    summary = ev.summarise(raw)
    assert summary["counts"]["clean"]["total"] == 4 and summary["mismatches"] == {"broken": ["run 1 failed: boom"]}
    assert summary["counts"]["clean"]["error"] == 1  # left out of the rates, but counted where the table shows it
    assert "| Clean | 1 | 0 | 3 | 0 | 4 | 1 |" in ev.md_tables(raw, summary)


@pytest.mark.parametrize("values, p50, p95", [([], None, None), ([7.0], 7.0, 7.0), ([1, 2, 3, 4], 2, 4),
                                              ([None, 3.0, 1.0], 1.0, 3.0)])
def test_nearest_rank(values, p50, p95):
    assert (ev.nearest_rank(values, 50), ev.nearest_rank(values, 95)) == (p50, p95)


# --- outputs --------------------------------------------------------------------------------------------------------

def test_csv_has_one_row_per_item_and_round_trips():
    raw = fixture_raw()
    rows = list(csv.DictReader(io.StringIO(ev.write_csv(raw))))
    assert [r["id"] for r in rows] == [i["id"] for i in raw["items"]] and list(rows[0]) == list(ev.CSV_COLUMNS)
    native = next(r for r in rows if r["id"] == "c-native")
    assert (native["status"], native["rule"], native["deep_status"], native["run1_scan_ms"]) == (
        "UNRESOLVED", "COMPILED_CODE_NOT_SCANNED", "", "5.0")


def test_markdown_blocks_replace_only_their_content():
    text = "intro\n<!-- cavr-eval:begin tables -->\nold\n<!-- cavr-eval:end tables -->\nhand-written findings\n"
    filled = ev.fill_markdown(text, {"tables": "new"})
    assert filled == "intro\n<!-- cavr-eval:begin tables -->\nnew\n<!-- cavr-eval:end tables -->\nhand-written findings\n"
    assert ev.fill_markdown(filled, {"tables": "new"}) == filled
    with pytest.raises(ValueError, match="exactly one"):
        ev.fill_markdown("no markers", {"tables": "x"})
    with pytest.raises(ValueError, match="exactly one"):
        ev.fill_markdown(text + text, {"tables": "x"})


def test_markdown_tables_name_every_item_and_the_expectations_commit():
    raw = fixture_raw()
    summary = ev.summarise(raw)
    tables = ev.md_tables(raw, summary)
    assert all(f"`{i['id']}`" in tables for i in raw["items"]) and "UNRESOLVED by reason" in tables
    assert "e" * 40 in ev.md_environment(raw)
    attack = ev.md_attack_vs_osv(raw, summary)
    assert "`a-1`" in attack and "`b-1`" in attack and "`c-ok`" not in attack


@pytest.mark.parametrize("chart", [ev.svg_verdicts, ev.svg_stage_times])
def test_svg_charts_are_self_contained_and_deterministic(chart):
    summary = ev.summarise(fixture_raw())
    text = chart(summary)
    root = ET.fromstring(text)
    ns = "{http://www.w3.org/2000/svg}"
    assert root.find(f"{ns}title").text and root.find(f"{ns}desc").text
    assert not list(root.iter(f"{ns}script"))
    assert "href" not in text and "http://" not in text.replace("http://www.w3.org/2000/svg", "")
    assert chart(copy.deepcopy(summary)) == text


def test_verdict_chart_has_one_bar_per_non_zero_count():
    summary = ev.summarise(fixture_raw())
    root = ET.fromstring(ev.svg_verdicts(summary))
    bars = [r for r in root.iter("{http://www.w3.org/2000/svg}rect") if r.find("{http://www.w3.org/2000/svg}title") is not None]
    expected = sum(1 for g in ev.GROUPS for s in ev.STATUSES if summary["counts"][g][s])
    assert len(bars) == expected


def test_report_writes_every_output_and_keeps_hand_written_text(tmp_path):
    (tmp_path / ev.RAW_NAME).write_text(json.dumps(fixture_raw()))
    ev.report(tmp_path)
    md = (tmp_path / ev.MD_NAME).read_text()
    (tmp_path / ev.MD_NAME).write_text(md.replace("(written by hand)", "Small corpus."))
    ev.report(tmp_path)
    again = (tmp_path / ev.MD_NAME).read_text()
    assert "Small corpus." in again and again.index("Attack set: CAVR against") < again.index("## Limitations")
    for name in (ev.CSV_NAME, ev.VERDICT_SVG, ev.STAGE_SVG):
        assert (tmp_path / name).stat().st_size > 0


def test_gzip_recordings_are_byte_stable(tmp_path):
    ev.write_gz(tmp_path / "a.json.gz", {"b": 1, "a": [1]})
    ev.write_gz(tmp_path / "b.json.gz", {"a": [1], "b": 1})
    assert (tmp_path / "a.json.gz").read_bytes() == (tmp_path / "b.json.gz").read_bytes()
    assert ev.read_gz(tmp_path / "a.json.gz") == {"a": [1], "b": 1}
    assert gzip.decompress((tmp_path / "a.json.gz").read_bytes()).startswith(b"{")


def test_run_refuses_a_dirty_tree(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "f").write_text("1")
    env = ["-c", "user.email=t@example.invalid", "-c", "user.name=t"]
    subprocess.run(["git", "-C", str(tmp_path), *env, "add", "f"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), *env, "commit", "-qm", "x"], check=True)
    ev.require_clean_tree(tmp_path)
    (tmp_path / "f").write_text("2")
    with pytest.raises(SystemExit, match="clean working tree"):
        ev.require_clean_tree(tmp_path)


# --- the script's own gate path, offline ----------------------------------------------------------------------------

def offline_world(index, osv):
    return {"transport": ev.RecordingTransport(index), "advisory_cache_dir": osv, "live_advisories": False, "deep": None,
            "osv_dir": osv}


def test_a_real_item_through_the_scripts_gate_path_offline(tmp_path):
    """The path the live run takes for a real item (repo, lockfile, policy, app, two gate runs, recording, OSV-only),
    on a local index with a seeded OSV cache instead of PyPI and OSV, and with the deep stage off."""
    item = real_item(id="tiny-1.0", requirement="tiny==1.0", lock={"leaf": "2.0"},
                     app="import tiny\n\n\ndef go():\n    return tiny.run()\n")
    index = FakeIndex()
    index.add("tiny", "1.0", build_wheel(tmp_path / "wheels", "tiny", "1.0", files={"tiny/__init__.py": "def run():\n    return 1\n"},
                                         requires=("leaf>=1",)))
    index.add("leaf", "2.0", build_wheel(tmp_path / "wheels", "leaf", "2.0", files={"leaf/__init__.py": "X = 1\n"}))
    osv = tmp_path / "osv"
    write_osv_cache(osv, "tiny", "1.0", [])
    write_osv_cache(osv, "leaf", "2.0", [{"id": "SYNTH-1", "affected": [{"package": {"name": "leaf", "ecosystem": "PyPI"},
                                                                         "versions": ["2.0"]}]}])
    world = offline_world(index, osv)
    repo = ev.make_repo(item, tmp_path / "w")
    first = ev.gate_once(item, repo, tmp_path / "w", world, 1)
    second = ev.gate_once(item, repo, tmp_path / "w", world, 2)
    # The leaf's seeded advisory rejects the tree; the OSV-only column sees it through the child as well.
    assert (first["status"], first["stage"], first["rule"], first["decision"], first["exit_code"]) == (
        "REJECTED", "advisories", "KNOWN_VULNERABILITY", "BLOCK", 1)
    assert {n["name"] for n in first["tree"]["nodes"]} == {"tiny", "leaf"} and first["deep"] is None
    assert first["repair"]["result"] in ("NO_REPAIR_FOUND", "PROPOSED", "NOT_ATTEMPTED")
    timing = first["timing_ms"]
    assert all(timing[s] is not None for s in ("requirement_gate", "tree", "contract", "cache_lookup", "advisories", "repair"))
    assert timing["scan"] is None and timing["deep"] is None and timing["gate_run"] >= timing["verify_request"]
    assert second["status"] == "REJECTED" and second["cache_hit"] is False  # an advisory REJECTED is never cached
    baseline = ev.osv_only(ev.tree_nodes(first, item), ev.osv_snapshot(osv))
    assert baseline["result"] == "VULNERABLE" and [n["result"] for n in baseline["nodes"] if n["name"] == "leaf"] == ["VULNERABLE"]
    record = world["transport"].recording()
    assert {f["run"] for f in record["fetches"]} == {1, 2} and record["bodies"]
    downloads = {f["sha256"] for f in record["fetches"] if "files.pythonhosted.org" in f["url"] and f["run"] == 1}
    assert {n["sha256"] for n in first["tree"]["nodes"]} <= downloads


def test_a_verified_item_hits_the_cache_on_the_second_run(tmp_path):
    item = real_item(id="tiny-1.0", requirement="tiny==1.0", app="import tiny\n\n\ndef go():\n    return tiny.run()\n")
    index = FakeIndex()
    index.add("tiny", "1.0", build_wheel(tmp_path / "wheels", "tiny", "1.0", files={"tiny/__init__.py": "def run():\n    return 1\n"}))
    osv = tmp_path / "osv"
    write_osv_cache(osv, "tiny", "1.0", [])
    world = offline_world(index, osv)
    repo = ev.make_repo(item, tmp_path / "w")
    first = ev.gate_once(item, repo, tmp_path / "w", world, 1)
    second = ev.gate_once(item, repo, tmp_path / "w", world, 2)
    assert (first["status"], first["rule"], first["cache_hit"]) == ("VERIFIED", "ALL_CHECKS_PASSED", False)
    assert (second["status"], second["cache_hit"]) == ("VERIFIED", True)
    assert first["timing_ms"]["scan"] is not None and second["timing_ms"]["scan"] is None
    assert ev.compare(item, first, second) == []


def test_a_synthetic_wheel_through_the_scripts_gate_path_without_docker(tmp_path):
    """The wheel path (the test's local index, seeded OSV); without a deep analyzer it stays the escalated UNRESOLVED."""
    item = wheel_item("env_ci")
    world = ev.live_world(item, tmp_path / "w")
    world["deep"] = None
    repo = ev.make_repo(item, tmp_path / "w")
    first = ev.gate_once(item, repo, tmp_path / "w", world, 1)
    assert (first["status"], first["fast"]["escalated"], first["deep"]) == ("UNRESOLVED", True, None)
    assert ev.compare(item, first) == ["status UNRESOLVED != expected REJECTED", "rule SINK_REACHABLE != expected "
                                       "DEEP_CONTRACT_VIOLATION", "deep stage ran: False != expected True",
                                       "decision REVIEW != expected BLOCK", "exit_code 2 != expected 1"]


def test_run_report_and_check_end_to_end_offline(tmp_path):
    """`run` (one wheel, no Docker, the deep stage off), then `report` and `check` on what it wrote. The mismatch with
    the tested expectation (no deep stage here) is recorded and gives exit code 3, never a changed expectation."""
    def world_for(item, workdir):
        world = ev.live_world(item, workdir)
        world["deep"] = None
        return world

    code = ev.run(tmp_path, only={"file_kube"}, allow_dirty=True, world_for=world_for, sandbox=False)
    raw = json.loads((tmp_path / ev.RAW_NAME).read_text())
    (item,) = raw["items"]
    assert code == 3 and item["mismatches"] and item["expected"]["status"] == "REJECTED"
    assert raw["subset"] == ["file_kube"] and raw["working_tree"].startswith("not checked")
    assert "expectations_commit" in raw and item["osv_only"]["result"] == "PASS"
    for name in ("pypi/file_kube.json.gz", "osv/file_kube-run1.json.gz", "osv/file_kube-run2.json.gz"):
        assert (tmp_path / "recordings" / name).is_file()
    ev.report(tmp_path)
    assert "`file_kube`" in (tmp_path / ev.MD_NAME).read_text()
    assert ev.check(tmp_path) == []
    # A recording changed after the run is found.
    path = tmp_path / "recordings" / "osv" / "file_kube-run1.json.gz"
    snapshot = ev.read_gz(path)
    first = next(iter(snapshot))
    snapshot[first]["response"]["vulns"].append({"id": "SYNTH-LATER"})
    ev.write_gz(path, snapshot)
    problems = ev.check(tmp_path)
    assert any("response_sha256 does not match" in p for p in problems)


def path_with_git_only(tmp_path):
    """A PATH directory holding only `git` (the header still asks git for the commit), so `docker` cannot be found."""
    import shutil
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "git").symlink_to(shutil.which("git"))
    return bin_dir


def header(tmp_path):
    from datetime import datetime, timezone
    return ev.environment(None, datetime.now(timezone.utc), {"items": []}, None, True)


def test_run_header_records_docker_not_available_when_the_program_is_absent(tmp_path, monkeypatch):
    """CI runner without Docker: the header says why, instead of `environment()` raising FileNotFoundError."""
    monkeypatch.setenv("PATH", str(path_with_git_only(tmp_path)))
    raw = header(tmp_path)
    assert raw["docker_version"].startswith("not available: FileNotFoundError")
    assert raw["containers_left"] is None  # unknown, not "none left"
    assert raw["commit"] == ev.git("rev-parse", "HEAD") != ""  # the rest of the header is still recorded


def test_run_header_records_docker_not_available_when_the_program_fails(tmp_path, monkeypatch):
    bin_dir = path_with_git_only(tmp_path)
    fake = bin_dir / "docker"
    fake.write_text("#!/bin/sh\necho 'Cannot connect to the Docker daemon' >&2\nexit 1\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))
    raw = header(tmp_path)
    assert raw["docker_version"] == "not available: exit code 1: Cannot connect to the Docker daemon"
    assert raw["containers_left"] is None


def test_run_refuses_an_unknown_item_id(tmp_path):
    with pytest.raises(SystemExit, match="unknown item"):
        ev.run(tmp_path, only={"no-such-item"}, allow_dirty=True, sandbox=False)


# --- defects found by the first live attempt (Step M2-22) -----------------------------------------------------------

def test_expectations_are_compared_with_the_package_rule_not_the_request_rule():
    """Defect 1: an all-VERIFIED request's rule is always ALL_CHECKS_PASSED; the wheels' tested rule is the package's."""
    item = wheel_item("driven_verify")
    deep = {"status": "VERIFIED", "rule": "DEEP_RUN_CLEAN", "runs": 1, "frontier": 0, "explored": 0, "from_cache": False}
    got = result("VERIFIED", "ALL_CHECKS_PASSED", deep=deep) | {"package_stage": "deep", "package_rule": "DEEP_RUN_CLEAN"}
    assert ev.compare(item, got, got | {"run": 2}) == []
    assert ev.decided(got) == ("deep", "DEEP_RUN_CLEAN") and ev._verdict(got) == "VERIFIED DEEP_RUN_CLEAN"
    wrong = got | {"package_rule": "DEEP_SINK_NOT_EXERCISED"}
    assert ev.compare(item, wrong) == ["rule DEEP_SINK_NOT_EXERCISED != expected DEEP_RUN_CLEAN"]
    assert ev.decided(result()) == ("verdict", "ALL_CHECKS_PASSED")  # an older row without package fields


def test_a_real_item_records_osv_answers_from_the_directory_the_gate_writes(tmp_path):
    """Defect 2: the live world's snapshot directory is the advisory cache directory the gate and repair are given."""
    world = ev.live_world(real_item(), tmp_path)
    assert world["advisory_cache_dir"] == world["osv_dir"] and world["live_advisories"] is True


def test_an_osv_answer_used_but_not_recorded_is_reported(tmp_path):
    item = real_item(id="tiny-1.0", requirement="tiny==1.0", app="import tiny\n\n\ndef go():\n    return tiny.run()\n")
    index = FakeIndex()
    index.add("tiny", "1.0", build_wheel(tmp_path / "wheels", "tiny", "1.0", files={"tiny/__init__.py": "def run():\n    return 1\n"}))
    osv = tmp_path / "osv"
    write_osv_cache(osv, "tiny", "1.0", [])
    world = offline_world(index, osv)
    first = ev.gate_once(item, ev.make_repo(item, tmp_path / "w"), tmp_path / "w", world, 1)
    assert first["package_rule"] == "ALL_CHECKS_PASSED" and first["advisories"][0]["response_sha256"]
    assert ev.unrecorded_answers(first, ev.osv_snapshot(world["osv_dir"])) == []
    (problem,) = ev.unrecorded_answers(first, {})
    assert "tiny 1.0" in problem and "not recorded" in problem
    assert ev.unrecorded_answers({"run": 1, "error": "boom"}, {}) == []


# --- repair-screen: the diagnosis of the urllib3 repair result (Step M2-22) -----------------------------------------

PYSEC_LIKE = {"id": "PYSEC-TEST", "affected": [{"package": {"name": "urllib3", "ecosystem": "PyPI"},
              "ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "644124ec"}]},
                         {"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0"}, {"fixed": "2.0.6"},
                                                          {"introduced": "0"}, {"fixed": "1.26.17"}]}],
              "versions": ["1.26.16", "2.0.5"]}]}


@pytest.mark.parametrize("version, inside", [("2.0.5", True), ("2.0.3", True), ("1.26.0", True), ("2.0.6", False),
                                             ("1.26.17", False), ("2.8.0", False), ("1.26.16", True)])
def test_spec_affected_reads_ecosystem_ranges_in_version_order_and_ignores_git(version, inside):
    assert ev.spec_affected(PYSEC_LIKE["affected"][0], version) is inside


def test_spec_affected_last_affected_limit_and_unsorted_events():
    entry = lambda events: {"ranges": [{"type": "ECOSYSTEM", "events": events}]}
    assert ev.spec_affected(entry([{"introduced": "1.0"}, {"last_affected": "1.5"}]), "1.5") is True
    assert ev.spec_affected(entry([{"introduced": "1.0"}, {"last_affected": "1.5"}]), "1.6") is False
    assert ev.spec_affected(entry([{"introduced": "1.0"}, {"limit": "2.0"}]), "2.0") is False
    # Listed out of order: sorting puts introduced 0 first, so 2.0 is outside [0, 1.26.17).
    assert ev.spec_affected(entry([{"fixed": "1.26.17"}, {"introduced": "0"}]), "2.0") is False
    assert ev.spec_affected({"ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]}, "1.0") is False


def test_cavr_reads_a_git_plus_ecosystem_entry_as_unknown_for_every_version():
    """What the live run found (found defect D-1 in docs/evaluation/cavr-m2-evaluation.md): a GIT range next to an
    ECOSYSTEM range makes CAVR's range check UNKNOWN, also for a version the ECOSYSTEM range and `versions` exclude.
    This test records today's behaviour of `advisories.match_advisory`; it is not fixed in this branch."""
    from backend.cavr.advisories import match_advisory
    assert match_advisory("urllib3", "2.8.0", PYSEC_LIKE)["status"] == "UNKNOWN"
    assert ev.spec_affected(PYSEC_LIKE["affected"][0], "2.8.0") is False
    assert match_advisory("urllib3", "2.0.5", PYSEC_LIKE)["status"] == "AFFECTED"  # an affected version is still found


def test_repair_screen_from_recordings(tmp_path):
    vuln_in = {"id": "GHSA-IN", "affected": [{"package": {"name": "urllib3", "ecosystem": "PyPI"},
                                              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.8.0"}]}]}]}
    body = {"vulns": [vuln_in, PYSEC_LIKE], "pages": []}
    package_answer = {"query": {"package": {"name": "urllib3", "ecosystem": "PyPI"}}, "response": body,
                      "response_sha256": ev.digest(body)}
    ev.write_gz(tmp_path / "recordings" / "osv" / "u-run1.json.gz", {"package-x.json": package_answer})
    repair = {"result": "NO_REPAIR_FOUND", "excluded": [{"version": "2.7.0", "rule": "ADVISORY_AFFECTED"},
                                                        {"version": "2.8.0", "rule": "ADVISORY_RANGE_UNKNOWN"},
                                                        {"version": "3.0rc1", "rule": "PRE_RELEASE"}]}
    raw = fixture_raw()
    raw["items"] = [{**row("u", "vulnerable", result("REJECTED", "KNOWN_VULNERABILITY", repair=repair))}]
    (tmp_path / ev.RAW_NAME).write_text(json.dumps(raw))
    seven, eight = ev.repair_screen(tmp_path, "u")
    assert (seven["version"], seven["cavr_affected"], seven["spec_affected"], seven["exclusion_supported"]) == (
        "2.7.0", ["GHSA-IN"], ["GHSA-IN"], True)
    assert seven["cavr_unknown"] == ["PYSEC-TEST"] and seven["same_affected"] is True
    assert (eight["cavr_affected"], eight["cavr_unknown"], eight["exclusion_supported"]) == ([], ["PYSEC-TEST"], False)
    assert eight["advisories"]["PYSEC-TEST"]["versions_listed"] == 2


# --- the committed results (docs/evaluation/) -----------------------------------------------------------------------

EVALUATION = REPO / "docs" / "evaluation"


@pytest.mark.skipif(not (EVALUATION / ev.RAW_NAME).is_file(), reason="no recorded evaluation committed")
def test_committed_results_regenerate_byte_for_byte_and_their_recordings_check(tmp_path):
    """`report` on the committed raw JSON writes exactly the committed CSV, tables and charts; `check` finds nothing."""
    import shutil
    for name in (ev.RAW_NAME, ev.MD_NAME):
        shutil.copy(EVALUATION / name, tmp_path / name)
    shutil.copytree(EVALUATION / "recordings", tmp_path / "recordings")
    ev.report(tmp_path)
    for name in (ev.CSV_NAME, ev.MD_NAME, ev.VERDICT_SVG, ev.STAGE_SVG):
        assert (tmp_path / name).read_bytes() == (EVALUATION / name).read_bytes(), name
    assert ev.check(EVALUATION) == []


def ancestry_unavailable(*commits):
    """Why `git merge-base --is-ancestor` cannot answer here (a shallow checkout, as on CI, or a commit object not in
    this clone), or None when it can."""
    shallow = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--is-shallow-repository"], capture_output=True, text=True)
    if shallow.stdout.strip() == "true":
        return "shallow checkout (git rev-parse --is-shallow-repository = true)"
    missing = [c for c in commits if subprocess.run(["git", "-C", str(REPO), "cat-file", "-e", f"{c}^{{commit}}"],
                                                    capture_output=True).returncode != 0]
    return f"commit object(s) not in this clone: {', '.join(missing)}" if missing else None


@pytest.mark.skipif(not (EVALUATION / ev.RAW_NAME).is_file(), reason="no recorded evaluation committed")
def test_committed_results_name_the_expectations_commit_and_a_clean_tree():
    raw = json.loads((EVALUATION / ev.RAW_NAME).read_text())
    assert raw["working_tree"] == "clean (tracked files)" and raw["subset"] is None
    assert raw["expectations_commit"] and raw["commit"] and raw["image_id"].startswith("sha256:")
    # The expectations in the raw file are the corpus's as committed: never edited after the run.
    corpus = {item["id"]: item["expected"] for item in ev.load_corpus()["items"]}
    assert {row["id"]: row["expected"] for row in raw["items"]} == corpus
    assert raw["corpus_sha256"] == __import__("hashlib").sha256(ev.CORPUS.read_bytes()).hexdigest()
    why = ancestry_unavailable(raw["expectations_commit"], raw["commit"])
    if why:
        pytest.skip(f"expectations-before-run ancestry check not possible: {why} (every other assertion ran)")
    ancestor = subprocess.run(["git", "-C", str(REPO), "merge-base", "--is-ancestor", raw["expectations_commit"], raw["commit"]])
    assert ancestor.returncode == 0, "the expectations must be committed before (or in) the commit that ran"


@pytest.mark.skipif(not (EVALUATION / ev.RAW_NAME).is_file(), reason="no recorded evaluation committed")
def test_every_recorded_child_of_a_real_item_is_pinned_in_its_lockfile():
    raw = json.loads((EVALUATION / ev.RAW_NAME).read_text())
    corpus = {item["id"]: item for item in ev.load_corpus()["items"]}
    for row in raw["items"]:
        if row["kind"] != "pypi":
            continue
        item = corpus[row["id"]]
        root, version = ev.pinned(item)
        children = {(n["name"], n["version"]) for n in row["runs"][0]["tree"]["nodes"]} - {(root, version)}
        pins = {(ev.canonicalize_name(name), pin) for name, pin in item["lock"].items()}
        assert children <= pins, (row["id"], children - pins)


@pytest.mark.parametrize("value, label", [(0.01, "0.01 ms"), (0.1, "0.1 ms"), (1, "1 ms"), (100, "100 ms"),
                                          (1000, "1 s"), (100000, "100 s")])
def test_axis_ticks_are_never_rounded_to_zero(value, label):
    assert ev._tick(value) == label


# --- review of Step M2-22 -------------------------------------------------------------------------------------------

def test_summary_times_real_and_synthetic_items_apart_and_repair_attempts_alone():
    summary = ev.summarise(fixture_raw())
    by_kind = summary["timing_ms_by_kind"]
    assert by_kind["wheel"]["deep"] == {"count": 3, "p50": 9000.0, "p95": 40000.0}   # a-1, a-2, b-1 (b-2 has no deep)
    assert by_kind["pypi"]["deep"]["count"] == 1 and by_kind["pypi"]["gate_run"]["count"] == 5
    # Only v-1's repair was attempted (PROPOSED); a NOT_ATTEMPTED repair would not count.
    assert summary["repair_attempted_ms"] == {"count": 1, "p50": 2000.0, "p95": 2000.0}
    tables = ev.md_tables(fixture_raw(), summary)
    assert "repair (attempted only)" in tables and "real packages and synthetic wheels" in tables


def test_run_refuses_untracked_code(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "notes.txt").write_text("not code")
    ev.require_clean_tree(tmp_path)  # untracked files outside the code directories do not matter
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "planted.py").write_text("X = 1\n")
    with pytest.raises(SystemExit, match="untracked files where code is imported from"):
        ev.require_clean_tree(tmp_path)


def screen_fixture(tmp_path):
    vuln_in = {"id": "GHSA-IN", "affected": [{"package": {"name": "urllib3", "ecosystem": "PyPI"},
                                              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.8.0"}]}]}]}
    body = {"vulns": [vuln_in, PYSEC_LIKE], "pages": []}
    answer = {"query": {"package": {"name": "urllib3", "ecosystem": "PyPI"}}, "response": body, "response_sha256": ev.digest(body)}
    ev.write_gz(tmp_path / "recordings" / "osv" / "u-run1.json.gz", {"package-x.json": answer})
    registry = json.dumps({"info": {"name": "urllib3"}, "releases": {"2.8.0": [], "2.7.0": [], "not-a-version": [], "2.0.5": []}})
    ev.write_gz(tmp_path / "recordings" / "pypi" / "u.json.gz",
                {"fetches": [], "bodies": {"x": {"text": registry}, "y": {"text": "{not json"}}})
    repair = {"result": "NO_REPAIR_FOUND", "excluded": [{"version": "2.7.0", "rule": "ADVISORY_AFFECTED"},
                                                        {"version": "2.8.0", "rule": "ADVISORY_RANGE_UNKNOWN"}]}
    raw = fixture_raw()
    raw["items"] = [row("u", "vulnerable", result("REJECTED", "KNOWN_VULNERABILITY", repair=repair))]
    (tmp_path / ev.RAW_NAME).write_text(json.dumps(raw))
    return raw


def test_repair_screen_over_every_recorded_release(tmp_path):
    screen_fixture(tmp_path)
    assert ev.recorded_releases(tmp_path, "u") == ["2.0.5", "2.7.0", "2.8.0"]   # sorted; the invalid version left out
    every = {r["version"]: r for r in ev.repair_screen(tmp_path, "u", all_releases=True)}
    assert every["2.0.5"]["cavr_affected"] == ["GHSA-IN", "PYSEC-TEST"] and every["2.0.5"]["same_affected"] is True
    assert every["2.8.0"]["cavr_unknown"] == ["PYSEC-TEST"] and every["2.8.0"]["rule"] is None
    assert ev.repair_screen(tmp_path, "missing", all_releases=True) == []


def test_the_report_generates_the_repair_screen_tables(tmp_path):
    raw = screen_fixture(tmp_path)
    text = ev.md_repair_screens(tmp_path, raw)
    assert "#### `u`: releases repair left out on an advisory" in text
    assert "| 2.8.0 | ADVISORY_RANGE_UNKNOWN | 0 | PYSEC-TEST | 0 | **no** |" in text
    assert "equals the specification's for 3 of 3 releases" in text
    assert "| PYSEC-TEST | UNKNOWN | ECOSYSTEM+GIT | introduced 2.0.0, fixed 2.0.6, introduced 0, fixed 1.26.17 | 2 |" in text
    assert ev.md_repair_screens(tmp_path, {"items": []}) == ""
