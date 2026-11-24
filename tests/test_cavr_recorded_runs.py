"""PR 19: the recorded M2 demo runs the dashboard replays without Docker (`backend/cavr/recorded/m2-demo-runs.json`).

The file was written by `CAVR_DOCKER=1 .venv/bin/python tests/test_cavr_m2_wheels.py --record ...`: 14 real gate runs
in the CAVR sandbox. These tests do not run anything; they check that the file is what docs/cavr-demo.md says was
recorded, that it is labelled as recorded, and that it carries no host path and no canary value.
"""
import json
import re
from pathlib import Path

import pytest

from test_cavr_m2_wheels import CAUSES, RECORDED_SCHEMA, WHEELS, demo_table

REPO = Path(__file__).resolve().parents[1]
RECORDED = REPO / "backend" / "cavr" / "recorded" / "m2-demo-runs.json"
DATA = json.loads(RECORDED.read_text(encoding="utf-8"))
TEXT = RECORDED.read_text(encoding="utf-8")


def deep(name) -> dict:
    (package,) = DATA["runs"][name]["verdict"]["packages"]
    return package["evidence"]["deep"]


def test_the_file_says_what_it_is_and_when_and_where_it_was_recorded():
    assert DATA["schema"] == RECORDED_SCHEMA and DATA["label"].startswith("recorded:")
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00", DATA["recorded_at"])
    assert re.fullmatch(r"[0-9a-f]{40}", DATA["commit"]) and re.fullmatch(r"sha256:[0-9a-f]{64}", DATA["image_id"])
    assert DATA["docker_version"] and "--record" in DATA["command"] and DATA["source"].startswith("docs/cavr-demo.md")


def test_every_demo_wheel_is_recorded_once():
    assert sorted(DATA["runs"]) == sorted(WHEELS) and len(WHEELS) == 14


@pytest.mark.parametrize("name", list(WHEELS))
def test_each_recorded_run_has_the_verdict_decision_and_exit_code_the_wheel_must_give(name):
    run = DATA["runs"][name]
    status, rule, decision, exit_code = WHEELS[name][3]
    (package,) = run["verdict"]["packages"]
    assert (package["status"], deep(name)["rule"], run["decision"], run["exit_code"]) == (status, rule, decision, exit_code)
    assert run["expected"] == {"status": status, "rule": rule, "decision": decision, "exit_code": exit_code}
    assert run["verdict"]["status"] == status and package["escalation"] == "escalated: deep analysis ran"


@pytest.mark.parametrize("name", list(WHEELS))
def test_each_recorded_deep_line_is_the_line_docs_cavr_demo_md_shows(name):
    """The doc prints the line without its `CAVR deep: ` prefix."""
    row = demo_table()[name]
    assert DATA["runs"][name]["deep_line"] == "CAVR deep: " + row["deep_line"]
    assert (DATA["runs"][name]["what"], DATA["runs"][name]["policy"]) == (row["what"], row["policy"])


@pytest.mark.parametrize("name", list(WHEELS))
def test_each_recorded_graph_has_the_digest_its_evidence_names_and_the_right_cause(name):
    evidence = deep(name)["evidence"]
    graph, causal = evidence["causal_graph"], evidence["causal"]
    assert causal["digest"] == graph["digest"] and re.fullmatch(r"[0-9a-f]{64}", graph["digest"]) and not causal["error"]
    if name in CAUSES:
        assert causal["cause"].startswith(CAUSES[name]) and any(e["kind"] == "decides" for e in graph["edges"])
    else:
        assert causal["cause"] is None and not any(e["kind"] == "decides" for e in graph["edges"])


def test_every_rejected_run_has_its_real_repair_answer():
    for name, run in DATA["runs"].items():
        if run["expected"]["status"] == "REJECTED":
            assert run["repair"]["result"] == "NOT_ATTEMPTED" and run["repair"]["applied"] is False, name
            assert "deep / DEEP_CONTRACT_VIOLATION" in run["repair"]["reason"]
        else:
            assert run["repair"] is None, name


def test_the_canary_leak_is_recorded_by_its_id_only():
    leaks = [k for k in deep("canary_exfil")["evidence"]["key_events"] if k["type"] == "CANARY_EXFIL_ATTEMPT"]
    assert leaks and "file:aws-secret-key" in leaks[0]["why"]
    # No canary value (env_synthesis.canaries formats) is in the file: only ids.
    assert re.findall(r"AKIA[0-9A-F]{16}|ghp_[0-9a-f]{36}|pypi-[0-9a-f]{32}|aws_secret_access_key = ", TEXT) == []


def test_no_host_path_is_in_the_file():
    assert str(Path.home()) not in TEXT and str(REPO) not in TEXT
    # Every /home path is the sandbox's own HOME, /tmp/home.
    assert {match.start() for match in re.finditer(r"/home/", TEXT)} == {m.start() + 4 for m in re.finditer(r"/tmp/home/", TEXT)}


@pytest.mark.parametrize("name", list(WHEELS))
def test_each_recorded_graph_hashes_to_its_digest(name):
    from backend.cavr.dashboard_view import _graph_ok
    evidence = deep(name)["evidence"]
    assert _graph_ok(evidence["causal_graph"], evidence["causal"]["digest"]) is True
