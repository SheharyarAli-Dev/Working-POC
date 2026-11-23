"""PR 10 of docs/cavr-m2-plan.md: the trigger frontier, a static scan of the verified wheel (FR-12).

Every test builds a real wheel in `tmp_path` (`build_wheel`) and gives `trigger_frontier.frontier` the tree node with
the wheel's real SHA-256. Nothing is imported or run. `NOW` fixes the analysis clock so results are reproducible.
"""
import datetime
import hashlib
import json
import random

import pytest

from backend.cavr import trigger_frontier
from backend.cavr.capability_contract import vocabulary
from tests.test_cavr_support import build_wheel

NOW = datetime.datetime(2026, 11, 23, 12, 0, 0)
VOCABULARY = vocabulary()
CONNECT = "    socket.create_connection(('198.51.100.24', 443))\n"


def contract(**allowed):
    allow = [{"capability": name, "scope": scope, "status": "OPTIONAL"} for name, scope in allowed.items()]
    deny = [{"capability": name} for name in VOCABULARY if name not in allowed]
    return {"result": "OK", "rule": "CONTRACT_INFERRED", "allowed": allow, "denied": deny, "vocabulary": VOCABULARY}


DENY_ALL = contract()


def node(tmp_path, source, name="demo", version="1.0", extra=None):
    files = {f"{name}/__init__.py": source, **(extra or {})}
    wheel = build_wheel(tmp_path / "q", name, version, files=files)
    data = wheel.read_bytes()
    return {"name": name, "version": version, "filename": wheel.name, "path": str(wheel),
            "sha256": hashlib.sha256(data).hexdigest()}


def scan(tmp_path, source, the_contract=DENY_ALL, **kwargs):
    return trigger_frontier.frontier([node(tmp_path, source)], the_contract, now=NOW, **kwargs)


def only(result):
    assert result["ok"], result["reason"]
    assert len(result["entries"]) == 1, [e["predicate"] for e in result["entries"]]
    return result["entries"][0]


# --- the six test wheels of PR 10 / PR 11 ----------------------------------------------------------------------------

def test_ci_true_is_a_simulable_env_trigger(tmp_path):
    entry = only(scan(tmp_path, "import os, socket\nif os.environ.get('CI') == 'true':\n" + CONNECT))
    assert entry["families"] == ["env"] and entry["simulable"] is True
    assert entry["activation"]["env"] == {"CI": "true"} and entry["baseline_takes_it"] is False
    assert entry["sinks"][0]["capability"] == "NETWORK_CONNECT" and entry["risk"] == "high"


def test_after_a_date_is_a_simulable_time_trigger(tmp_path):
    entry = only(scan(tmp_path, "import datetime, socket\nif datetime.date.today() >= datetime.date(2027, 1, 1):\n"
                      + CONNECT))
    assert entry["families"] == ["time"] and entry["simulable"] is True
    assert entry["activation"]["time"] >= "2027-01-01T00:00:00"
    assert entry["activation"]["env"] == {} and entry["activation"]["files"] == {}


def test_kube_config_exists_is_a_simulable_file_trigger(tmp_path):
    entry = only(scan(tmp_path, "import os, socket\nif os.path.exists(os.path.expanduser('~/.kube/config')):\n"
                      + CONNECT))
    assert entry["families"] == ["file"] and entry["simulable"] is True
    assert entry["activation"]["files"] == {"/tmp/home/.kube/config": "file"}


def test_a_hostname_is_a_simulable_host_trigger(tmp_path):
    entry = only(scan(tmp_path, "import socket\nif socket.gethostname() == 'build-prod-7':\n" + CONNECT))
    assert entry["families"] == ["host"] and entry["activation"]["hostname"] == "build-prod-7"


def test_win32_platform_check_is_unsimulable_and_says_so(tmp_path):
    entry = only(scan(tmp_path, "import sys, socket\nif sys.platform == 'win32':\n" + CONNECT))
    assert entry["families"] == ["platform"] and entry["simulable"] is False and entry["activation"] is None
    assert "win32" in entry["unsimulable_reason"] and "Linux" in entry["unsimulable_reason"]


def test_reading_the_aws_key_and_sending_it_is_a_secret_read_sink(tmp_path):
    source = ("import os, socket\nif os.getenv('AWS_PROFILE') == 'prod':\n"
              "    key = open(os.path.expanduser('~/.aws/credentials')).read()\n" + CONNECT)
    entry = only(scan(tmp_path, source))
    assert {s["capability"] for s in entry["sinks"]} == {"SECRET_READ", "NETWORK_CONNECT"}


# --- each family: positive and negative --------------------------------------------------------------------------------

@pytest.mark.parametrize("test, expected", [
    ("os.getenv('CI')", {"CI": "1"}),
    ("'CI' in os.environ", {"CI": "1"}),
    ("os.environ['DEPLOY'] == 'yes'", {"DEPLOY": "yes"}),
    ("os.environ.get('MODE', '').lower() == 'prod'", {"MODE": "prod"}),
    ("os.getenv('A') == 'x' and os.getenv('B') == 'y'", {"A": "x", "B": "y"}),
    ("os.getenv('STAGE') in ('prod', 'live')", {"STAGE": "prod"}),
])
def test_env_predicates_get_the_value_that_makes_them_true(tmp_path, test, expected):
    entry = only(scan(tmp_path, f"import os, socket\nif {test}:\n" + CONNECT))
    assert entry["simulable"] and entry["activation"]["env"] == expected


def test_a_guard_without_any_family_is_an_other_guard_not_a_trigger(tmp_path):
    result = scan(tmp_path, "import socket\nDATA = [1]\nif DATA:\n" + CONNECT)
    assert result["entries"] == [] and result["other_guards_count"] == 1
    assert result["other_guards"][0]["predicate"] == "DATA"


def test_an_unguarded_sink_is_not_a_trigger(tmp_path):
    result = scan(tmp_path, "import socket\n" + CONNECT.strip() + "\n")
    assert result["entries"] == [] and result["other_guards_count"] == 0


def test_a_guarded_branch_without_a_sink_is_not_a_trigger(tmp_path):
    assert scan(tmp_path, "import os\nif os.getenv('CI'):\n    x = 1\n")["entries"] == []


@pytest.mark.parametrize("test", [
    "datetime.datetime.now() > datetime.datetime(2027, 3, 1, 9, 30)",
    "time.time() > 1798761600",
    "(datetime.date.today() - datetime.date(2026, 1, 1)).days > 400",
    "datetime.date.today() > datetime.date(2026, 6, 1) + datetime.timedelta(days=300)",
    "datetime.date.today() >= datetime.date.fromisoformat('2027-02-02')",
])
def test_time_predicates_with_constants_are_simulable(tmp_path, test):
    entry = only(scan(tmp_path, f"import datetime, socket, time\nif {test}:\n" + CONNECT))
    assert entry["families"] == ["time"] and entry["simulable"], entry["unsimulable_reason"]
    shifted = datetime.datetime.fromisoformat(entry["activation"]["time"])
    assert shifted > NOW  # every one of these lies after the analysis clock


def test_a_date_already_passed_is_taken_by_the_baseline(tmp_path):
    entry = only(scan(tmp_path, "import datetime, socket\nif datetime.date.today() > datetime.date(2020, 1, 1):\n"
                      + CONNECT))
    assert entry["simulable"] and entry["baseline_takes_it"] is True and entry["activation"]["time"] is None


def test_a_time_compared_with_a_computed_value_is_unsimulable(tmp_path):
    source = ("import os, socket, time\nif time.time() - os.path.getmtime(__file__) > 7 * 86400:\n" + CONNECT)
    entry = only(scan(tmp_path, source))
    assert entry["simulable"] is False and "time" in entry["families"]


@pytest.mark.parametrize("test, path, kind", [
    ("os.path.isfile(os.path.join(os.path.expanduser('~'), '.kube', 'config'))", "/tmp/home/.kube/config", "file"),
    ("pathlib.Path.home().joinpath('.docker').is_dir()", "/tmp/home/.docker", "dir"),
    ("(pathlib.Path.home() / '.config' / 'gh' / 'hosts.yml').exists()", "/tmp/home/.config/gh/hosts.yml", "file"),
])
def test_file_predicates_under_home_are_simulable(tmp_path, test, path, kind):
    entry = only(scan(tmp_path, f"import os, pathlib, socket\nif {test}:\n" + CONNECT))
    assert entry["activation"]["files"] == {path: kind}


def test_a_canary_file_is_there_in_every_run_so_the_baseline_takes_it(tmp_path):
    entry = only(scan(tmp_path, "import os, socket\nif os.path.exists(os.path.expanduser('~/.aws/credentials')):\n"
                      + CONNECT))
    assert entry["simulable"] and entry["baseline_takes_it"] is True


@pytest.mark.parametrize("test", ["os.path.exists('/.dockerenv')", "not os.path.exists('/.dockerenv')",
                                  "os.path.exists('/etc/kubernetes/admin.conf')"])
def test_a_file_outside_the_sandbox_home_is_unsimulable(tmp_path, test):
    entry = only(scan(tmp_path, f"import os, socket\nif {test}:\n" + CONNECT))
    assert entry["simulable"] is False and "outside the sandbox HOME" in entry["unsimulable_reason"]


@pytest.mark.parametrize("test", ["platform.node() == 'ci-runner-3'", "os.uname().nodename == 'ci-runner-3'"])
def test_other_hostname_reads_are_simulable(tmp_path, test):
    entry = only(scan(tmp_path, f"import os, platform, socket\nif {test}:\n" + CONNECT))
    assert entry["activation"]["hostname"] == "ci-runner-3"


def test_an_invalid_hostname_constant_is_unsimulable(tmp_path):
    entry = only(scan(tmp_path, "import socket\nif socket.gethostname() == 'bad_host!':\n" + CONNECT))
    assert entry["simulable"] is False and "hostname" in entry["unsimulable_reason"]


def test_getuser_is_set_through_the_login_variables(tmp_path):
    entry = only(scan(tmp_path, "import getpass, socket\nif getpass.getuser() == 'jenkins':\n" + CONNECT))
    assert entry["families"] == ["user"] and entry["activation"]["env"] == {"LOGNAME": "jenkins", "USER": "jenkins"}


@pytest.mark.parametrize("test, why", [("os.getuid() == 0", "UID 0"), ("os.geteuid() == 0", "UID 0"),
                                       ("os.getlogin() == 'admin'", "getlogin")])
def test_root_and_login_checks_are_unsimulable(tmp_path, test, why):
    entry = only(scan(tmp_path, f"import os, socket\nif {test}:\n" + CONNECT))
    assert entry["simulable"] is False and why in entry["unsimulable_reason"]


@pytest.mark.parametrize("test, argv", [("'--deploy' in sys.argv", ["-c", "--deploy"]),
                                        ("len(sys.argv) > 2", ["-c", "cavr-arg", "cavr-arg"]),
                                        ("sys.argv[1:] == ['serve']", ["-c", "serve"])])
def test_argv_predicates_are_simulable(tmp_path, test, argv):
    entry = only(scan(tmp_path, f"import sys, socket\nif {test}:\n" + CONNECT))
    assert entry["families"] == ["argv"] and entry["activation"]["argv"] == argv


@pytest.mark.parametrize("test, baseline", [("sys.platform == 'linux'", True), ("sys.platform != 'win32'", True),
                                            ("os.name == 'nt'", False), ("platform.system() == 'Darwin'", False),
                                            ("sys.platform.startswith('win')", False)])
def test_platform_checks(tmp_path, test, baseline):
    entry = only(scan(tmp_path, f"import os, platform, sys, socket\nif {test}:\n" + CONNECT))
    assert entry["families"] == ["platform"]
    assert entry["simulable"] is baseline and entry["baseline_takes_it"] is baseline
    if not baseline:
        assert "the sandbox runs Linux" in entry["unsimulable_reason"]


# --- shapes of guards ------------------------------------------------------------------------------------------------

def test_else_branch_needs_the_negated_predicate(tmp_path):
    source = "import os, socket\nif os.getenv('SAFE_MODE') == '1':\n    pass\nelse:\n" + CONNECT
    entry = only(scan(tmp_path, source))
    assert entry["guards"][0]["polarity"] is False and entry["baseline_takes_it"] is True


def test_an_early_exit_guard_covers_what_follows(tmp_path):
    source = ("import os, socket\n\ndef run():\n    if os.getenv('CI') != 'true':\n        return\n"
              "    socket.create_connection(('198.51.100.24', 443))\n")
    entry = only(scan(tmp_path, source))
    assert entry["guards"][0]["how"] == "after" and entry["activation"]["env"] == {"CI": "true"}
    assert entry["priority"]["reachability_confidence"] == 0.9 and entry["scope"] == "function run"


def test_nested_guards_are_combined(tmp_path):
    source = ("import os, socket, sys\nif os.getenv('CI'):\n    if sys.argv[-1] == 'go':\n"
              "        socket.create_connection(('198.51.100.24', 443))\n")
    entry = only(scan(tmp_path, source))
    assert [g["line"] for g in entry["guards"]] == [2, 3] and entry["families"] == ["argv", "env"]
    assert entry["activation"]["env"] == {"CI": "1"} and entry["activation"]["argv"] == ["-c", "go"]


def test_or_is_activated_by_its_simulable_side(tmp_path):
    entry = only(scan(tmp_path, "import os, sys, socket\nif sys.platform == 'win32' or os.getenv('CI') == 'true':\n"
                      + CONNECT))
    assert entry["simulable"] and entry["activation"]["env"] == {"CI": "true"}


def test_and_with_an_unsimulable_side_is_unsimulable(tmp_path):
    entry = only(scan(tmp_path, "import os, sys, socket\nif sys.platform == 'win32' and os.getenv('CI'):\n" + CONNECT))
    assert entry["simulable"] is False


def test_a_sink_in_a_function_called_from_the_branch_is_found(tmp_path):
    source = ("import os, socket\n\ndef steal():\n    helper()\n\ndef helper():\n"
              "    socket.create_connection(('198.51.100.24', 443))\n\nif os.getenv('CI'):\n    steal()\n")
    entry = only(scan(tmp_path, source))
    assert entry["sinks"][0]["via"] == "steal() -> helper()" and entry["priority"]["reachability_confidence"] == 0.8


def test_another_guard_on_the_path_lowers_the_confidence_and_is_listed(tmp_path):
    source = "import os, socket\nDATA = []\nif os.getenv('CI'):\n    if DATA:\n" + "    " + CONNECT
    entry = only(scan(tmp_path, source))
    assert entry["opaque_guards"] == [{"line": 4, "predicate": "DATA"}]
    assert entry["priority"]["reachability_confidence"] == 0.5


def test_a_variable_assigned_once_is_followed(tmp_path):
    entry = only(scan(tmp_path, "import os, socket\nci = os.getenv('CI')\nif ci == 'true':\n" + CONNECT))
    assert entry["families"] == ["env"] and entry["activation"]["env"] == {"CI": "true"}


def test_a_variable_assigned_twice_is_computed_and_unsimulable(tmp_path):
    source = "import os, socket\nci = os.getenv('CI')\nci = ci + 'x'\nif ci == 'truex':\n" + CONNECT
    entry = only(scan(tmp_path, source))
    assert entry["families"] == ["env"] and entry["simulable"] is False
    assert "assigned more than once" in entry["unsimulable_reason"]


def test_an_import_alias_is_resolved(tmp_path):
    source = ("from os import getenv as ge\nfrom datetime import date as d\nimport socket\n"
              "if ge('CI') and d.today() > d(2027, 5, 5):\n" + CONNECT)
    entry = only(scan(tmp_path, source))
    assert entry["families"] == ["env", "time"] and entry["simulable"]


@pytest.mark.parametrize("test", ["getattr(os, 'getenv')('CI')", "__import__('os').getenv('CI')",
                                  "os.getenv(''.join(['C', 'I']))", "os.getenv(chr(67) + chr(73))"])
def test_obfuscated_or_computed_reads_are_unsimulable(tmp_path, test):
    entry = only(scan(tmp_path, f"import os, socket\nif {test}:\n" + CONNECT))
    assert entry["simulable"] is False and entry["activation"] is None


def test_a_while_loop_guard_is_a_trigger(tmp_path):
    source = "import os, socket\nwhile os.getenv('CI'):\n" + CONNECT + "    break\n"
    assert only(scan(tmp_path, source))["guards"][0]["how"] == "body"


# --- risk and priority -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("allowed, risk", [({}, "high"), ({"NETWORK_CONNECT": "198.51.100.24:443"}, "medium"),
                                           ({"NETWORK_CONNECT": "*"}, "low")])
def test_risk_follows_the_contract(tmp_path, allowed, risk):
    entry = only(scan(tmp_path, "import os, socket\nif os.getenv('CI'):\n" + CONNECT, contract(**allowed)))
    assert entry["risk"] == risk


def test_an_unreadable_contract_makes_every_entry_high(tmp_path):
    entry = only(scan(tmp_path, "import os, socket\nif os.getenv('CI'):\n" + CONNECT, {"result": "UNRESOLVED"}))
    assert entry["risk"] == "high" and "cannot be read" in entry["risk_why"]


def test_the_design_high_and_low_examples_rank_as_in_section_6_3(tmp_path):
    # §6.3: an environment predicate in front of a process exec outranks one in front of an allowed network call.
    source = ("import os, socket, subprocess\nif os.getenv('LOW'):\n" + CONNECT +
              "if os.getenv('HIGH'):\n    subprocess.run(['sh', '-c', 'id'])\n")
    result = scan(tmp_path, source, contract(NETWORK_CONNECT="*"))
    assert [e["activation"]["env"] for e in result["entries"]] == [{"HIGH": "1"}, {"LOW": "1"}]
    high, low = result["entries"]
    assert (high["risk"], low["risk"]) == ("high", "low") and high["priority"]["score"] > low["priority"]["score"]
    assert set(high["priority"]) == {"sink_risk", "reachability_confidence", "novelty", "run_cost", "score", "formula"}


def test_the_same_activation_twice_halves_the_novelty_of_the_second(tmp_path):
    source = "import os, socket\nif os.getenv('CI'):\n" + CONNECT + "if os.getenv('CI'):\n" + CONNECT
    first, second = scan(tmp_path, source)["entries"]
    assert (first["priority"]["novelty"], second["priority"]["novelty"]) == (1.0, 0.5)


def test_the_frontier_is_bounded_and_counts_what_it_dropped(tmp_path):
    source = "import os, socket\n" + "".join(f"if os.getenv('V{i}'):\n" + CONNECT for i in range(10))
    result = scan(tmp_path, source, limit=4)
    assert len(result["entries"]) == 4 and result["total"] == 10
    assert result["dropped"] == {"count": 6, "by_risk": {"high": 6}}


def test_the_frontier_is_deterministic_and_does_not_depend_on_node_order(tmp_path):
    a = node(tmp_path / "a", "import os, socket\nif os.getenv('A'):\n" + CONNECT, name="alpha")
    b = node(tmp_path / "b", "import sys, socket\nif sys.platform == 'win32':\n" + CONNECT, name="beta")
    runs = []
    for _ in range(4):
        nodes = [a, b]
        random.shuffle(nodes)
        runs.append(json.dumps(trigger_frontier.frontier(nodes, DENY_ALL, now=NOW), sort_keys=True))
    assert len(set(runs)) == 1
    ids = [e["id"] for e in json.loads(runs[0])["entries"]]
    assert len(ids) == len(set(ids)) == 2 and all(len(i) == 16 for i in ids)


# --- what the frontier cannot see --------------------------------------------------------------------------------------

def test_a_wheel_whose_bytes_changed_is_artifact_changed(tmp_path):
    entry = node(tmp_path, "import os\n")
    entry["sha256"] = "0" * 64
    result = trigger_frontier.frontier([entry], DENY_ALL, now=NOW)
    assert result["ok"] is False and result["rule"] == "ARTIFACT_CHANGED" and result["entries"] == []


def test_a_source_that_cannot_be_parsed_makes_the_frontier_incomplete(tmp_path):
    good = "import os, socket\nif os.getenv('CI'):\n" + CONNECT
    result = trigger_frontier.frontier([node(tmp_path, good, extra={"demo/bad.py": "def (:\n"})], DENY_ALL, now=NOW)
    assert result["ok"] is False and result["rule"] == "FRONTIER_INCOMPLETE" and len(result["entries"]) == 1
    assert result["findings"][0]["file"] == "demo/bad.py"


def test_native_code_makes_the_frontier_incomplete(tmp_path):
    result = trigger_frontier.frontier([node(tmp_path, "x = 1\n", extra={"demo/_fast.cpython-312-x86_64-linux-gnu.so": b"\x7fELF"})],
                                       DENY_ALL, now=NOW)
    assert result["ok"] is False and result["rule"] == "FRONTIER_INCOMPLETE"


def test_no_nodes_is_not_a_complete_frontier():
    result = trigger_frontier.frontier([], DENY_ALL, now=NOW)
    assert result["ok"] is False and result["rule"] == "FRONTIER_NO_WHEEL"


# --- the check PR 12 calls: an unsimulable entry can never give VERIFIED ---------------------------------------------

def entry_of(entry_id, risk, simulable, baseline=False):
    return {"id": entry_id, "risk": risk, "simulable": simulable, "baseline_takes_it": baseline,
            "unsimulable_reason": None if simulable else "needs win32", "predicate": "p", "package": "demo",
            "file": "demo/__init__.py", "line": 1}


def frontier_of(*entries, ok=True, dropped=0):
    return {"version": trigger_frontier.VERSION, "ok": ok, "rule": "FRONTIER_COMPLETE" if ok else "FRONTIER_INCOMPLETE",
            "reason": "r", "entries": list(entries), "dropped": {"count": dropped, "by_risk": {}}}


@pytest.mark.parametrize("risk", ["high", "medium", "low"])
@pytest.mark.parametrize("explored_too", [False, True])
def test_an_unsimulable_entry_is_always_unresolved(risk, explored_too):
    found = frontier_of(entry_of("u1", risk, False), entry_of("s1", "low", True))
    out = trigger_frontier.frontier_residual(found, explored=["u1", "s1"] if explored_too else ["s1"])
    assert out["verified_possible"] is False and out["status"] == "UNRESOLVED" and out["rule"] == "TRIGGER_UNSIMULABLE"
    assert out["unsimulable"] == ["u1"]


def test_an_unsimulable_high_risk_entry_wins_over_everything_else():
    found = frontier_of(entry_of("s1", "high", True), entry_of("u1", "high", False))
    for explored in ([], ["s1"], ["s1", "u1"], ["u1"]):
        assert trigger_frontier.frontier_residual(found, explored=explored)["status"] == "UNRESOLVED"


def test_an_unexplored_simulable_entry_is_unresolved_and_a_baseline_one_is_not():
    found = frontier_of(entry_of("s1", "high", True), entry_of("b1", "high", True, baseline=True))
    out = trigger_frontier.frontier_residual(found, explored=[])
    assert out["rule"] == "TRIGGER_UNEXPLORED" and out["unexplored"] == ["s1"]
    done = trigger_frontier.frontier_residual(found, explored=["s1"])
    assert done["verified_possible"] is True and done["status"] is None and done["rule"] == "FRONTIER_EXPLORED"


@pytest.mark.parametrize("found, rule", [(None, "FRONTIER_MISSING"), ({"ok": True}, "FRONTIER_MISSING"),
                                         (frontier_of(ok=False), "FRONTIER_INCOMPLETE"),
                                         (frontier_of(dropped=3), "FRONTIER_TRUNCATED")])
def test_a_missing_incomplete_or_truncated_frontier_is_unresolved(found, rule):
    out = trigger_frontier.frontier_residual(found, explored=[])
    assert out["verified_possible"] is False and out["status"] == "UNRESOLVED" and out["rule"] == rule


def test_a_real_frontier_with_a_win32_check_cannot_give_verified(tmp_path):
    found = scan(tmp_path, "import sys, socket\nif sys.platform == 'win32':\n" + CONNECT)
    out = trigger_frontier.frontier_residual(found, explored=[e["id"] for e in found["entries"]])
    assert out["status"] == "UNRESOLVED" and out["rule"] == "TRIGGER_UNSIMULABLE"
