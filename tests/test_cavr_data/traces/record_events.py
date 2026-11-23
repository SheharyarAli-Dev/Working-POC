"""Record the real sandbox traces that tests/test_cavr_sandbox_events.py reads (PR 7 of docs/cavr-m2-plan.md).

    CAVR_DOCKER=1 .venv/bin/python tests/test_cavr_data/traces/record_events.py

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


def main():
    assert sandbox_image.image_identity()["ok"], "build the image first: bash docker/cavr-sandbox/build.sh"
    sandbox_observe.secrets = FixedNonce
    steps = sandbox_observe.install_steps(["probe"])
    result, nodes = observe("probe", {"probe/__init__.py": PROBE})
    save("events-probe", result, steps, "sandbox_observe.observe: wheel probe 1.0 whose import does PROBE", nodes)
    steps = sandbox_observe.install_steps(["benign"])
    result, nodes = observe("benign", {"benign/__init__.py": BENIGN})
    save("events-benign", result, steps, "sandbox_observe.observe: wheel benign 1.0 (def run(): return 1)", nodes)
    steps = [sandbox_observe.step("imports", sandbox_observe.IMPORT_ARGV)]
    result = sandbox_observe.run_harness(steps, tmpfs=[sandbox_observe.SITE_TMPFS])
    save("events-baseline", result, steps, "sandbox_observe.run_harness: the empty-harness baseline (imports, no module)")


if __name__ == "__main__":
    main()
