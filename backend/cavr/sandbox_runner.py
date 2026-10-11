from __future__ import annotations
import hashlib
import json
import subprocess
import time
from pathlib import Path
from typing import Callable

# Absolute, so `docker run` finds the profile whatever the current directory is.
SECCOMP_PROFILE = Path(__file__).resolve().parents[2] / "docker" / "asent-seccomp.json"

class SandboxRunner:
    def __init__(self, use_gvisor: bool = False):
        self.use_gvisor = use_gvisor
        self.timeout_seconds = 30
        self.image_name = "asent-sandbox"
        self.image_digest = "sha256:7f9a2e8c1b50493817f5492d001e3b6289410ac0219582d92138a0f918e932b1"

    def get_docker_command(self, quarantine_dir: Path | str, run_id: str) -> list[str]:
        cmd = [
            "docker", "run", "--rm",
            "--network", "none",
            "--read-only",
            "--tmpfs", "/scratch:rw,noexec,nosuid,size=64m",
            "--user", "10001:10001",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--security-opt", f"seccomp={SECCOMP_PROFILE}",
            "--pids-limit", "64",
            "--memory", "256m",
            "--cpus", "0.5",
        ]
        if self.use_gvisor:
            cmd.extend(["--runtime", "runsc"])
        cmd.extend([
            "-v", f"{Path(quarantine_dir).resolve()}:/pkg:ro",
            # The image ENTRYPOINT is already `python /opt/asent/harness.py`;
            # only its argument, the package path, is passed here.
            self.image_name,
            "/pkg"
        ])
        return cmd

    def run(self, pkg_dir: Path | str, run_id: str, emit_line: Callable[[str], None] | None = None) -> dict:
        pkg_dir = Path(pkg_dir).resolve()
        docker_cmd = self.get_docker_command(pkg_dir, run_id)
        docker_cmd_str = " ".join(docker_cmd)

        container_id = hashlib.sha256(f"{run_id}-{time.time()}".encode()).hexdigest()[:12]
        logs: list[str] = []

        def log(msg: str):
            logs.append(msg)
            if emit_line:
                emit_line(msg)

        log(f"[INFO] Initializing sandbox isolation for run {run_id}...")
        log(f"[DOCKER_CMD] {docker_cmd_str}")

        has_docker = self._docker_available()

        report: dict | None = None
        timed_out = False
        start_time = time.time()

        if has_docker:
            log("[RUNNER] Docker daemon found; executing inside asent-sandbox container...")
            try:
                proc = subprocess.Popen(
                    docker_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1
                )
                raw_output = []
                while True:
                    line = proc.stdout.readline() if proc.stdout else ""
                    if not line and proc.poll() is not None:
                        break
                    if line:
                        stripped = line.strip()
                        raw_output.append(stripped)
                        log(stripped)
                    if time.time() - start_time > self.timeout_seconds:
                        proc.kill()
                        timed_out = True
                        log(f"[SECURITY_ALERT] Hard timeout of {self.timeout_seconds} seconds exceeded! Container force-killed.")
                        break
                proc.wait()
                if timed_out:
                    # A run that had to be killed did not finish. Whatever it printed before
                    # the kill, including a complete-looking report, is not read (fail closed).
                    log("[RUNNER] Run timed out; any report printed before the kill is not trusted.")
                else:
                    # Parse behavior report from output
                    full_text = "\n".join(raw_output)
                    if self._has_duplicate_markers(full_text):
                        log("[SECURITY_ALERT] More than one behavior report in container output; report not trusted.")
                    report = self._extract_report(full_text)
            except Exception as e:
                log(f"[ERROR] Docker container execution failed: {e}")

        # Fail closed: package code never runs on the host. Without a container, or
        # without a behavior report from it, nothing was observed -> UNRESOLVED.
        # observed uses the same test as the replacement below, so the two cannot disagree.
        observed = bool(report)
        if not has_docker:
            reason = "No container isolation available (docker not found); package was not executed"
            log(f"[RUNNER] {reason}. Result: UNRESOLVED.")
            report = self._unresolved_report(reason)
        elif not observed:
            reason = "Container run produced no usable behavior report (failed, killed, timed out, or malformed)"
            log(f"[RUNNER] {reason}. No host fallback. Result: UNRESOLVED.")
            report = self._unresolved_report(reason)

        # "container" only when a report really came back from one. Docker present but
        # nothing usable (launch failed, image missing, killed) is "container_failed".
        if not has_docker:
            isolation = "none"
        elif observed:
            isolation = "container"
        else:
            isolation = "container_failed"

        return {
            "run_id": run_id,
            "docker_command": docker_cmd_str,
            "container_id": f"asent-{container_id}",
            "image_digest": self.image_digest,
            "use_gvisor": self.use_gvisor,
            "observed": observed,
            "isolation": isolation,
            "timeout_seconds": self.timeout_seconds,
            "lockdown_flags": {
                "network": "none",
                "filesystem": "read-only",
                "user": "10001:10001 (non-root)",
                "capabilities": "cap-drop ALL",
                "security_opt": ["no-new-privileges", f"seccomp={SECCOMP_PROFILE}"],
                "memory": "256m",
                "cpus": "0.5",
                "tmpfs": "/scratch:rw,noexec,nosuid,size=64m"
            },
            "report": report,
            "logs": logs
        }

    def _docker_available(self) -> bool:
        try:
            res = subprocess.run(["docker", "--version"], capture_output=True, timeout=2)
            return res.returncode == 0
        except Exception:
            return False

    @staticmethod
    def _unresolved_report(reason: str) -> dict:
        # metrics is None, not zeros: zero would claim "observed, and nothing happened".
        return {
            "verdict": "UNRESOLVED",
            "hash": None,
            "test_passed": False,
            "error": reason,
            "metrics": None,
            "events": [{"type": "NOT_OBSERVED", "reason": reason}]
        }

    START_MARKER = "--- ASENT_BEHAVIOR_REPORT_START ---"
    END_MARKER = "--- ASENT_BEHAVIOR_REPORT_END ---"

    def _has_duplicate_markers(self, full_text: str) -> bool:
        return full_text.count(self.START_MARKER) > 1 or full_text.count(self.END_MARKER) > 1

    def _extract_report(self, full_text: str) -> dict | None:
        # The package shares stdout with the harness, so it can print a report of its own.
        # The harness prints exactly one; any other count means we cannot tell which is real.
        if full_text.count(self.START_MARKER) != 1 or full_text.count(self.END_MARKER) != 1:
            return None
        # END printed before START is not a report frame.
        if full_text.index(self.START_MARKER) > full_text.index(self.END_MARKER):
            return None
        try:
            json_part = full_text.split(self.START_MARKER)[1].split(self.END_MARKER)[0].strip()
            parsed = json.loads(json_part)
        except Exception:
            return None
        # Valid JSON that is not an object (a list, a string) is not a report.
        return parsed if isinstance(parsed, dict) else None
