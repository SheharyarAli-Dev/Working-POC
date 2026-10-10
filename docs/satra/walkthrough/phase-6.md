# Phase 6 walkthrough: Hardened Docker Sandbox Isolation

Files: `docker/sandbox.Dockerfile`, `backend/satra/pytest_runner.py`, `scripts/satra_build_sandbox.sh`, `tests/test_satra_sandbox.py`.

## Container Security Model

The SATRA execution engine runs security contract verification tests inside a hardened Docker sandbox (`asent-sandbox:local` and `asent-sandbox-app`) to safely execute candidate commits and counterfactual mutants without risking host contamination or network leaks.

| Sandbox Control | Container Flag | Security Guarantee |
|---|---|---|
| Network Lockdown | `--network none` | Completely prevents egress / ingress; all external socket connections fail closed |
| Read-Only Root | `--read-only` | Prevents filesystem modification outside designated scratch mounts |
| Capability Dropping | `--cap-drop ALL` | Drops all Linux capabilities to avoid privilege escalation |
| Non-Root Execution | `-u $(id -u):$(id -g)` | Runs tests under matching user permissions so test artifacts (`results.xml`) are cleanly readable by orchestrator |
| Ephemeral Tmpfs | `--tmpfs /tmp:rw,nosuid,size=64m` | Isolated bounded temporary filesystem for memory-only scratch files |
| Resource Bounds | `--memory 512m --cpus 1 --pids-limit 64` | Restricts CPU, RAM, and process forks to prevent fork bombs or DOS attacks |
| Execution Timeout | `timeout=40` | Process execution killed cleanly on runaway loops |

## Automated Verification

The test suite in `tests/test_satra_sandbox.py` programmatically confirms all 4 critical security properties:
1. `test_sandbox_network_isolated`: Socket connection attempts return `BLOCKED`.
2. `test_sandbox_readonly_root`: Root filesystem writes fail closed (`READONLY`).
3. `test_sandbox_tmpfs_isolated`: Tmpfs mount functions as an isolated 64MB buffer.
4. `test_sandbox_execution_timeout`: Long-running or infinite loops trigger `subprocess.TimeoutExpired`.
