# SATRA-RV Panel Action Register & Milestone Evidence

**Evaluator / Panel:** FYP-1 Mid-Term Evaluation  
**Project:** ASENT — SATRA-RV Workstream  
**Engineering Principle:** Nothing is marked "Done" without an explicit link to a real green test name or verified CI workflow run.

---

## 1. Milestone Tracking Register

| Milestone ID | Description | Evidence / Verifying Test | Status |
|---|---|---|---|
| **M1.1** | Allowlisted Commit Ingestion & Worktree Isolation | `tests/test_satra_ingest.py::test_ensure_repository_refuses_non_allowlisted` | **DONE** (Green Test) |
| **M1.2** | Cryptographic Manifest & Trusted Specification Pinning | `tests/test_satra_trust_and_seed.py::test_shipped_manifest_is_valid` | **DONE** (Green Test) |
| **M1.3** | AST Diff Localization & Guard Extraction | `tests/test_satra_localize.py::test_astscan_detects_removed_ownership_guard` | **DONE** (Green Test) |
| **M1.4** | Security Change Contracts (SCC) Derivation | `tests/test_satra_ollama_and_validator.py::test_missing_contract_produces_inconclusive_never_not_applicable` | **DONE** (Green Test) |
| **M1.5** | 8-Family Executable Security Dictionary | `tests/test_satra_dictionary.py::test_dictionary_rules_table` | **DONE** (Green Test) |
| **M1.6** | Adversarial Counterfactual AST Mutation & Oracle Defense | `tests/test_satra_counterfactuals.py::test_static_integrity_catches_broadened_assertion` | **DONE** (Green Test) |
| **M1.7** | Hardened Docker Container Sandbox (`cap-drop ALL`, no-network) | `tests/test_satra_sandbox.py::test_sandbox_network_isolated` | **DONE** (Green Test) |
| **M1.8** | Ollama LLM Test Generation & 7-Check Validator | `tests/test_satra_ollama_and_validator.py::test_killed_distinguishes_error_vs_failure` | **DONE** (Green Test) |
| **M1.9** | 7-Gate Assurance Matrix & Deterministic Bounded Repair | `tests/test_satra_decision_and_repair.py::test_decision_engine_blocks_on_weakened_oracle` | **DONE** (Green Test) |
| **M1.10** | Verified Recommit, Audit Trailers, & Append-Only Log | `tests/test_satra_recommit.py::test_audit_trail_append_only_and_tamper_detection` | **DONE** (Green Test) |
| **M1.11** | Automated CI Workflow & Test Traceability Matrix | `.github/workflows/satra-ci.yml` & `docs/satra/test-inventory.md` | **DONE** (Green CI Job) |

---

## 2. Root Cause Issue Register (Phase A Audit)

Below are the formal GitHub issues tracking root causes identified during the Phase A diagnostic session, assigned to appropriate workstream owners:

### Issue #1: CI workflow absent on feature branch
- **Owner:** `SATRA`
- **Root Cause:** GitHub Actions only triggers workflow runs if the workflow definition YAML exists on the ref being pushed. Because `.github/workflows/ci.yml` existed solely on `master`, pushes to `satra-feature` produced 0 CI runs.
- **Resolution:** Created SATRA-owned workflow `.github/workflows/satra-ci.yml` with required `satra-suite` job, step summary reporting, and test inventory freshness check.
- **Status:** **Resolved** (Commit `ae0bc59`).

### Issue #2: Tier-1 seed threat evaluation failure under Docker Desktop shim
- **Owner:** `SATRA`
- **Root Cause:** Windows Docker CLI shim in WSL PATH caused `shutil.which("docker")` to select an unintegrated Windows binary, returning exit code 1. Furthermore, seed rules imported from dynamic dictionary risked mutation pollution.
- **Resolution:** Merged PR #3 (`backend/satra/seed_rules.py`), verified Docker Desktop parity in WSL Ubuntu (21.90s), and added `@pytest.mark.skipif(win32)` for POSIX-only bash script invocation.
- **Status:** **Resolved** (Commits `7d4de6e`, `af630d1`).

### Issue #3: Cross-platform CRLF vs LF hash divergence on inert fixtures
- **Owner:** `CAVR`
- **Root Cause:** On Windows with `core.autocrlf=true`, text files are checked out with `\r\n`. Byte SHA-256 hashes differ from master's `scenarios/laboratory_hashes.json`, causing host fallback to reject valid inert fixtures.
- **Resolution:** Reverted all unauthorized shared edits. Implemented `_lf_digest` inside SATRA. Prepared formal handoff (`docs/satra/handoff-cavr.md`) recommending `.gitattributes` (`eol=lf`) and one-time re-normalization for the CAVR team.
- **Status:** **Handed Off to CAVR** (Commits `bc4c140`, `7dd9c07`, `7ef661c`, `798f032`, `c94d60d`).

### Issue #4: Docker container volume mount permissions under restricted capabilities
- **Owner:** `Shared / Infrastructure`
- **Root Cause:** When running `docker run` with `--cap-drop ALL`, container processes running as non-root cannot write to `/out` if mounted from host directories with restricted permissions (`strace: Can't fopen '/out/trace.log': Permission denied`).
- **Resolution:** Documented in CAVR handoff. SATRA runners explicitly map user flags (`-u $(id -u):$(id -g)`) and provide host-mode execution fallback.
- **Status:** **Documented & Isolated**.
