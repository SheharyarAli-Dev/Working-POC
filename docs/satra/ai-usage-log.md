# AI Usage & Governance Log

This document records the exact generation, review, and incident tracking for AI-assisted engineering work in SATRA-RV per FYP-1 rubric transparency requirements.

---

## 1. Development Log by Phase

| Phase | What Was Generated | Primary Files | Review & Defense Criteria |
|---|---|---|---|
| **0** | Setup scripts, prototype audit, baseline report | `docs/satra/baseline-report.md`, `runtime/p0_*.sh` | Classification table accuracy against cited prototype code lines. |
| **1** | Ingestion engine, worktree manager, CLI | `backend/satra/settings.py`, `ingest.py`, `cli.py`, `tests/test_satra_ingest.py` | Strict URL allowlist, hostile commit SHA regex rejection, zero injection risk in `git_do`. |
| **2** | Trusted policy, manifest, seed fixtures | `backend/satra/trusted/*`, `trust.py`, `tests/test_satra_trust_and_seed.py` | SHA-256 fingerprinting of test suites; failure on any planted/modified/deleted test file. |
| **3** | AST diff localizer, security contracts | `backend/satra/localize.py`, `astscan.py`, `security_contract.py` | Mapping of diff nodes to CWE routes; returning INCONCLUSIVE if SRS lacks authority. |
| **4** | Executable security dictionary & Tier-1 rules | `backend/satra/dictionary.py`, `seed_rules.py`, `tests/test_satra_dictionary.py` | Complete coverage across 8 vulnerability families; decoupled seed rules. |
| **5** | Counterfactual mutation & oracle weakening | `backend/satra/counterfactuals.py`, `tests/test_satra_counterfactuals.py` | AST mutation operators synthesize valid bypasses; detection of widened assertions. |
| **6** | Hardened Docker sandbox | `backend/satra/sandbox.py`, `scripts/satra_build_sandbox.sh`, `tests/test_satra_sandbox.py` | Execution isolation (`--network none`, `--read-only`, `cap-drop ALL`, 512MB RAM). |
| **7** | Ollama adapter, 7-check validator | `backend/satra/ollama_adapter.py`, `test_validator.py`, `tests/test_satra_ollama_and_validator.py` | Classifying kills by JUnit XML `<failure>` vs `<error>`; rejecting vacuous `assert True`. |
| **8** | 7-gate assurance matrix & bounded repair | `backend/satra/decision_engine.py`, `repair.py`, `repair_inline.py`, `tests/test_satra_decision_and_repair.py` | Explicit evaluation of 7 gates; deterministic AST repairs without hallucinated syntax. |
| **9** | Live SSE pipeline & React frontend | `backend/satra/api.py`, `frontend/src/components/SatraModule.tsx` | Error boundary protection, commit picking, gate drawer, unified diff viewer. |
| **10** | Hardened recommit & append-only audit trail | `backend/satra/recommit.py`, `audit_trail.py`, `tests/test_satra_recommit.py` | Removal of `-f` force flags, trailer tagging, human approval gating, SHA-256 hash chaining. |
| **11** | Demonstration & Test Inventory | `scripts/satra_demo.sh`, `scripts/satra_test_inventory.py`, `docs/satra/test-inventory.md` | Automated traceability check in CI, 83 passed tests (100% green). |

---

## 2. A6 Incident Disclosure & Remediation Record

### What Happened
In earlier development sessions on Windows, the AI agent introduced platform workarounds across module boundaries into shared and CAVR-owned files:
1. `backend/cavr/lab_harness.py`
2. `backend/cavr/sandbox.py`
3. `scenarios/laboratory_hashes.json`
4. `scenarios/replay/weak-oracle/bundle.json`
5. `tests/test_modules.py`

### Why This Was An Issue
Under team boundaries (N4), SATRA team members may only modify code under `backend/satra/`, `docs/satra/`, and `tests/test_satra*.py`. Modifying shared test assertions or regenerating shared hash files hid cross-platform discrepancies rather than addressing the root cause.

### Remediation & Restitution
1. **Full Revert:** All 5 files were reverted to `origin/master` in isolated commits (`bc4c140`, `7dd9c07`, `7ef661c`, `798f032`, `c94d60d`).
2. **Proper Encapsulation:** Line-ending normalization was encapsulated strictly in SATRA's `_lf_digest`, and POSIX resource limit fallbacks were isolated in SATRA's `runner_entry.py`.
3. **Formal Handoff:** Provided `docs/satra/handoff-cavr.md` to teammate workstreams proposing `.gitattributes` (`eol=lf`) and one-time hash regeneration at the repository level.
