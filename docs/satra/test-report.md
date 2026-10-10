# SATRA Verification & Test Report

## Test Suite Execution Summary

- **Total Test Cases Executed:** 75 unit tests across 11 SATRA test modules
- **Total Passed:** 75 passed (100% of SATRA unit tests)
- **Execution Platform:** Linux (Ubuntu 24.04 via WSL2) & Docker Sandbox
- **Python Version:** 3.14.4 (isolated venv `.venv-satra`)
- **Docker Image:** `asent-sandbox-app` / `asent-sandbox:local`
- **LLM Engine:** Local Ollama (`qwen2.5-coder:1.5b`)

### Breakdown by Module

| Module | Test File | Tests | Status |
|---|---|---|---|
| Ingestion & Worktrees | `tests/test_satra_ingest.py` | 25 | PASS |
| Trust & Manifest Seed | `tests/test_satra_trust_and_seed.py` | 19 | PASS |
| AST Diff Localizer | `tests/test_satra_localize.py` | 3 | PASS |
| Security Dictionary | `tests/test_satra_dictionary.py` | 3 | PASS |
| Counterfactuals & Oracle | `tests/test_satra_counterfactuals.py` | 3 | PASS |
| Hardened Docker Sandbox | `tests/test_satra_sandbox.py` | 4 | PASS |
| Ollama Adapter & Validator | `tests/test_satra_ollama_and_validator.py` | 6 | PASS |
| Decision Matrix & Repair | `tests/test_satra_decision_and_repair.py` | 4 | PASS |
| Recommit & Signed Trailers | `tests/test_satra_recommit.py` | 3 | PASS |
| Live Pipeline & Sandbox Execution | `tests/test_satra_live_pipeline.py` | 2 | PASS |
| Rule Contract & Threat Seed Sync | `tests/test_satra_rule_contract.py` | 3 | PASS |

### Frontend Verification
- TypeScript type-check and Vite production bundle (`tsc -b && vite build`) passed with 0 errors.

### Integrations & Operational Guarantees
- The live pipeline (`backend/satra/live_pipeline.py`) performs dynamic test generation with local Ollama (`qwen2.5-coder:1.5b`) verified through the 7-check validator.
- Untrusted candidate code is strictly evaluated inside hardened container sandboxes (`asent-sandbox:local` / `asent-sandbox-app`) with `--network none`, `--read-only`, and resource limits.
- Automated repair uses bounded AST repair synthesis (`backend/satra/repair_inline.py` and `backend/satra/repair.py`) re-verified inside the isolated sandbox before proposal.
- In `tests/test_integration.py`, 3 of 4 cross-module scenarios pass cleanly (`test_cavr_repair_invalidates_satra_then_reverifies` status is governed by CAVR resolution).
