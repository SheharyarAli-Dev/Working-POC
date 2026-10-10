# Phase 8 walkthrough: Bounded Deterministic Repair Loop & 7-Gate Matrix

Files: `backend/satra/repair.py`, `backend/satra/decision_engine.py`, `tests/test_satra_decision_and_repair.py`.

## 7-Gate Assurance Matrix

The SATRA decision engine evaluates candidate pull requests against 7 explicit sequential gates before any commit can be declared `ACCEPT`:

| Gate | Criterion | Enforcement Mechanism |
|---|---|---|
| Gate 1 | Repository Allowlist & Source Authenticity | Verified in `settings.py` against `SheharyarAli-Dev/Threat-Repository` |
| Gate 2 | Non-Circular Trusted Specification & Policy | SHA-256 verified against `trusted.manifest.json` via `trust.py` |
| Gate 3 | AST Semantic Localization | Syntactic AST traversal in `diff_localizer.py` identifies exact changed function bodies |
| Gate 4 | Security Change Contract Synthesis | Synthesizes immutable requirement contracts in `security_contract.py` |
| Gate 5 | Sandbox Baseline Pass | Hardened Docker sandbox verifies clean passing test run on baseline |
| Gate 6 | Counterfactual Oracle Discrimination | AST mutation operators test whether tests reject defects without weakened assertions |
| Gate 7 | Repeatability & Determinism | Repeated test execution guarantees lack of flakiness or non-determinism |

## Bounded Deterministic Repair Synthesis

When candidate code violates security obligations (e.g. IDOR bypass or weakened test assertions):
- `propose(root, evidence)` synthesizes a bounded deterministic patch rather than hallucinated code.
- Directly restores security boundary predicates in `app/security.py` (`can_access_invoice`).
- If tests were weakened or tampered with, restores the authoritative oracle from `backend/satra/trusted_security.py`.
- Generates reproducible, auditable evidence bundles at `artifacts/satra/<run_id>/evidence.json`.
