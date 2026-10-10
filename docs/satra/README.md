# ASENT SATRA-RV (Application-Code Security Change Assurance Engine)

SATRA-RV is the verification engine of project ASENT that analyzes incoming code changes from `Threat-Repository`, detects security regressions, tests code in hardened Docker sandboxes, verifies test oracle integrity against adversarial counterfactual mutations, leverages local Ollama LLMs with a 7-check static/dynamic validation checklist, evaluates an unbending 7-gate assurance matrix, and facilitates safe recommittal.

## Core Capabilities

1. **Commit Ingestion & Repository Allowlist (Phase 1):**
   - Validates target forge URLs against strict allowlists (`SheharyarAli-Dev/Threat-Repository`).
   - Resolves SHAs and manages isolated git worktrees for baseline and candidate comparisons.

2. **Trusted Specifications & Seed (Phase 2):**
   - Cryptographically binds baseline specifications, policies, and test suites with SHA-256 digests in `trusted.manifest.json`.

3. **AST Diff Localization & Security Contracts (Phase 3):**
   - Maps modified Python AST nodes to HTTP route endpoints, auth decorators, and database queries.
   - Formulates non-circular Security Change Contracts (`SCC-<family>-<hash>`).

4. **Executable Security Dictionary (Phase 4):**
   - 8 core vulnerability families (CWE-639 IDOR, CWE-285 Broken Role Auth, CWE-306 Missing Auth, CWE-89 SQLi, CWE-22 Path Traversal, CWE-78 Command Injection, CWE-502 Insecure Deserialization, CWE-918 SSRF).

5. **Counterfactual Mutation & Oracle Weakening Defense (Phase 5):**
   - Generates syntactic mutants in security-critical predicates.
   - Detects weakened test oracles (e.g., changing assertions from `== 403` to `in [200, 403]`).

6. **Hardened Docker Sandbox (Phase 6):**
   - Dual container execution in `asent-sandbox-app` / `asent-sandbox:local`.
   - Lockdown: `--network none`, `--read-only` root, unprivileged UID `10001`, dropped capabilities (`cap-drop ALL`), memory limit 512MB, execution timeouts.

7. **Ollama LLM Adapter & 7-Check Validator (Phase 7):**
   - Interfaces with local Ollama (`qwen2.5-coder:1.5b`).
   - Every candidate test must pass a 7-step checklist (syntax, baseline pass, counterfactual fail, locality, repeatability, zero side-effects, traceability) before inclusion.

8. **7-Gate Matrix & Bounded Repair (Phase 8):**
   - Evaluates 7 sequential gates to determine verdict: `ACCEPT`, `BLOCK`, or `REVIEW`.
   - Synthesizes bounded deterministic AST repairs for known invariant violations.

9. **Live API & Modularized React Frontend (Phase 9):**
   - Server-Sent Events (SSE) streaming live verification progress.
   - Subcomponents for commit picking, gate matrix visualization, evidence proof drawers, and unified diff inspection.

10. **Verified Safe Recommit (Phase 10):**
    - Creates local branches `satra/repair/<sha7>` with signed trailers `ASENT-Verified-By: SATRA-RV` upon operator approval.

11. **Demonstration & Verification (Phase 11):**
    - Run the complete verification demo via `scripts/satra_demo.sh`.
