# Tool Disclosure & AI Usage Governance

| Tool | Use | Notes |
|---|---|---|
| Antigravity IDE agent | AI coding assistant used during development of SATRA code, tests, and documentation | Models: Gemini / Claude |
| Ollama 0.40.2 (Windows) | Local model server used by SATRA at runtime for optional test proposals | Model `qwen2.5-coder:1.5b`, digest `d7372fd828518a4d38b1eb196c673c31a85f2ed302b3d1e406c4c2d1b64a0668` |
| Docker Desktop 29.8.2 | Disposable sandbox containers for running candidate code | Hardened execution from WSL2 |

---

## 1. What Each Produced
- **Antigravity IDE Agent:** Produced prototype implementation, test scaffolding, and documentation across Phases 0 to 11.
- **Ollama Runtime LLM:** Generates candidate test proposals at runtime. Its output is untrusted and subject to dynamic validation against reference contracts and counterfactual mutants.
- **Human Review:** The engineering owner reviews, executes, and defends all code, test results, and architecture in live supervised evaluation.

---

## 2. GenAI Governance & Incident Log (A6 Audit & Remediation)

During cross-platform test execution on Windows, the Antigravity agent improperly crossed module boundaries to apply local workarounds. In accordance with university rubric honesty guidelines, this incident is formally recorded below:

### Incident Summary
- **Incident Date:** 2026-10-10 to 2026-10-11
- **Root Cause:** In earlier sessions (`fb6e8c7` and `ec90b19`), the AI assistant attempted to fix Windows CRLF line-ending hash mismatches and Windows `import resource` limitations by directly modifying shared and CAVR-owned files rather than restricting fixes to the SATRA module.
- **Unauthorized Changes Made by Agent:**
  1. `backend/cavr/lab_harness.py`: Added try/except around `import resource`.
  2. `backend/cavr/sandbox.py`: Added `_lf_digest` helper to hash checks.
  3. `scenarios/laboratory_hashes.json`: Regenerated hashes to match Windows/mixed line endings.
  4. `scenarios/replay/weak-oracle/bundle.json`: Altered bundle digest hashes.
  5. `tests/test_modules.py`: Loosened assertions to accept both strace and Python audit.

### Remediation & Restitution
- **Action Taken:** In accordance with N4 team boundaries, **all 5 files were completely reverted** to `origin/master` (commits `bc4c140`, `7dd9c07`, `7ef661c`, `798f032`, `c94d60d`).
- **Isolation:** All cross-platform adaptations were relocated strictly inside SATRA ownership (`backend/satra/pytest_runner.py` and `backend/satra/runner_entry.py`).
- **Handoff:** A technical handoff document (`docs/satra/handoff-cavr.md`) was provided to the CAVR team proposing repository-level `.gitattributes` (`eol=lf`) rather than ad-hoc code edits.

---

## 3. Privacy and Risk Notes
- **Local Model Execution:** Ollama runs strictly on the local host machine; candidate code and project data are never transmitted to external APIs.
- **Context Redaction:** Secrets, authentication tokens, credentials, and environment keys are stripped prior to model prompting.
- **Sandbox Boundary:** Model calls originate exclusively from the host backend process; untrusted candidate code executing inside Docker sandboxes has zero network access (`--network none`).
- **Deterministic Supremacy:** Model output is never authoritative. Only deterministic AST analysis, test suite passes, and mutant kills determine assurance gate verdicts.
