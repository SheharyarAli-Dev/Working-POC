# SATRA-RV System Requirements & Specification (SRS)

## 1. Engine Objective
SATRA-RV (Application-Code Security Change Assurance Engine) provides deterministic, non-circular assurance on incoming AI-authored code changes before merge.

## 2. Functional Requirements
- **FR-01 (Commit Ingestion):** Ingest commits exclusively from authorized allowlisted repositories (`SheharyarAli-Dev/Threat-Repository`). Reject unlisted repositories or malformed SHAs.
- **FR-02 (Trusted Specifications):** Cryptographically pin reference specifications, requirements, and test fixtures against SHA-256 digests in `trusted.manifest.json`.
- **FR-03 (AST Diff Localization):** Parse syntax trees of modified Python files to map exact functions, HTTP route decorators, auth predicates, and database queries.
- **FR-04 (Security Change Contracts):** Derive explicit pre/post condition obligations (`SCC-<family>-<hash>`) mapping code modifications to CWE taxonomies.
- **FR-05 (Executable Security Dictionary):** Provide executable rule fixtures across 8 core vulnerability families (IDOR, Broken Role Auth, Missing Auth, SQLi, Path Traversal, Command Injection, Insecure Deserialization, SSRF).
- **FR-06 (Adversarial Counterfactual Mutation):** Apply syntactic mutant operators to ensure test suites detect bypasses and flag test-weakening edits (where assertions are widened).
- **FR-07 (Hardened Docker Sandbox):** Execute all test harnesses inside isolated containers (`asent-sandbox-app` / `asent-sandbox:local`) with `--network none`, `--read-only` root filesystem, memory limits, and dropped privileges.
- **FR-08 (Ollama LLM Test Generation & 7-Check Validator):** Stream code generation requests to local Ollama (`qwen2.5-coder:1.5b`), enforcing a 7-step static and dynamic verification checklist before any test is admitted into evidence.
- **FR-09 (7-Gate Assurance Matrix & Bounded Repair):** Evaluate runs against 7 explicit verification gates. Synthesize bounded, deterministic repairs for invariant failures without hallucinated code.
- **FR-10 (Verified Recommit):** Prepare dedicated branches (`satra/repair/<sha7>`) with cryptographically traceable commit trailers (`ASENT-Verified-By: SATRA-RV`).
