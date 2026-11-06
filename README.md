# ASENT: Assurance for Software Evolution & Network-boundary Transitions

> **Local Evidence-Driven Assurance Prototype for AI-Assisted Software Changes**  
> Final Year Project (FYP-I) — FAST National University of Computer and Emerging Sciences, Islamabad

[![CI](https://github.com/muhammadalisajjad-dev/ASENT/actions/workflows/ci.yml/badge.svg)](https://github.com/muhammadalisajjad-dev/ASENT/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python: 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](requirements.lock.txt)

---

## 1. Executive Summary

Autonomous and LLM-assisted code generation rapidly produces pull requests, refactorings, and infrastructure updates. However, automated changes frequently introduce silent security regressions, broken authorization bindings, or malicious supply-chain dependencies.

**ASENT** is an automated, evidence-driven assurance system that evaluates candidate changes across multiple security boundaries before they can merge or deploy. Instead of treating testing as a monolithic green/red indicator, ASENT coordinates three specialized, bounded analyzers and collects tamper-evident proof records at a unified orchestrator to render an authoritative **ACCEPT**, **REVIEW**, or **BLOCK** verdict.

```
                           +--------------------------------------+
                           |   Candidate Pull Request / Commit    |
                           +--------------------------------------+
                                              |
                     +------------------------+------------------------+
                     |                                                 |
                     v                                                 v
   +------------------------------------+            +------------------------------------+
   |               CAVR                 |            |              SATRA-RV              |
   |   Dependency & Supply Chain        |            |   Application Code Contracts       |
   | - Provenance & wheel verification  |            | - AST localization & diffing       |
   | - Known vulnerability checks (OSV) |            | - Route-slicing test selection     |
   | - Manifest SHA-256 fingerprinting  |            | - Hardened Docker sandbox (tmpfs,  |
   +------------------------------------+            |   read-only root, network=none)    |
                     |                               +------------------------------------+
                     |                                                 |
                     +------------------------+------------------------+
                                              |
                                              v
                             +------------------------------------+
                             |               SABLE                |
                             |   Infrastructure as Code & IAM     |
                             | - Terraform refactor continuity    |
                             | - S3 & IAM policy authorization    |
                             | - Graph correspondence engine      |
                             | - Deterministic SQLite persistence |
                             +------------------------------------+
                                              |
                                              v
                             +------------------------------------+
                             |     ASENT Shared Orchestrator      |
                             |   Freshness & Integrity Gate       |
                             | - Stale-evidence invalidation      |
                             | - Fail-closed ambiguity handling   |
                             | - Final Verdict: ACCEPT/REVIEW/BLK |
                             +------------------------------------+
```

---

## 2. Project Team & Attribution

This project is developed as a joint Final Year Project by:

| Team Member | Academic Email | Primary Module Responsibility |
| :--- | :--- | :--- |
| **Muhammad Ali Sajjad** | `i230110@isb.nu.edu.pk` | **SABLE**: Infrastructure-as-Code continuity, Terraform AST correspondence, IAM authorization projection, SQLite evidence persistence, research evaluation oracle, WSL2 Linux & cross-platform portability. |
| **Maryam Fatima** | `i233007@isb.nu.edu.pk` | **CAVR**: Continuous Automated Vulnerability Remediation, dependency supply-chain analysis, wheel inspection, OSV advisory caching, and manifest integrity. |
| **Syed Sheharyar Ali** | `sheharyar.ali.job@gmail.com` | **SATRA-RV**: Security Architecture Threat Risk Assessment & Runtime Verification, AST diff localization, PR-aware regression test selection (RTS), Docker sandbox isolation. |

---

## 3. Specialized Module Roles

### 3.1 CAVR — Continuous Automated Vulnerability Remediation
- **Scope**: Package supply chain, third-party libraries, and wheel artifacts.
- **Key Capabilities**:
  - Offline-capable OSV vulnerability advisory caching.
  - Strict path-traversal and directory containment enforcement during package extraction.
  - Deterministic SHA-256 manifest pinning across POSIX and Windows checkouts.
  - Fail-closed behavior on missing or unverified advisory caches (`UNRESOLVED`).

### 3.2 SATRA-RV — Threat Risk Assessment & Runtime Verification
- **Scope**: Application-level source code security contracts and test suites.
- **Key Capabilities**:
  - **AST Differential Localization**: Pinpoints modified functions, routes, and decorators between base and candidate commits.
  - **PR-Aware Regression Test Selection (RTS)**: Maps modified AST regions to security invariant test families (`AUTHZ.IDOR`, `AUTH.REQ`, `INJ.SQL`, `PATH.TRAV`), safely pruning unaffected tests while preventing test leakage.
  - **Hardened Docker Sandbox**: Executes untrusted test suites in an isolated container environment (`asent-sandbox:local`) with `--network none`, `--read-only` root filesystem, dropped Linux capabilities (`--cap-drop ALL`), `no-new-privileges`, memory ceilings, and isolated `tmpfs` mounts.
  - **Restricted Loopback Audit Hook**: Limits internal test harness communications strictly to ephemeral loopback ports, forbidding connections to sensitive host services (Docker daemon, cloud metadata `169.254.169.254`, SSH, database ports).

### 3.3 SABLE — Structural Architecture & Binding Legality Evaluator
- **Scope**: Terraform Infrastructure-as-Code (IaC) and IAM security policies.
- **Key Capabilities**:
  - **Structural Refactor Continuity**: Evaluates whether an infrastructure refactoring (resource renames, modularization, `moved {}` blocks) preserves pre-existing security obligations.
  - **Graph Correspondence**: Models AWS S3 buckets, IAM roles, and identity policy attachments as a directed dependency graph via `python-hcl2` and NetworkX.
  - **Deterministic Evidence Persistence**: Stores cryptographic proof records, decision hashes, and timestamps in SQLite with tamper detection.
  - **Fail-Closed Semantics**: Ambiguous bindings, wildened resource scopes, or missing baselines result in `REGRESSED` or `UNKNOWN` verdicts—never false acceptance.

---

## 4. Getting Started

### 4.1 Prerequisites
- **Python**: 3.12 (strictly pinned via `requirements.lock.txt`)
- **Node.js**: 18.x or 20.x with npm (for frontend dashboard)
- **Operating System**: Linux (Ubuntu 22.04/24.04 recommended), WSL2, or Windows 11
- **Docker**: Optional for host-level evaluation; **required** for SATRA-RV container sandbox isolation tests.

### 4.2 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/muhammadalisajjad-dev/ASENT.git
   cd ASENT
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install pinned dependencies**:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.lock.txt
   ```

4. **Build the frontend (optional for web UI)**:
   ```bash
   cd frontend
   npm ci
   npm run build
   cd ..
   ```

### 4.3 Running the Test Suite

ASENT includes over 1,500 tests covering unit functionality, contracts, sandboxing, and full integrated workflows:

```bash
# Run all unit and module contract tests (~1,500 tests)
pytest tests/ -m "not integration"

# Run SATRA sandbox isolation tests (verifies Docker isolation or host fallback)
pytest tests/test_satra_sandbox.py -v

# Run SABLE IaC continuity and persistence tests
pytest tests/test_sable_*.py -v

# Run CAVR dependency and manifest tests
pytest tests/test_cavr_*.py -v

# Run the full integrated ASENT orchestrator verification suite
pytest tests/test_integration.py -v
```

### 4.4 Launching the Prototype Server

To start the local FastAPI orchestrator and serve the user dashboard:
```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
Navigate to `http://localhost:8000` to interact with the Run Workflow interface.

---

## 5. Scope & Explicit Capabilities

To maintain academic and scientific integrity, ASENT explicitly documents its evaluation boundaries:

| Dimension | Supported & Verified | Explicitly Out-of-Scope / Unsupported |
| :--- | :--- | :--- |
| **Cloud IaC** | AWS S3 bucket resources, IAM roles, and attached inline identity policies defined in Terraform/HCL2. | Live AWS API validation, GCP/Azure providers, AWS Organization SCPs, or unmodeled resource types. |
| **Refactoring** | Direct renames, explicit `moved {}` blocks, and unambiguous 1-to-1 resource mappings. | Autonomous multi-way bucket splits, non-deterministic identity mergers, or unconstrained dynamic HCL loops. |
| **Sandbox** | Linux Docker container isolation with restricted loopback, dropped caps, and read-only mounts. | Production-grade multi-tenant Kubernetes sandboxing or Windows native container isolation. |
| **Research Baseline** | Transparent, independent `moved_only` regex comparator (`B4`) strictly segregated from SABLE core logic. | Claiming comparative benchmark superiority on unreviewed test cases; unreviewed benchmarks report metrics as `UNMEASURED`. |

---

## 6. Repository Layout

```
ASENT/
├── backend/
│   ├── cavr/               # CAVR dependency analysis & vulnerability pipeline
│   ├── satra/              # SATRA-RV contract runner, AST localizer & RTS
│   ├── sable/              # SABLE Terraform parser, correspondence & proof engine
│   ├── orchestrator/       # Shared assurance gate, evidence collector & verdict logic
│   └── main.py             # FastAPI entrypoint
├── frontend/               # React + TypeScript + Vite assurance dashboard
├── tests/                  # Over 1,500 automated tests (unit, contract, integration)
├── scripts/                # CI helper scripts and sandbox build utilities
├── .github/workflows/      # Automated CI/CD pipelines (Ubuntu Linux)
├── requirements.lock.txt   # Fully reproducible, hash-pinned Python dependencies
└── README.md               # Repository documentation
```

---

## 7. License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
