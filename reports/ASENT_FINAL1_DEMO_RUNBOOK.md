# ASENT Final-1 Integrated Security Assurance — Demonstration Runbook

## 1. System Overview

**ASENT** (Automated Security Assurance for AI-Assisted Software Development) evaluates AI-generated software changes across three connected, cross-layer assurance dimensions before any candidate change is permitted to merge or deploy:

```
                     Actual Candidate Project Input
                       (Source + Lock + Infra)
                                  │
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
     [ CAVR ]                 [ SATRA-RV ]              [ SABLE ]
Dependency Assurance      Application Assurance    Infrastructure Assurance
   - Capability Contract     - Trusted Test Oracles   - HCL/Terraform Parser
   - Static Trigger Scan     - Mutant Generation      - Successor Correspondence
   - Counterfactual Exec     - Ollama LLM Validator   - Bounded S3/IAM Policy
   - OSV Vulnerability DB    - Differential Execution - Obligation Projection
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  ▼
                     [ SHARED SERVICE & GATE ]
                     - Cryptographic Evidence Store
                     - Decision Engine (ACCEPT / BLOCK / REVIEW)
                     - Tamper-Evident SHA-256 Chains
                     - Automatic Cross-Module Invalidation
```

The final decision is **not an independent dashboard vote**, but an aggregate, cryptographically bound security gate:
- **`ACCEPT`**: All applicable modules succeed with valid, non-stale evidence bound to the exact candidate snapshot.
- **`BLOCK`**: Any security regression is detected (e.g., SABLE policy widening, SATRA test failure / weakened oracle, or CAVR unmitigated high-risk trigger).
- **`REVIEW`**: Analysis is inconclusive or ambiguous (e.g., correspondence tie, unsupported HCL syntax, missing dependency lock).

---

## 2. Prerequisites & Host Readiness

| Component | Status on Windows Host | Verification Command |
|---|---|---|
| **Python Environment** | Python 3.12 venv active | `& "C:\Users\hp\Downloads\ASENT\ASENT\.venv\Scripts\python.exe" --version` |
| **Ollama LLM Engine** | Running daemon on `127.0.0.1:11434` | `ollama list` -> `qwen2.5-coder:1.5b` (986 MB) |
| **Dashboard Frontend** | Compiled in `frontend/dist/` | Tested via FastAPI StaticFiles on `/` |
| **Git Command Line** | Available in PATH | `git --version` |
| **Docker / Isolation** | Host fallback active | Process sandboxing with audit hooks & LF normalization |

---

## 3. Starting the ASENT System

### Step 1: Ensure Ollama is running with the model loaded
In PowerShell:
```powershell
# Verify Ollama is running
curl.exe -s http://127.0.0.1:11434/api/tags
# If not running, start in a separate terminal:
# ollama serve
```

### Step 2: Start the ASENT Backend & Dashboard Server
In PowerShell from the repository root:
```powershell
Set-Location "C:\Users\hp\Downloads\ASENT\ASENT_recovery_20261027\candidate-prep-copy"
$env:PYTHONPATH = "."
& "C:\Users\hp\Downloads\ASENT\ASENT\.venv\Scripts\python.exe" -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

### Step 3: Verify Service Health
Open a browser or run:
```powershell
curl.exe -s http://127.0.0.1:8000/api/health
# Expected: {"status":"ok","version":"1.0.0","database":"..."}

curl.exe -s http://127.0.0.1:8000/api/capabilities
# Expected: lists CAVR, SATRA, SABLE capabilities and active sandboxing
```

---

## 4. Live Demonstration Scenarios

Open **`http://127.0.0.1:8000`** in Google Chrome or Microsoft Edge.
Click on **RUN WORKFLOW** in the top navigation.

---

### Scenario 1: Safe Baseline AI-Refactor (`safe`)
- **What is tested**: A legitimate PDF processing enhancement (`pypdf` dependency, intact ownership checks in `read_invoice`, and least-privilege Terraform S3 bucket access).
- **How to demonstrate**:
  1. Under **Select Candidate AI-Change Scenario**, select `Normal first build` (`safe`).
  2. Click **Execute Assurance Workflow**.
- **Expected Outcomes**:
  - **CAVR**: `VERIFIED` — `pypdf` satisfies capability contract; disabled optional sinks verified.
  - **SATRA**: `ACCEPT` — 10/10 trusted security and functional tests pass; oracle mutation testing validates test suite strength.
  - **SABLE**: `PRESERVED` — Exact modeled S3 obligation holds for `aws_iam_role.app` accessing `customer-data`.
  - **Overall Decision**: **`ACCEPT`** (Clean commit hash generated).
- **Key Evidence to Show**:
  - Click **EVIDENCE BUNDLE** to inspect the cryptographic SHA-256 hash chain and `clean_workspace` snapshot.

---

### Scenario 2: SABLE Infrastructure Privilege Regression (`sable_regressed`)
- **What is tested**: An AI assistant refactors Terraform infrastructure to add an archive bucket, but mistakenly binds the application role's inline policy to the *archive* bucket instead of the *active customer data* bucket.
- **How to demonstrate**:
  1. Select `Storage refactor · wrong binding` (`sable_regressed`).
  2. Click **Execute Assurance Workflow**.
- **Expected Outcomes**:
  - **SABLE**: **`REGRESSED`** — Policy target misbinding detected.
  - **Overall Decision**: **`BLOCK`**.
- **Defense Explanation (SABLE Owner)**:
  - "SABLE computes successor correspondence: the active bucket moved, but the IAM policy resource was rewritten to `aws_s3_bucket.archive.arn`. Because the registered obligation requires access to the active asset, the obligation is violated. SABLE fails closed and prevents deployment."

---

### Scenario 3: SATRA-RV Oracle Weakening Attack (`satra_weak`)
- **What is tested**: The AI developer introduces an IDOR vulnerability by removing the user ownership check, and simultaneously *relaxes the test assertion* from `assert response.status_code == 403` to `assert response.status_code in [200, 403]`. The candidate tests appear completely green!
- **How to demonstrate**:
  1. Select `The green test that misses a breach` (`satra_weak`).
  2. Click **Execute Assurance Workflow**.
- **Expected Outcomes**:
  - **SATRA**: **`REJECT`** — Diagnosis: `ORACLE_WEAKENED`.
  - **Overall Decision**: **`BLOCK`**.
- **Defense Explanation (SATRA-RV Owner)**:
  - "Ordinary CI passes because the developer weakened the test. However, SATRA executes *counterfactual mutation analysis*: it checks whether the test suite detects known security mutants. The weakened assertion fails to kill the mutant, exposing test suite degradation."

---

### Scenario 4: SATRA Application Ownership Bypass (`satra_bypass`)
- **What is tested**: An AI patch simplifies the invoice endpoint by removing `if row['owner_id'] != user['id']: raise HTTPException(403)`.
- **How to demonstrate**:
  1. Select `Ownership regression` (`satra_bypass`).
  2. Click **Execute Assurance Workflow**.
- **Expected Outcomes**:
  - **SATRA**: **`REJECT`** — Trusted test suite fails on ownership boundary test (`test_read_invoice_other_user_forbidden`).
  - **Overall Decision**: **`BLOCK`**.

---

### Scenario 5: Cross-Module Invalidation & Auto-Repair (`cross_module`)
- **What is tested**: Candidate code introduces an unverified local lab dependency (`invoice_pdf_lab.py`) with sensitive triggers. Auto-repair is enabled.
- **How to demonstrate**:
  1. Select `cross_module` (or trigger via API with `auto_repair=True`).
- **Expected Outcomes**:
  - CAVR first detects unauthorized trigger -> `REJECTED`.
  - Auto-repair replaces the insecure lab stub with `invoice_pdf_safe.py`.
  - The shared Service detects candidate workspace mutation and **invalidates SATRA evidence** (`evidence.invalidated`).
  - SATRA automatically re-runs against the repaired workspace.
  - Both modules re-verify -> Overall Decision: **`ACCEPT`**.
- **Defense Explanation (Cross-Module Orchestration)**:
  - "This demonstrates cross-module coupling: repairing a dependency changes the workspace, which immediately invalidates all prior application-code test proofs. ASENT forces re-verification before granting final trust."

---

### Scenario 6: SABLE Ambiguous Correspondence (`sable_unknown`)
- **What is tested**: An AI splits one bucket into multiple successor candidates with identical tags and no explicit `moved {}` block.
- **How to demonstrate**:
  1. Select `sable_unknown`.
  2. Click **Execute Assurance Workflow**.
- **Expected Outcomes**:
  - **SABLE**: **`UNKNOWN`** — Successor scores are tied; cannot uniquely attribute obligation.
  - **Overall Decision**: **`REVIEW`** — Requires human architectural sign-off.

---

## 5. Defense Alignment Guide for Examiners

| Student | Component | Core Technical Contribution to Highlight |
|---|---|---|
| **Muhammad Ali Sajjad** | **SABLE & Shared Final Gate** | HCL AST graph parsing, 6-signal correspondence heuristic, bounded IAM/S3 semantics, fail-closed tie-breaking, tamper-evident cryptographic decision aggregation. |
| **Sheharyar Ali** | **SATRA-RV** | Run-time verification, trusted test oracle protection, AST-based mutant generation, Ollama LLM test proposal validation, cross-platform audit hooks. |
| **Maryam Fatima** | **CAVR** | Software supply-chain capability contracts, static AST trigger-to-sink scanning, dynamic counterfactual lab harness, OSV vulnerability tracking. |

---

## 6. Documented Limitations & Research Scope

For transparency and academic defense integrity:
1. **SABLE Scope**: Covers Terraform/HCL S3 buckets and inline IAM role policies (`aws_iam_role_policy`). Managed policies, customer-managed policies, and live AWS API validation are outside the bounded formal model.
2. **SATRA Scope**: Targets FastAPI/Starlette REST APIs with relational database backends (InvoiceHub). Host execution relies on Python audit hooks and hash-pinned sources; full untrusted container isolation requires Docker/Podman with appropriate privileges.
3. **CAVR Scope**: Evaluates Python wheels and local dependencies with declared call graphs. Arbitrary dynamic reflection is flagged for review.
