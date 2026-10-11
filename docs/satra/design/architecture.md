# SATRA-RV Architecture & Verification Flow

## 1. System Component Flowchart

```mermaid
flowchart TD
    subgraph Ingestion ["Phase 1: Commit Ingestion & Allowlist"]
        TR["SheharyarAli-Dev/Threat-Repository"] --> Fetch["ingest.ensure_repository_fetched()"]
        Fetch --> Allowlist{"ingest.require_allowed_url() (Gate 1)"}
        Allowlist -- "Pass" --> Worktrees["ingest.create_worktree() (Baseline & Candidate)"]
        Allowlist -- "Reject" --> Block["BLOCK (Untrusted Repo / Hostile SHA)"]
    end

    subgraph Analysis ["Phase 2, 3, 4: AST & Specifications"]
        Worktrees --> Manifest{"trust.verify_manifest() (Gate 2)"}
        Manifest -- "Valid" --> AST["diff_localizer.localize() (Gate 3)"]
        AST --> Regions["AST Regions (Route, Auth, DB)"]
        Regions --> SCC["security_contract.build() (Gate 4)"]
        SCC --> Dict["dictionary.RULES (8 CWE Families)"]
    end

    subgraph Adversarial ["Phase 5, 7: Counterfactuals & LLM Validator"]
        SCC --> Mutants["counterfactuals.mutate_candidate_worktree()"]
        Mutants --> OracleCheck{"test_validator.judge() (Gate 6)"}
        OracleCheck -- "Weakened" --> BlockOracle["BLOCK (Weakened Oracle)"]
        OracleCheck -- "Valid" --> Ollama["ollama_adapter.generate_tests()"]
        Ollama --> SevenChecks["test_validator.validate_generated_test()"]
    end

    subgraph Sandbox ["Phase 6, 8: Hardened Sandbox & Matrix"]
        SevenChecks --> Docker["contract_runner.run_contract_test() (Docker Sandbox)"]
        Dict --> Docker
        Docker --> GateMatrix{"decision_engine.evaluate_gates()"}
        GateMatrix -- "All Passed" --> Accept["ACCEPT"]
        GateMatrix -- "Security Violation" --> Repair["repair_inline.restore_inline_ownership_guard()"]
        Repair --> Docker
        GateMatrix -- "Regression / Weakness" --> Review["REJECT / REVIEW"]
    end

    subgraph Recommit ["Phase 10: Verified Safe Recommit"]
        Accept --> Human["Explicit Human Approval Record"]
        Human --> TrailerBranch["recommit.create_verified_repair_branch() (Trailer-Tagged)"]
        TrailerBranch --> PushPolicy{"recommit.push_repair_branch_if_allowed() (No -f)"}
        PushPolicy -- "Passed Gates" --> RemotePush["git push -u origin satra/repair/<sha7>"]
        PushPolicy -- "Flag 0 / Test" --> LocalOnly["Retained Locally (Audit Logged)"]
        RemotePush --> Audit["audit_trail.AuditTrail.append() (SHA-256 Hash Chained)"]
        LocalOnly --> Audit
    end
```

---

## 2. Recommit Sequence Diagram

This sequence diagram depicts the exact function calls, policy gates, and verification points in the recommit workflow. Notice: **no force-push (`-f`) is used**, commits are **trailer-tagged** (not cryptographic GPG signatures), and every action is appended to the hash-chained audit trail.

```mermaid
sequenceDiagram
    autonumber
    actor Operator as Human Reviewer
    participant API as backend.satra.api
    participant Recommit as backend.satra.recommit
    participant Ingest as backend.satra.ingest
    participant Git as Target Git Worktree
    participant Forge as Remote Forge (Threat-Repository)
    participant Audit as backend.satra.audit_trail

    Operator->>API: POST /api/satra/repair/approve (run_id, branch, user)
    Note over API: Verifies run_id and 7-gate matrix passed

    API->>Recommit: create_verified_repair_branch(repo, base_sha, run_id)
    Recommit->>Recommit: get_unique_repair_branch_name(repo, base_sha, run_id)
    Note over Recommit: Ensures no overwrite; creates satra/repair/<sha7> or satra/repair/<sha7>-<run8>

    Recommit->>Git: git checkout -B branch_name base_sha
    Recommit->>Recommit: prepare_trailer_tagged_commit_message(msg, run_id, approver)
    Note over Recommit: Adds ASENT-Verified-By, Run-ID, Approved-By, Approved-At
    Recommit->>Git: git commit -m commit_msg --author="ASENT Security Gate"

    API->>Recommit: push_repair_branch_if_allowed(repo, branch_name, settings, approval_record)
    
    rect rgb(240, 248, 255)
        Note over Recommit: Policy Verification Gates:<br/>1. PYTEST_CURRENT_TEST is unset<br/>2. SATRA_ALLOW_PUSH == 1<br/>3. approval_record.approved == True<br/>4. origin URL matches allowlist
    end

    alt Policy Gates Pass
        Recommit->>Forge: git push -u origin branch_name (NORMAL PUSH - NO -f!)
        Forge-->>Recommit: Push succeeded (new branch ref created)
        Recommit-->>API: {pushed: true, branch: branch_name}
    else Policy Gate Disabled or In Test
        Recommit-->>API: {pushed: false, reason: "Push disabled by policy / test env"}
    end

    API->>Audit: AuditTrail.append(run_id, operator, action, branch, commit_sha)
    Note over Audit: Computes SHA-256 hash over canonical entry + prev_hash
    Audit-->>API: Appended to append-only satra_audit.jsonl
    API-->>Operator: 200 OK (status, branch, commit_sha, audit_entry)
```
