# SATRA-RV System Requirements & Specification (SRS)

## 1. Engine Objective
SATRA-RV (Application-Code Security Change Assurance Engine) provides deterministic, non-circular assurance on incoming AI-authored code changes before merge.

---

## 2. Functional Requirements (FR) & Test Verification Mapping

### **FR-01: Commit Ingestion & Allowlisting**
- **Definition:** Ingest commits exclusively from authorized allowlisted repositories (`SheharyarAli-Dev/Threat-Repository`). Reject unlisted repositories, malformed SHAs, or path-traversal ref arguments.
- **Verifying Tests in Suite:**
  - `tests/test_satra_ingest.py::test_modified_file`
  - `tests/test_satra_ingest.py::test_added_and_deleted`
  - `tests/test_satra_ingest.py::test_rename_records_both_paths`
  - `tests/test_satra_ingest.py::test_binary_is_recorded_without_diff`
  - `tests/test_satra_ingest.py::test_root_commit_uses_empty_tree`
  - `tests/test_satra_ingest.py::test_merge_commit_uses_first_parent`
  - `tests/test_satra_ingest.py::test_hostile_sha_rejected`
  - `tests/test_satra_ingest.py::test_absent_sha_rejected`
  - `tests/test_satra_ingest.py::test_hostile_ref_rejected`
  - `tests/test_satra_ingest.py::test_valid_ref_resolves`
  - `tests/test_satra_ingest.py::test_wrong_repository_url_rejected`
  - `tests/test_satra_ingest.py::test_ensure_repository_refuses_non_allowlisted`
  - `tests/test_satra_ingest.py::test_clone_list_and_worktrees`
  - `tests/test_satra_ingest.py::test_worktree_for_root_commit_has_empty_baseline`

---

### **FR-02: Trusted Specifications & Cryptographic Manifest Pinning**
- **Definition:** Cryptographically pin reference specifications, requirements, and test fixtures against SHA-256 digests in `trusted.manifest.json`. Detect any modification, deletion, or planting of unauthorized test code.
- **Verifying Tests in Suite:**
  - `tests/test_satra_trust_and_seed.py::test_shipped_manifest_is_valid`
  - `tests/test_satra_trust_and_seed.py::test_manifest_lists_every_trusted_test`
  - `tests/test_satra_trust_and_seed.py::test_modified_file_is_detected`
  - `tests/test_satra_trust_and_seed.py::test_deleted_file_is_detected`
  - `tests/test_satra_trust_and_seed.py::test_planted_file_is_detected`
  - `tests/test_satra_trust_and_seed.py::test_missing_manifest_is_invalid`
  - `tests/test_satra_trust_and_seed.py::test_line_endings_do_not_change_fingerprint`
  - `tests/test_satra_trust_and_seed.py::test_seed_creates_all_branches`
  - `tests/test_satra_trust_and_seed.py::test_seed_refuses_to_run_twice`

---

### **FR-03: AST Diff Localization**
- **Definition:** Parse syntax trees of modified Python files to map exact functions, HTTP route decorators, auth predicates, and database queries.
- **Verifying Tests in Suite:**
  - `tests/test_satra_localize.py::test_astscan_detects_removed_ownership_guard`
  - `tests/test_satra_localize.py::test_astscan_detects_string_built_sql`
  - `tests/test_satra_localize.py::test_end_to_end_localization_on_repo`

---

### **FR-04: Security Change Contracts (SCC)**
- **Definition:** Derive explicit pre/post condition obligations (`SCC-<family>-<hash>`) mapping code modifications to CWE taxonomies. Produce `INCONCLUSIVE` (never `NOT_APPLICABLE`) if the SRS lacks authority keywords.
- **Verifying Tests in Suite:**
  - `tests/test_satra_rule_contract.py::test_seed_json_satisfies_loader_contract`
  - `tests/test_satra_rule_contract.py::test_seed_script_uses_loader_rule_source`
  - `tests/test_satra_rule_contract.py::test_every_run_not_inconclusive_for_rules`
  - `tests/test_satra_ollama_and_validator.py::test_missing_contract_produces_inconclusive_never_not_applicable`

---

### **FR-05: Executable Security Dictionary**
- **Definition:** Provide executable rule fixtures across 8 core vulnerability families (IDOR, Broken Role Auth, Missing Auth, SQLi, Path Traversal, Command Injection, Insecure Deserialization, SSRF).
- **Verifying Tests in Suite:**
  - `tests/test_satra_dictionary.py::test_dictionary_rules_table`
  - `tests/test_satra_dictionary.py::test_contract_runner_sanity_failure_gives_inconclusive`
  - `tests/test_satra_dictionary.py::test_tier1_rules_against_seed_repos`
  - `tests/test_satra_trust_and_seed.py::test_trusted_suite_passes_on_main_in_plain_subprocess`
  - `tests/test_satra_trust_and_seed.py::test_trusted_suite_fails_on_attack_branches`
  - `tests/test_satra_trust_and_seed.py::test_weakened_branch_is_green_for_its_own_suite`
  - `tests/test_satra_trust_and_seed.py::test_idor_branch_fails_its_own_suite`

---

### **FR-06: Adversarial Counterfactual Mutation**
- **Definition:** Apply syntactic mutant operators to ensure test suites detect bypasses and flag test-weakening edits (where assertions are widened).
- **Verifying Tests in Suite:**
  - `tests/test_satra_counterfactuals.py::test_mutate_file_ast_ownership`
  - `tests/test_satra_counterfactuals.py::test_static_integrity_catches_broadened_assertion`
  - `tests/test_satra_counterfactuals.py::test_judge_on_scenario_branches`

---

### **FR-07: Hardened Docker Sandbox Isolation**
- **Definition:** Execute test harnesses inside isolated containers (`asent-sandbox-app` / `asent-sandbox:local`) with `--network none`, `--read-only` root filesystem, memory limits, and dropped privileges (`cap-drop ALL`).
- **Verifying Tests in Suite:**
  - `tests/test_satra_sandbox.py::test_sandbox_network_isolated`
  - `tests/test_satra_sandbox.py::test_sandbox_readonly_root`
  - `tests/test_satra_sandbox.py::test_sandbox_tmpfs_isolated`
  - `tests/test_satra_sandbox.py::test_sandbox_execution_timeout`
  - `tests/test_satra_live_pipeline.py::test_host_execution_refused_without_docker`

---

### **FR-08: Ollama LLM Test Generation & 7-Check Validator**
- **Definition:** Stream code generation requests to local Ollama (`qwen2.5-coder:1.5b`), enforcing a 7-step static and dynamic verification checklist before any test is admitted into evidence. Classify mutant kills strictly via JUnit XML `<failure>` vs `<error>`.
- **Verifying Tests in Suite:**
  - `tests/test_satra_ollama_and_validator.py::test_validator_rejects_syntax_error`
  - `tests/test_satra_ollama_and_validator.py::test_validator_rejects_missing_assertion`
  - `tests/test_satra_ollama_and_validator.py::test_validator_rejects_weakened_assertion`
  - `tests/test_satra_ollama_and_validator.py::test_validator_rejects_misaligned_contract`
  - `tests/test_satra_ollama_and_validator.py::test_validator_accepts_valid_test`
  - `tests/test_satra_ollama_and_validator.py::test_ollama_client_fallback_or_live`
  - `tests/test_satra_ollama_and_validator.py::test_killed_distinguishes_error_vs_failure`
  - `tests/test_satra_ollama_and_validator.py::test_preflight_rejects_vacuous_assertions`

---

### **FR-09: 7-Gate Assurance Matrix & Bounded Repair**
- **Definition:** Evaluate runs against 7 explicit verification gates. Synthesize bounded, deterministic repairs for invariant failures without hallucinated code.
- **Verifying Tests in Suite:**
  - `tests/test_satra_decision_and_repair.py::test_decision_engine_accepts_clean_run`
  - `tests/test_satra_decision_and_repair.py::test_decision_engine_blocks_on_weakened_oracle`
  - `tests/test_satra_decision_and_repair.py::test_decision_engine_evidence_bundle`
  - `tests/test_satra_decision_and_repair.py::test_repair_propose_on_ownership_vulnerability`
  - `tests/test_satra_live_pipeline.py::test_live_pipeline_executes_real_engine`

---

### **FR-10: Verified Recommit & Append-Only Audit Trail**
- **Definition:** Prepare dedicated non-colliding branches (`satra/repair/<sha7>` or `satra/repair/<sha7>-<run8>`) with audit trailers (`ASENT-Verified-By: SATRA-RV`). Enforce human approval and policy gates before push. Maintain a cryptographic hash-chained append-only audit trail.
- **Verifying Tests in Suite:**
  - `tests/test_satra_recommit.py::test_prepare_trailer_tagged_commit_message`
  - `tests/test_satra_recommit.py::test_create_verified_repair_branch_unique_naming`
  - `tests/test_satra_recommit.py::test_recommit_flow_with_local_bare_remote`
  - `tests/test_satra_recommit.py::test_audit_trail_append_only_and_tamper_detection`

---

## 3. Non-Functional Requirements (NFR)

### **NFR-01: Deterministic Offline Replay & Reproducibility**
- **Definition:** Replays must execute offline without internet dependency, maintaining identical verdicts across runs.
- **Verifying Tests in Suite:**
  - `tests/test_api_replay.py::test_real_recorded_replay`
  - `tests/test_api_replay.py::test_research_is_explicit_and_local`
  - `tests/test_api_replay.py::test_threat_api_validation_and_export`

### **NFR-02: Cross-Platform Line Ending & Hash Invariance**
- **Definition:** Cryptographic SHA-256 verifications must produce identical results on Windows (CRLF) and Linux (LF) without rejecting authentic code fixtures.
- **Verifying Tests in Suite:**
  - `tests/test_satra_trust_and_seed.py::test_line_endings_do_not_change_fingerprint`
  - `tests/test_satra_ollama_and_validator.py::test_pytest_runner_lf_digest_cross_platform_invariance`

### **NFR-03: Security Boundary & Integrity Protection**
- **Definition:** Refuse symbolic link traversal, prohibit force-pushing to remotes, and detect snapshot cache tampering.
- **Verifying Tests in Suite:**
  - `tests/test_api_replay.py::test_snapshot_rejects_symlinks_and_cache_tampering`
  - `tests/test_satra_recommit.py::test_recommit_flow_with_local_bare_remote`
  - `tests/test_satra_recommit.py::test_audit_trail_append_only_and_tamper_detection`
