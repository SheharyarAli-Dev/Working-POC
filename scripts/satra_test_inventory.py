#!/usr/bin/env python3
"""
SATRA Test Inventory Generator
Scans all SATRA and replay test suites, maps each test case to functional requirements (FR-01 to FR-10)
and non-functional requirements (NFR-01 to NFR-03), and generates docs/satra/test-inventory.md.
Supports --check flag for CI to verify that committed inventory is up to date.
"""

import ast
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Mapping rules from test file or function name to Requirement ID, Kind, and Description
REQUIREMENT_MAP = {
    # test_satra_ingest.py
    "test_satra_ingest.py": {
        "req": "FR-01",
        "kind": "unit",
        "default_desc": "Validates git commit ingestion, worktree isolation, and SHA allowlist filtering."
    },
    # test_satra_trust_and_seed.py
    "test_satra_trust_and_seed.py": {
        "req": "FR-02",
        "kind": "integration",
        "default_desc": "Verifies cryptographic manifest pinning (SHA-256) of trusted tests and fixtures."
    },
    # test_satra_localize.py
    "test_satra_localize.py": {
        "req": "FR-03",
        "kind": "unit",
        "default_desc": "Validates AST diff localization and detection of removed security guards."
    },
    # test_satra_rule_contract.py
    "test_satra_rule_contract.py": {
        "req": "FR-04",
        "kind": "unit",
        "default_desc": "Validates security change contract obligations and loader rule consistency."
    },
    # test_satra_dictionary.py
    "test_satra_dictionary.py": {
        "req": "FR-05",
        "kind": "integration",
        "default_desc": "Verifies executable rule dictionary contracts and seed threat repo evaluation."
    },
    # test_satra_counterfactuals.py
    "test_satra_counterfactuals.py": {
        "req": "FR-06",
        "kind": "unit",
        "default_desc": "Tests counterfactual AST mutations and detection of widened assertions."
    },
    # test_satra_sandbox.py
    "test_satra_sandbox.py": {
        "req": "FR-07",
        "kind": "docker",
        "default_desc": "Verifies container sandbox network isolation, read-only root, and resource limits."
    },
    # test_satra_ollama_and_validator.py
    "test_satra_ollama_and_validator.py": {
        "req": "FR-08",
        "kind": "ollama",
        "default_desc": "Validates LLM test generation checklist, JUnit XML error/fail classification, and preflight."
    },
    # test_satra_decision_and_repair.py
    "test_satra_decision_and_repair.py": {
        "req": "FR-09",
        "kind": "integration",
        "default_desc": "Verifies 7-gate decision engine verdicts, evidence bundles, and inline repairs."
    },
    # test_satra_recommit.py
    "test_satra_recommit.py": {
        "req": "FR-10",
        "kind": "integration",
        "default_desc": "Verifies verified recommit branch creation, trailer tags, and append-only audit trail."
    },
    # test_satra_live_pipeline.py
    "test_satra_live_pipeline.py": {
        "req": "FR-09",
        "kind": "integration",
        "default_desc": "Tests live pipeline end-to-end execution and container gating policy."
    },
    # test_satra_gitkit.py
    "test_satra_gitkit.py": {
        "req": "FR-01",
        "kind": "unit",
        "default_desc": "Validates local fixture repository management and git operations."
    },
    # test_api_replay.py
    "test_api_replay.py": {
        "req": "NFR-01",
        "kind": "integration",
        "default_desc": "Verifies replay reproducibility, symlink rejection, and threat API export."
    },
}

SPECIFIC_DESCRIPTIONS = {
    "test_modified_file": "Detects modified file in commit diff and produces accurate delta metadata.",
    "test_added_and_deleted": "Verifies commit parser records file additions and deletions correctly.",
    "test_rename_records_both_paths": "Verifies git renames record both previous and new relative paths.",
    "test_binary_is_recorded_without_diff": "Ensures binary files are detected and excluded from text diff parsing.",
    "test_root_commit_uses_empty_tree": "Verifies root commit diffs against git empty tree hash.",
    "test_merge_commit_uses_first_parent": "Verifies merge commits compare exclusively against first parent.",
    "test_hostile_sha_rejected": "Rejects malformed, injected, or path-traversal commit SHA arguments.",
    "test_absent_sha_rejected": "Rejects commit SHAs that do not exist in the ingested git history.",
    "test_hostile_ref_rejected": "Rejects malformed or option-injected git branch and tag ref names.",
    "test_valid_ref_resolves": "Resolves standard branch and tag names to valid commit objects.",
    "test_wrong_repository_url_rejected": "Refuses to clone or ingest from URLs outside the strict allowlist.",
    "test_ensure_repository_refuses_non_allowlisted": "Enforces forge allowlist checks before initiating fetch.",
    "test_clone_list_and_worktrees": "Creates isolated git worktrees per candidate evaluation.",
    "test_worktree_for_root_commit_has_empty_baseline": "Handles root commit worktree creation with empty baseline tree.",
    "test_shipped_manifest_is_valid": "Verifies trusted.manifest.json SHA-256 digests match on-disk fixtures.",
    "test_manifest_lists_every_trusted_test": "Ensures every security test in trusted/ is registered in the manifest.",
    "test_modified_file_is_detected": "Fails manifest verification when a trusted security test is modified.",
    "test_deleted_file_is_detected": "Fails manifest verification when a trusted security test is removed.",
    "test_planted_file_is_detected": "Fails manifest verification when an unauthorized test file is planted.",
    "test_missing_manifest_is_invalid": "Refuses execution when trusted.manifest.json is absent.",
    "test_line_endings_do_not_change_fingerprint": "Normalizes CRLF and LF byte streams to yield deterministic manifests.",
    "test_seed_creates_all_branches": "Verifies seeding script generates all mandatory scenario branches.",
    "test_seed_refuses_to_run_twice": "Prevents accidental re-seeding and destructive branch overwrite.",
    "test_baseline_own_suite_passes": "Confirms clean baseline repository passes its internal test suite.",
    "test_trusted_suite_passes_on_main_in_plain_subprocess": "Runs trusted contract suite on main branch and asserts SATISFIED.",
    "test_trusted_suite_fails_on_attack_branches": "Asserts trusted contract suite detects and flags attack branches as VIOLATED.",
    "test_weakened_branch_is_green_for_its_own_suite": "Validates that weakened branch passes its own mutated test suite.",
    "test_idor_branch_fails_its_own_suite": "Verifies unpatched vulnerability fails baseline assertion suite.",
    "test_astscan_detects_removed_ownership_guard": "AST scanner localizes removed IDOR checks in invoice routes.",
    "test_astscan_detects_string_built_sql": "AST scanner flags string-interpolated and f-string SQL queries.",
    "test_end_to_end_localization_on_repo": "End-to-end AST localization pinpoints modified functions in worktrees.",
    "test_seed_json_satisfies_loader_contract": "Validates seed rule JSON adheres to threat repo schema.",
    "test_seed_script_uses_loader_rule_source": "Ensures seeding script sources rules from seed_rules.py.",
    "test_every_run_not_inconclusive_for_rules": "Guarantees seed rules are recognized and never inconclusive.",
    "test_dictionary_rules_table": "Verifies 8-rule executable security dictionary covers target CWEs.",
    "test_contract_runner_sanity_failure_gives_inconclusive": "Returns INCONCLUSIVE when test harness sanity checks fail.",
    "test_tier1_rules_against_seed_repos": "Evaluates Tier-1 security contract suite against seeded attack branches.",
    "test_mutate_file_ast_ownership": "Synthesizes counterfactual bypass mutation in target ownership check.",
    "test_static_integrity_catches_broadened_assertion": "Detects assertion widening (e.g. status in [200, 403]).",
    "test_judge_on_scenario_branches": "Validates judge discriminator classifies counterfactual outcomes accurately.",
    "test_sandbox_network_isolated": "Proves container sandbox cannot establish outbound network connections.",
    "test_sandbox_readonly_root": "Proves container sandbox filesystem root is strictly read-only.",
    "test_sandbox_tmpfs_isolated": "Verifies ephemeral /tmp tmpfs execution does not persist state.",
    "test_sandbox_execution_timeout": "Terminates candidate executions exceeding execution timeout limits.",
    "test_validator_rejects_syntax_error": "Rejects malformed Python test syntax before execution.",
    "test_validator_rejects_missing_assertion": "Rejects tests lacking assert statements at preflight.",
    "test_validator_rejects_weakened_assertion": "Rejects broadened assertion accepting insecure HTTP responses.",
    "test_validator_rejects_misaligned_contract": "Rejects tests targeting routes outside the security contract.",
    "test_validator_accepts_valid_test": "Accepts well-formed generated test killing counterfactual mutant.",
    "test_ollama_client_fallback_or_live": "Handles live Ollama streaming or deterministic fallback.",
    "test_killed_distinguishes_error_vs_failure": "Distinguishes assertion failure (<failure>) from setup crash (<error>).",
    "test_preflight_rejects_vacuous_assertions": "Rejects vacuous assertions (assert True, assert 1, assert '') at AST preflight.",
    "test_missing_contract_produces_inconclusive_never_not_applicable": "Yields INCONCLUSIVE when SRS lacks InvoiceHub security requirements.",
    "test_pytest_runner_lf_digest_cross_platform_invariance": "Computes identical SHA-256 digests across CRLF and LF byte streams.",
    "test_decision_engine_accepts_clean_run": "Approves clean runs where all 7 assurance gates pass.",
    "test_decision_engine_blocks_on_weakened_oracle": "Blocks pull request when candidate oracle has been weakened.",
    "test_decision_engine_evidence_bundle": "Assembles cryptographic evidence bundle with all gate verdicts.",
    "test_repair_propose_on_ownership_vulnerability": "Synthesizes and applies verified repair for ownership violation.",
    "test_prepare_trailer_tagged_commit_message": "Formats audit trailers (Run-ID, Approver, Timestamp) in commit body.",
    "test_create_verified_repair_branch_unique_naming": "Creates non-colliding branch satra/repair/<sha7>-<run8> upon repeat repair.",
    "test_recommit_flow_with_local_bare_remote": "Verifies push policy gates, human approval requirement, and bare remote push.",
    "test_audit_trail_append_only_and_tamper_detection": "Maintains cryptographic hash-chained audit log and detects record tampering.",
    "test_host_execution_refused_without_docker": "Refuses execution on host when Docker is absent and allow flag is 0.",
    "test_live_pipeline_executes_real_engine": "Executes full multi-step SATRA assurance engine on real git repository.",
    "test_threat_api_validation_and_export": "Validates Threat-Repository API export and schema integrity.",
    "test_real_recorded_replay": "Replays recorded session trace deterministically without network access.",
    "test_research_is_explicit_and_local": "Confirms research case execution remains completely local and isolated.",
    "test_snapshot_rejects_symlinks_and_cache_tampering": "Rejects symlink planting and snapshot cache tampering.",
}


def collect_test_functions():
    test_dir = ROOT / "tests"
    items = []
    test_files = sorted(list(test_dir.glob("test_satra*.py")) + [test_dir / "test_api_replay.py"])

    for file_path in test_files:
        if not file_path.exists():
            continue
        rel_file = file_path.relative_to(ROOT).as_posix()
        tree = ast.parse(file_path.read_text(encoding="utf-8", errors="replace"))
        file_rule = REQUIREMENT_MAP.get(file_path.name, {"req": "FR-01", "kind": "unit", "default_desc": "Test suite."})

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                # Extract markers
                markers = []
                req_marker = None
                for dec in node.decorator_list:
                    rendered = ast.unparse(dec)
                    if "mark.req" in rendered:
                        m = re.search(r'["\']([^"\']+)["\']', rendered)
                        if m:
                            req_marker = m.group(1)
                    markers.append(rendered)

                req_id = req_marker or file_rule["req"]
                kind = file_rule["kind"]

                # Extract docstring or lookup
                doc = ast.get_docstring(node)
                desc = doc.strip().splitlines()[0] if doc else SPECIFIC_DESCRIPTIONS.get(node.name, file_rule["default_desc"])

                # Check parameterization (e.g. [scenario/idor-bypass])
                items.append({
                    "name": node.name,
                    "file": rel_file,
                    "req": req_id,
                    "kind": kind,
                    "markers": ", ".join(markers) if markers else "none",
                    "description": desc,
                })

    return items


def generate_inventory_markdown(items):
    lines = [
        "# SATRA Test Inventory & Requirements Traceability Matrix\n\n",
        "**Generated by:** `scripts/satra_test_inventory.py`  \n",
        "**Date:** 2026-10-11  \n",
        "**Total Test Functions:** %d  \n\n" % len(items),
        "This matrix maps every test in the SATRA-RV test suite to its corresponding Functional Requirement (FR-01 to FR-10) or Non-Functional Requirement (NFR-01 to NFR-03).\n\n",
        "| Test Name | File | Req ID | Kind | Verification Purpose |\n",
        "|---|---|---|---|---|\n"
    ]
    for it in items:
        lines.append(f"| `{it['name']}` | `{it['file']}` | **{it['req']}** | {it['kind']} | {it['description']} |\n")

    lines.append("\n## Summary by Requirement\n\n")
    req_counts = {}
    for it in items:
        req_counts[it["req"]] = req_counts.get(it["req"], 0) + 1

    lines.append("| Requirement | Description | Test Count |\n|---|---|---|\n")
    req_titles = {
        "FR-01": "Commit Ingestion & Forge Allowlisting",
        "FR-02": "Trusted Specifications & Cryptographic Manifest",
        "FR-03": "AST Diff Localization & Guard Detection",
        "FR-04": "Security Change Contracts (SCC)",
        "FR-05": "Executable Security Dictionary (Tier-1 CWE Rules)",
        "FR-06": "Adversarial Counterfactual Mutation",
        "FR-07": "Hardened Docker Sandbox Isolation",
        "FR-08": "Ollama LLM Test Generation & 7-Check Validator",
        "FR-09": "7-Gate Assurance Matrix & Bounded Repair",
        "FR-10": "Verified Recommit & Append-Only Audit Trail",
        "NFR-01": "Deterministic Offline Replay & Reproducibility",
        "NFR-02": "Cross-Platform Consistency & Line Ending Invariance",
        "NFR-03": "Least-Privilege Operation & Security Boundary",
    }
    for r in sorted(req_counts.keys()):
        lines.append(f"| **{r}** | {req_titles.get(r, 'Requirement')} | {req_counts[r]} |\n")

    return "".join(lines)


def main():
    check_mode = "--check" in sys.argv
    items = collect_test_functions()
    content = generate_inventory_markdown(items)
    out_path = ROOT / "docs/satra/test-inventory.md"

    if check_mode:
        if not out_path.exists():
            print("ERROR: docs/satra/test-inventory.md does not exist.")
            sys.exit(1)
        existing = out_path.read_text(encoding="utf-8")
        if existing.strip() != content.strip():
            print("ERROR: docs/satra/test-inventory.md is stale. Run scripts/satra_test_inventory.py to regenerate.")
            sys.exit(1)
        print("PASS: docs/satra/test-inventory.md is up to date.")
        sys.exit(0)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(content, encoding="utf-8")
    print(f"Generated {out_path} with {len(items)} test functions.")


if __name__ == "__main__":
    main()
