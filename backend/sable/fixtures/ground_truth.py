"""
SABLE Ground Truth Labels — hidden from the analysis engine.

IMPORTANT: The analysis engine (analyzer.py, authorization.py, correspondence.py,
baselines.py, benchmark.py) must NEVER import this module.
This module is ONLY imported by the benchmark evaluator (benchmark.py via _load_gt()).
A test in tests/test_sable_isolation.py proves the engine never reads it.
"""

# Ground truth labels: scenario_id -> "PRESERVED" | "REGRESSED" | "UNKNOWN"
GROUND_TRUTH: dict[str, str] = {
    # Family 1: Rename / Move
    "rename_with_moved": "PRESERVED",
    "rename_no_moved": "PRESERVED",
    "move_into_module": "PRESERVED",

    # Family 2: Split
    "split_to_two": "UNKNOWN",
    "split_tagged_successor": "PRESERVED",

    # Family 3: Merge
    "merge_into_one": "UNKNOWN",
    "merge_preserved_identity": "PRESERVED",

    # Family 4: Replacement
    "replacement_preserved": "PRESERVED",
    "replacement_wrong_bucket": "UNKNOWN",

    # Family 5: Parallel assets
    "parallel_similar_names": "UNKNOWN",
    "parallel_differentiated": "PRESERVED",

    # Family 6: Policy relationship rewrite
    "policy_rewrite_preserved": "PRESERVED",
    "policy_rewrite_wrong_target": "REGRESSED",

    # Family 7: Wrong binding (hard)
    "wrong_binding_regressed": "REGRESSED",

    # Family 8: Privilege widening
    "privilege_widening": "REGRESSED",
    "resource_wildened": "REGRESSED",

    # Family 9: Weakening
    "privilege_weakened_action": "REGRESSED",
    "policy_detached": "REGRESSED",

    # Family 10: Conflicting evidence
    "conflicting_move_and_physical": "UNKNOWN",
    "no_successor_found": "UNKNOWN",

    # Family 11: Ambiguous
    "ambiguous_set_three_candidates": "UNKNOWN",
    "ambiguous_resolved_by_moved": "PRESERVED",

    # Family 12-15: Legitimate refactors
    "locals_refactor": "PRESERVED",
    "policy_doc_restructure": "PRESERVED",
    "unrelated_resource_added": "PRESERVED",
    "reformat_only": "PRESERVED",
    "exact_unchanged": "PRESERVED",

    # Hard cases
    "hard_legitimate_move": "PRESERVED",
    "hard_module_split_ambiguous": "UNKNOWN",
    "hard_wrong_binding": "REGRESSED",
    "hard_privilege_widening": "REGRESSED",
    "hard_conflicting_evidence": "UNKNOWN",

    # Additional
    "extra_get_action_wildcard": "REGRESSED",
}


def load_ground_truth() -> dict[str, str]:
    """Called ONLY by the benchmark evaluator, never by the engine."""
    return dict(GROUND_TRUTH)
