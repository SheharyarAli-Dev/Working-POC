from pathlib import Path
from backend.satra import astscan


def is_test_file(path_str):
    parts = Path(path_str).parts
    return any(p in ("tests", "test") for p in parts) or Path(path_str).name.startswith("test_") or Path(path_str).name.endswith("_test.py")


def localize_change_set(change_set, baseline_dir, candidate_dir):
    app_regions = []
    test_changes = []

    for file_info in change_set.get("files", []):
        path = file_info["path"]
        old_path = file_info.get("old_path") or path
        status = file_info["status"]

        if file_info.get("binary") or not path.endswith(".py"):
            if file_info.get("binary"):
                continue
            continue

        if is_test_file(path) or is_test_file(old_path):
            test_changes.append({
                "path": path,
                "old_path": old_path,
                "status": status,
                "diff": file_info.get("diff", "")
            })
            continue

        cand_file = Path(candidate_dir) / path
        base_file = Path(baseline_dir) / old_path

        cand_text = cand_file.read_text(encoding="utf-8", errors="replace") if cand_file.exists() else ""
        base_text = base_file.read_text(encoding="utf-8", errors="replace") if base_file.exists() else ""

        cand_tree = astscan.parse_source(cand_text) if cand_text else None
        base_tree = astscan.parse_source(base_text) if base_text else None

        if cand_text and not cand_tree:
            app_regions.append({
                "file": path,
                "function": None,
                "syntax_error": True,
                "changed": True,
                "families": [],
                "regression_notes": ["syntax error in candidate file"]
            })
            continue

        line_ranges = astscan.changed_line_ranges(base_text, cand_text) if (base_text and cand_text) else []
        cand_funcs = dict(astscan.collect_functions(cand_tree)) if cand_tree else {}
        base_funcs = dict(astscan.collect_functions(base_tree)) if base_tree else {}

        all_names = sorted(set(cand_funcs.keys()) | set(base_funcs.keys()))

        for fn_name in all_names:
            c_node = cand_funcs.get(fn_name)
            b_node = base_funcs.get(fn_name)

            if c_node and b_node:
                is_changed = astscan.span_touches(c_node, line_ranges) or (astscan.structure_signature(c_node) != astscan.structure_signature(b_node))
                if not is_changed:
                    continue

                c_scan = astscan.scan_function(c_node)
                b_scan = astscan.scan_function(b_node)

                b_kinds = set(b_scan["kinds"])
                c_kinds = set(c_scan["kinds"])

                lost = b_kinds - c_kinds
                gained = c_kinds - b_kinds

                effective_kinds = sorted(b_kinds | c_kinds)
                families = astscan.families_for(effective_kinds, c_scan["route"] or b_scan["route"])
                notes = astscan.derive_notes(lost, gained, b_kinds, c_kinds)

                if families or notes or c_scan["route"]:
                    app_regions.append({
                        "file": path,
                        "old_file": old_path if old_path != path else None,
                        "function": fn_name,
                        "start_line": astscan.span_start(c_node),
                        "end_line": c_node.end_lineno,
                        "changed": True,
                        "route": c_scan["route"] or b_scan["route"],
                        "families": families,
                        "regression_notes": notes,
                        "keyword_score": astscan.keyword_score(c_node)
                    })

            elif c_node and not b_node:
                c_scan = astscan.scan_function(c_node)
                families = astscan.families_for(c_scan["kinds"], c_scan["route"])
                if families or c_scan["route"]:
                    app_regions.append({
                        "file": path,
                        "old_file": None,
                        "function": fn_name,
                        "start_line": astscan.span_start(c_node),
                        "end_line": c_node.end_lineno,
                        "changed": True,
                        "route": c_scan["route"],
                        "families": families,
                        "regression_notes": ["function added"],
                        "keyword_score": astscan.keyword_score(c_node)
                    })

            elif b_node and not c_node:
                b_scan = astscan.scan_function(b_node)
                families = astscan.families_for(b_scan["kinds"], b_scan["route"])
                if families or b_scan["route"]:
                    app_regions.append({
                        "file": path,
                        "old_file": old_path,
                        "function": fn_name,
                        "start_line": astscan.span_start(b_node),
                        "end_line": b_node.end_lineno,
                        "changed": True,
                        "route": b_scan["route"],
                        "families": families,
                        "regression_notes": ["function deleted"],
                        "keyword_score": astscan.keyword_score(b_node)
                    })

    return {
        "regions": app_regions,
        "test_changes": test_changes
    }


def localize(baseline, candidate):
    """Change set of the .py files that differ between two folders, then `localize_change_set`.

    A file is listed only when it is new in `candidate` or its text differs from `baseline` (read as Python
    reads source, so a line-ending-only change is not a change); each entry carries its own unified diff.
    Unchanged files are not listed: before, every candidate .py file was reported as "modified" with an empty diff.
    """
    import difflib
    cand_path = Path(candidate)
    base_path = Path(baseline)
    files, diffs = [], []

    for p in sorted(cand_path.rglob("*.py")):
        rel = p.relative_to(cand_path)
        if "__pycache__" in rel.parts or ".git" in rel.parts or not p.is_file():
            continue
        old_file = base_path / rel
        before = old_file.read_text(encoding="utf-8", errors="replace") if old_file.is_file() else None
        after = p.read_text(encoding="utf-8", errors="replace")
        if before == after:
            continue
        lines = list(difflib.unified_diff(
            (before or "").splitlines(), after.splitlines(),
            fromfile=rel.as_posix(), tofile=rel.as_posix(), lineterm=""
        ))
        diffs.extend(lines)
        files.append({"path": rel.as_posix(), "status": "added" if before is None else "modified",
                      "binary": False, "diff": "\n".join(lines)})

    result = localize_change_set({"files": files}, baseline, candidate)
    result["diff"] = "\n".join(diffs)
    return result
