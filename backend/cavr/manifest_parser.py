"""C1 capture: requirements.txt edits.

`snapshot_requirements` records a requirements file as it is now. `capture_requirements_edit`
compares two snapshots of the same file and returns a capture record (same fields as
`backend.cavr.capture`) whose `requirements` are the lines that were added or changed, which
are the ones that have to be verified. The diff itself is `detect_manifest_changes`.

Lines are classified by `backend.cavr.capture.parse_requirements_text`. A line that is not a
named requirement is never turned into a package: it is reported under `unsupported` or
`errors`, and the record is then not `complete`.
"""
from __future__ import annotations
import hashlib
import re
from pathlib import Path
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from backend.cavr.capture import (
    conflicting_requirements,
    new_record,
    parse_requirements_text,
    read_requirements_bytes,
)

INCLUDE_REASON = "-r/-c include is not followed in an edit capture; capture that file's edits separately"


def read_manifest(content: str, source: str = "requirements.txt") -> dict:
    """Sort the lines of a requirements file into requirements, options, unsupported and errors."""
    manifest: dict = {"requirements": [], "options": [], "unsupported": [], "errors": []}
    for entry in parse_requirements_text(content, source):
        kind = entry.pop("kind")
        if kind == "requirement":
            manifest["requirements"].append(entry)
        elif kind == "option":
            manifest["options"].append([entry["name"], entry["value"]])
        elif kind == "include":
            manifest["unsupported"].append({"raw": entry["raw"], "reason": INCLUDE_REASON, "origin": entry["origin"]})
        elif kind == "unsupported":
            manifest["unsupported"].append(entry)
        else:
            manifest["errors"].append(entry)
    manifest["errors"].extend(conflicting_requirements(manifest["requirements"]))
    return manifest


def parse_requirements_txt(content: str) -> list[dict]:
    """The named requirements in a requirements file. Unparseable lines are left out here and
    reported by `read_manifest`; they are no longer guessed at with a regex."""
    return [{**req, "specifier": req["specifier"] or "*"} for req in read_manifest(content)["requirements"]]

def parse_pyproject_toml(content: str) -> list[dict]:
    results: list[dict] = []
    # Match dependencies = [ ... ]
    m = re.search(r"dependencies\s*=\s*\[(.*?)\]", content, re.DOTALL)
    if m:
        dep_lines = m.group(1).split(",")
        for line in dep_lines:
            clean = line.strip().strip("'\"")
            if clean:
                try:
                    req = Requirement(clean)
                    results.append({
                        "name": req.name,
                        "specifier": str(req.specifier) if req.specifier else "*",
                        "raw": clean
                    })
                except Exception:
                    pass
    return results

def detect_manifest_changes(before_content: str, after_content: str, manifest_type: str = "requirements.txt") -> list[dict]:
    """Changes between two versions of a manifest: ADDED, VERSION_CHANGED, MODIFIED, REMOVED.

    Two lines are the same requirement when the canonical name and the marker are equal, so
    `Foo_Bar` and `foo-bar` match. VERSION_CHANGED means the specifier differs; MODIFIED means
    the specifier is the same but the extras or `--hash` values differ. ADDED, VERSION_CHANGED
    and MODIFIED carry the new requirement under `requirement`.
    """
    if manifest_type == "requirements.txt":
        before, after = (read_manifest(text)["requirements"] for text in (before_content, after_content))
    else:
        before, after = (parse_pyproject_toml(text) for text in (before_content, after_content))
    return _diff(before, after)


def _diff(before: list[dict], after: list[dict]) -> list[dict]:
    def keyed(requirements):
        return {(canonicalize_name(r["name"]), r.get("marker")): r for r in requirements}

    def spec(requirement):
        return requirement["specifier"] or "*"

    before_deps, after_deps = keyed(before), keyed(after)
    changes: list[dict] = []
    for key, dep in after_deps.items():
        old = before_deps.get(key)
        if old is None:
            changes.append({"action": "ADDED", "package": dep["name"], "specifier": spec(dep), "raw": dep["raw"],
                            "requirement": dep})
        elif spec(old) != spec(dep):
            changes.append({
                "action": "VERSION_CHANGED",
                "package": dep["name"],
                "old_specifier": spec(old),
                "new_specifier": spec(dep),
                "raw": dep["raw"],
                "requirement": dep
            })
        elif (old.get("extras"), old.get("hashes")) != (dep.get("extras"), dep.get("hashes")):
            changes.append({"action": "MODIFIED", "package": dep["name"], "specifier": spec(dep), "raw": dep["raw"],
                            "requirement": dep})
    for key, dep in before_deps.items():
        if key not in after_deps:
            changes.append({"action": "REMOVED", "package": dep["name"], "specifier": spec(dep), "removed": dep})
    return changes


def snapshot_requirements(path) -> dict:
    """The file as it is now: path, exists, sha256 of its bytes, content, and error if unreadable."""
    path = Path(path).resolve()
    snapshot = {"path": str(path), "exists": path.exists(), "error": None, "content": "", "sha256": None}
    if snapshot["exists"]:
        data, text, problem = read_requirements_bytes(path)
        if problem:
            snapshot["error"] = problem
        else:
            snapshot["content"] = text
            snapshot["sha256"] = hashlib.sha256(data).hexdigest()
    return snapshot


def capture_requirements_edit(before: dict, after: dict) -> dict:
    """Capture record for the edit between two snapshots of one requirements file."""
    if before["path"] != after["path"]:
        raise ValueError(f"snapshots are of different files: {before['path']} and {after['path']}")
    path = after["path"]
    record = new_record("requirements_edit")
    record.update({"path": path, "before_sha256": before["sha256"], "after_sha256": after["sha256"],
                   "changed": before["sha256"] != after["sha256"] or before["exists"] != after["exists"],
                   "changes": [], "removed": []})

    if before["error"]:
        # The old state is unknown, so nothing can be assumed to be already verified.
        record["errors"].append({"raw": path, "reason": "earlier snapshot is unreadable: " + before["error"],
                                 "origin": path})
    if after["error"]:
        record["errors"].append({"raw": path, "reason": after["error"], "origin": path})
        return record

    manifest = read_manifest(after["content"], path)
    record["options"] = manifest["options"]
    record["unsupported"].extend(manifest["unsupported"])
    record["errors"].extend(manifest["errors"])
    if after["exists"]:
        record["files"].append({"path": path, "role": "requirements", "sha256": after["sha256"],
                                "included_from": None})

    previous = read_manifest(before["content"], path)["requirements"]
    record["changes"] = _diff(previous, manifest["requirements"])
    record["requirements"] = [c["requirement"] for c in record["changes"] if c["action"] != "REMOVED"]
    record["removed"] = [c["removed"] for c in record["changes"] if c["action"] == "REMOVED"]
    record["complete"] = not record["unsupported"] and not record["errors"]
    return record
