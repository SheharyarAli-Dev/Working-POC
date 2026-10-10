"""C2 requirement gate: is this requirement permitted by the project policy?

The gate runs before anything is downloaded and answers PERMITTED, BLOCK or UNRESOLVED.
It fails closed: PERMITTED is returned from exactly one place, after every rule has passed.

Rules, in order (the first one that applies decides):

    POLICY_MISSING       no policy                                   -> UNRESOLVED
    POLICY_INVALID       policy is not readable or not well formed   -> UNRESOLVED
    REQUIREMENT_INVALID  the request is not a named requirement      -> UNRESOLVED
    DENYLIST             canonical name is in `denied_packages`      -> BLOCK
    NOT_PINNED           not exactly one `==` version                -> BLOCK
    NOT_ON_ALLOWLIST     no `approved_requirements` entry has this
                         canonical name and a specifier that the
                         requested version satisfies                 -> BLOCK
    LOCKFILE_INVALID     a lockfile exists but is not well formed    -> UNRESOLVED
    NOT_IN_LOCKFILE      a lockfile exists and has no PyPI entry
                         with this name and version                  -> BLOCK
    ALLOWED              none of the above                           -> PERMITTED

Policy keys read by the gate: `approved_requirements` (list of requirement strings such as
"pypdf==6.19.0" or "pypdf>=6,<7") and `denied_packages` (list of {"name", "reason"}).
Other keys are not read, but they are part of `policy_version`, which is the SHA-256 of
the whole policy as canonical JSON.
"""
from __future__ import annotations
import json
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from backend.cavr.capture import parse_requirement
from backend.orchestrator.hashing import digest

POLICY_PATH = Path(__file__).parent / "project_policy.json"

RULE_TITLES = {
    "POLICY_MISSING": "Project policy must exist",
    "POLICY_INVALID": "Project policy must be well formed",
    "REQUIREMENT_INVALID": "Request must be a named requirement",
    "DENYLIST": "Explicit project denylist",
    "NOT_PINNED": "Requirement must be pinned with ==",
    "NOT_ON_ALLOWLIST": "Approved project requirements (name and version)",
    "LOCKFILE_INVALID": "Project lockfile must be well formed",
    "NOT_IN_LOCKFILE": "Project lockfile (name and version)",
    "CAPTURE_INCOMPLETE": "Request must be fully captured",
    "NOTHING_TO_VERIFY": "No requirement was added or changed",
    "ALLOWED": "Approved project requirements (name and version)",
}


class Unreadable:
    """Stands for a policy or lockfile that exists but could not be read as JSON."""

    def __init__(self, reason: str):
        self.reason = reason


def policy_version(policy) -> str:
    """SHA-256 of the policy as canonical JSON (sorted keys, no whitespace)."""
    return digest(policy)


def policy_problems(policy) -> list[str]:
    """Everything that is wrong with a policy. An empty list means it can be used."""
    if isinstance(policy, Unreadable):
        return [policy.reason]
    if not isinstance(policy, dict):
        return ["policy must be a JSON object"]
    problems: list[str] = []

    approved = policy.get("approved_requirements")
    if not isinstance(approved, list):
        problems.append("approved_requirements must be a list")
    else:
        for entry in approved:
            if _approved_entry(entry) is None:
                problems.append(f"approved_requirements entry is not a name with a version specifier: {entry!r}")

    denied = policy.get("denied_packages")
    if not isinstance(denied, list):
        problems.append("denied_packages must be a list")
    else:
        for entry in denied:
            if _denied_name(entry) is None:
                problems.append(f"denied_packages entry is not an object with a package name: {entry!r}")
    return problems


def lockfile_problems(lockfile) -> list[str]:
    """Everything that is wrong with a lockfile. An empty list means it can be used."""
    if isinstance(lockfile, Unreadable):
        return [lockfile.reason]
    if not isinstance(lockfile, dict) or not isinstance(lockfile.get("packages"), list):
        return ["lockfile must be a JSON object with a packages list"]
    problems: list[str] = []
    for entry in lockfile["packages"]:
        if not (isinstance(entry, dict) and all(isinstance(entry.get(key), str) for key in ("name", "version", "ecosystem"))):
            problems.append(f"lockfile entry needs name, version and ecosystem: {entry!r}")
        elif _is_pypi(entry) and _version(entry["version"]) is None:
            problems.append(f"lockfile entry has an invalid version: {entry!r}")
    return problems


def evaluate_requirement(requirement, policy, lockfile=None) -> dict:
    """Judge one requirement.

    `requirement` is a string ("pypdf==6.19.0") or a capture requirement record; only its
    `name` and `specifier` are used and they are parsed again here, so a wrong `pinned` flag
    cannot get an unpinned requirement through. `policy` is the parsed policy, or None when
    there is none. `lockfile` is the parsed project lockfile, or None when the project has none.
    """
    if policy is None:
        return _decision("UNRESOLVED", "POLICY_MISSING", "no project policy; nothing can be permitted")
    problems = policy_problems(policy)
    if problems:
        return _decision("UNRESOLVED", "POLICY_INVALID", "project policy is not usable: " + problems[0],
                         evidence={"problems": problems})
    version_digest = policy_version(policy)

    def decide(result, rule, reason, **fields):
        return _decision(result, rule, reason, policy_version=version_digest, **fields)

    parsed = parse_requirement(_requirement_text(requirement), "gate")
    if parsed["kind"] != "requirement":
        return decide("UNRESOLVED", "REQUIREMENT_INVALID", "not a named requirement: " + parsed["reason"],
                      requested=parsed["raw"])
    name = parsed["canonical_name"]
    fields = {"package": name, "version": parsed["version"], "requested": parsed["raw"]}

    for entry in policy["denied_packages"]:
        if _denied_name(entry) == name:
            reason = entry.get("reason") or "explicitly forbidden dependency"
            return decide("BLOCK", "DENYLIST", f"{name} is on the project denylist: {reason}",
                          evidence={"denied_package": entry}, **fields)

    if not parsed["pinned"]:
        return decide("BLOCK", "NOT_PINNED",
                      f"{parsed['raw']} is not pinned to one exact version with ==", **fields)

    requested = Version(parsed["version"])
    for_name = [entry for entry in policy["approved_requirements"] if _approved_entry(entry).name == name]
    matching = [entry for entry in for_name
                if _approved_entry(entry).specifier.contains(requested, prereleases=True)]
    if not matching:
        reason = (f"{name} is not on the project allowlist" if not for_name else
                  f"{name} {parsed['version']} is not an approved version; approved: {', '.join(for_name)}")
        return decide("BLOCK", "NOT_ON_ALLOWLIST", reason, evidence={"approved_for_name": for_name}, **fields)

    locked = None
    if lockfile is not None:
        problems = lockfile_problems(lockfile)
        if problems:
            return decide("UNRESOLVED", "LOCKFILE_INVALID", "project lockfile is not usable: " + problems[0],
                          evidence={"problems": problems}, **fields)
        same_name = [entry for entry in lockfile["packages"]
                     if _is_pypi(entry) and canonicalize_name(entry["name"]) == name]
        locked = next((entry for entry in same_name if _version(entry["version"]) == requested), None)
        if locked is None:
            return decide("BLOCK", "NOT_IN_LOCKFILE",
                          f"{name} {parsed['version']} is not in the project lockfile",
                          evidence={"locked_versions": [entry["version"] for entry in same_name]}, **fields)
        locked = {"name": locked["name"], "version": locked["version"]}

    return decide("PERMITTED", "ALLOWED", f"{name}=={parsed['version']} satisfies approved requirement {matching[0]}",
                  evidence={"approved_requirement": matching[0], "lockfile": locked}, **fields)


def evaluate_capture(record, policy, lockfile=None) -> dict:
    """Judge a whole capture record (from `capture.py` or `manifest_parser.py`).

    BLOCK if any requirement is blocked. Otherwise UNRESOLVED if the capture is not complete
    (something in it was unsupported or unreadable) or any requirement is unresolved.
    PERMITTED only when the capture is complete and every requirement is permitted.
    Constraints (`-c` files) are not judged: they do not ask for anything to be installed.
    """
    if policy is None or policy_problems(policy):
        decision = evaluate_requirement("", policy)
        decision["decisions"] = []
        return decision
    if not isinstance(record, dict):
        record = {}
    requirements = record.get("requirements")
    if not isinstance(requirements, list):
        requirements = []
    decisions = [evaluate_requirement(requirement, policy, lockfile) for requirement in requirements]

    def overall(result, rule, reason, evidence=None):
        decision = _decision(result, rule, reason, policy_version=policy_version(policy), evidence=evidence)
        decision["decisions"] = decisions
        return decision

    blocked = next((d for d in decisions if d["result"] == "BLOCK"), None)
    if blocked:
        return overall("BLOCK", blocked["rule"], blocked["reason"], blocked["evidence"])
    if record.get("complete") is not True:
        return overall("UNRESOLVED", "CAPTURE_INCOMPLETE", "the request was not fully captured",
                       {"unsupported": record.get("unsupported", []), "errors": record.get("errors", [])})
    unresolved = next((d for d in decisions if d["result"] != "PERMITTED"), None)
    if unresolved:
        return overall("UNRESOLVED", unresolved["rule"], unresolved["reason"], unresolved["evidence"])
    if not decisions:
        return overall("PERMITTED", "NOTHING_TO_VERIFY", "no requirement was added or changed")
    return overall("PERMITTED", "ALLOWED", f"all {len(decisions)} requirements are permitted")


def load_json_file(path):
    """Parsed JSON from `path`; None when the file does not exist; `Unreadable` when it cannot be used."""
    path = Path(path)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return Unreadable(f"cannot read {path}: {exc}")
    if data is None:
        return Unreadable(f"{path} contains null")
    return data


def gate_from_files(target, policy_path, lockfile_path=None) -> dict:
    """Run the gate with the policy and lockfile read from disk.

    `target` is one requirement or a capture record. A missing lockfile means the project
    has no lockfile (the rule is skipped); a missing policy is UNRESOLVED.
    """
    policy = load_json_file(policy_path)
    lockfile = load_json_file(lockfile_path) if lockfile_path is not None else None
    if isinstance(target, dict) and "requirements" in target:
        return evaluate_capture(target, policy, lockfile)
    return evaluate_requirement(target, policy, lockfile)


def check_requirement_gate(package_name: str, version: str) -> dict:
    """Entry point of the dashboard path (`backend/cavr/api.py`), kept with its old keys.

    It checks `name==version` against `project_policy.json` with the rules above. No lockfile
    is passed: the dashboard path has no project directory until step 13.
    """
    decision = gate_from_files(f"{package_name}=={version}", POLICY_PATH)
    return {
        **decision,
        "status": "PASS" if decision["result"] == "PERMITTED" else "FAIL",
        "matched_rule": decision["rule"],
        "rule_checked": RULE_TITLES[decision["rule"]],
        "policy_file_excerpt": json.dumps(decision["evidence"], sort_keys=True),
    }


# --- internals ---------------------------------------------------------------

def _decision(result, rule, reason, policy_version=None, package=None, version=None, requested=None, evidence=None) -> dict:
    return {"result": result, "rule": rule, "reason": reason, "package": package, "version": version,
            "requested": requested, "policy_version": policy_version, "evidence": evidence or {}}


def _requirement_text(requirement) -> str:
    """`name` + `specifier` of a record, or the string itself. Anything else gives "" (not a requirement)."""
    if isinstance(requirement, str):
        return requirement
    if isinstance(requirement, dict):
        name, specifier = requirement.get("name"), requirement.get("specifier", "")
        if isinstance(name, str) and isinstance(specifier, str):
            return name + specifier
    return ""


def _approved_entry(entry):
    """An allowlist entry as a Requirement with a canonical name, or None if it is not `name[specifier]` only."""
    if not isinstance(entry, str):
        return None
    try:
        requirement = Requirement(entry)
    except InvalidRequirement:
        return None
    if requirement.url or requirement.marker or requirement.extras:
        return None
    requirement.name = canonicalize_name(requirement.name)
    return requirement


def _denied_name(entry):
    """Canonical name of a denylist entry, or None if the entry is not {"name": "<package name>", ...}."""
    if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
        return None
    if not isinstance(entry.get("reason", ""), str):
        return None
    try:
        requirement = Requirement(entry["name"])
    except InvalidRequirement:
        return None
    if requirement.url or requirement.marker or requirement.extras or requirement.specifier:
        return None
    return canonicalize_name(requirement.name)


def _is_pypi(entry: dict) -> bool:
    return entry["ecosystem"].lower() == "pypi"


def _version(text: str):
    try:
        return Version(text)
    except InvalidVersion:
        return None
