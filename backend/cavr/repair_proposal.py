"""Repair proposal for a REJECTED package (FR-7; the fast-gate part of FR-8). It proposes; it never applies (Q9).

`propose_repair(verdict, package, project_dir=..., policy=...)` takes one package verdict of
`pipeline.verify_request` and returns a repair block. It never raises, never writes to the project, and never
changes the verdict it was given or the gate decision made from it: the block is extra information for a person.

When a repair is attempted: the package is REJECTED by an advisory (stage `advisories`) or its file did not match
the registry digest (`HASH_MISMATCH`). Anything else gets NOT_ATTEMPTED.

Pin candidates, in this order:

    1. every release of the package from the registry (`pypi_client.fetch_releases`)
    2. newer than the rejected version, not a pre-release, not yanked, with at least one wheel
    3. not affected by any advisory of OSV's package-wide answer (`advisories.package_advisories`,
       stale after 24 hours; without a usable answer there is no pin proposal)
    4. same major version first, then the next major versions; smallest upgrade first
    5. at most `max_candidates` (5), within `budget_seconds` (60), the budget checked before each candidate

Each candidate is re-checked as if it had been requested: the project is copied to a temporary directory
(symbolic links are not followed; a link that points outside the project is not copied), the patch is applied to
the copy (requirements line, lockfile entry with the registry SHA-256, the policy's `approved_requirements`) and
`verify_request` runs on the copy under the patched policy, with a fresh quarantine and no store (the re-check is
neither logged nor cached). The copy must read exactly as the project did (same result and sources digest),
otherwise the re-check would be about another project and there is no repair. Only a VERIFIED, not escalated
re-check whose wheel has the registry digest becomes the proposal; every other candidate is skipped with its reason.

Removal is proposed only when the project was fully read and never imports the package, the package is a line
of the requirements file, and nothing depends on it: no other package of the verdict has it in its tree and no
lockfile edge points to it (a lockfile that locks other packages but records no edges cannot tell, so no removal).

Result: PROPOSED (a pin, a removal, or both), NO_REPAIR_FOUND, or NOT_ATTEMPTED. Any exception gives
NO_REPAIR_FOUND / INTERNAL_ERROR. Project tests are not run (Q10), which every block states.
"""
from __future__ import annotations
import copy
import difflib
import hashlib
import json
import os
import shutil
import stat
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from backend.cavr.advisories import match_advisory, package_advisories, summarise_ids
from backend.cavr.capture import parse_requirements_text
from backend.cavr.context_extractor import SKIPPED_DIRECTORY_NAMES, _is_virtualenv, extract_project_context
from backend.cavr.manifest_parser import snapshot_requirements
from backend.cavr.pipeline import LOCKFILE_NAME, verify_request
from backend.cavr.pypi_client import fetch_releases, release_wheel
from backend.cavr.requirement_gate import _approved_entry, load_json_file

SCHEMA = "cavr.repair.v1"
MAX_CANDIDATES = 5
BUDGET_SECONDS = 60.0
MAX_COPY_FILES = 20000
MAX_COPY_BYTES = 200 * 1024 * 1024
COPY_SKIPPED = SKIPPED_DIRECTORY_NAMES   # and every dot-directory and virtual environment, as context_extractor
LIMITATIONS = (
    "project tests were not run on the proposal (Q10: waiting for SATRA's project image builder)",
    "fast-gate re-check only: no sandbox and no deep analysis; an escalated candidate is skipped",
    "only newer releases of the same package are considered: no downgrades, no pre-releases, no other package",
    "a candidate's new dependencies must already be pinned in the lockfile; there is no resolver",
    "the time budget is checked before each candidate; a candidate being checked is not interrupted",
    "a rewritten `--hash` line carries the hash of the wheel this host would install only",
)
REMOVAL_LIMITATION = ("removal is judged from the project's Python imports only: command-line use, plugins, entry points "
                      "and imports by string are not seen")


def propose_repair(verdict, package, *, project_dir, policy, requirements_file=None, lockfile_name=LOCKFILE_NAME,
                   transport=None, osv=None, advisory_cache_dir=None, live_advisories=True, knowledge=None,
                   environment=None, work_dir=None, max_candidates=MAX_CANDIDATES, budget_seconds=BUDGET_SECONDS,
                   clock=time.monotonic, now=None) -> dict:
    """The repair block for `package` (one entry of `verdict["packages"]`). Never raises.

    `requirements_file` is the project-relative requirements file the request came from (None for a pip command).
    `work_dir` is where the temporary copy is made (removed afterwards). `clock` (seconds) and `now` (a datetime)
    replace the time in tests: `clock` for the budget, `now` for the age of the package-wide OSV answer.
    """
    name = canonicalize_name(str((package or {}).get("package") or "")) or None
    version = (package or {}).get("version")
    try:
        return _propose(verdict, package, name, version, SimpleNamespace(
            project_dir=project_dir, policy=policy, requirements_file=requirements_file, lockfile_name=lockfile_name,
            transport=transport, osv=osv, advisory_cache_dir=advisory_cache_dir, live_advisories=live_advisories,
            knowledge=knowledge, environment=environment, work_dir=work_dir, max_candidates=max_candidates,
            budget_seconds=budget_seconds, clock=clock, now=now))
    except Exception as exc:  # a fault in repair is "no repair", never a changed verdict
        return no_repair(name, version, package, "INTERNAL_ERROR", f"repair failed: {type(exc).__name__}: {exc}")


def no_repair(name, version, package, rule, reason) -> dict:
    """NO_REPAIR_FOUND with every key of a block; the package stays as judged."""
    return _block("NO_REPAIR_FOUND", rule, reason, name, version, package)


# --- the steps ---------------------------------------------------------------------------------------------------

def _propose(verdict, package, name, version, run) -> dict:
    block = _block(None, None, None, name, version, package)
    if not isinstance(package, dict) or package.get("status") != "REJECTED":
        return _finish(block, "NOT_ATTEMPTED", "NOT_REJECTED", "the package is not REJECTED; there is nothing to repair")
    if not _repairable(package):
        return _finish(block, "NOT_ATTEMPTED", "NOT_REPAIRABLE",
                       f"repair covers advisory and hash-mismatch rejections; this one is {package.get('stage')} / "
                       f"{package.get('rule')}")
    project_dir = Path(run.project_dir)
    work = Path(tempfile.mkdtemp(prefix="cavr-repair-", dir=_work_parent(run.work_dir)))
    try:
        copied = work / "project"
        try:
            block["project_copy"] = copy_project(project_dir, copied)
        except OSError as exc:
            return _finish(block, "NO_REPAIR_FOUND", "COPY_FAILED", f"the project could not be copied for the re-check: {exc}")
        problem = _copy_problem(verdict, project_dir, copied, run.requirements_file, run.lockfile_name)
        block["project_copy"]["matches_project"] = problem is None
        if problem:
            return _finish(block, "NO_REPAIR_FOUND", "COPY_DIFFERS", problem)
        files = _ProjectFiles(copied, run.requirements_file, run.lockfile_name)
        pin_rule, pin_reason = _search_pins(block, package, name, version, files, work, run)
        _search_removal(block, verdict, package, name, version, files, work, run)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if block["pin"] or block["removal"]:
        what = " and ".join(part for part, there in (
            (f"pin {block['pin']['requirement']}" if block["pin"] else "", block["pin"]),
            (f"remove {name}", block["removal"])) if there)
        return _finish(block, "PROPOSED", "REPAIR_PROPOSED", f"proposed for a person to approve: {what}; not applied")
    return _finish(block, "NO_REPAIR_FOUND", pin_rule, pin_reason)


def _repairable(package: dict) -> bool:
    return package.get("stage") == "advisories" or (package.get("stage") == "artifact" and package.get("rule") == "HASH_MISMATCH")


def _search_pins(block, package, name, version, files, work, run):
    """Fill `block` with the pin search; return (rule, reason) for the case that no pin is found."""
    started = run.clock()   # the budget covers the release list, the advisory screen and every re-check
    releases = fetch_releases(name, transport=run.transport)
    block["registry"] = {key: releases.get(key) for key in ("result", "rule", "reason", "url", "response_sha256")}
    if releases["result"] != "OK":
        return releases["rule"], f"the registry's release list could not be read: {releases['reason']}"
    if files.requirements_file is not None and files.requirement_line(name, version) is None:
        return "REQUIREMENT_LINE_NOT_FOUND", (f"{name}=={version} is not exactly one line of {files.requirements_file} "
                                              "(it may come from an included file); a pin cannot be proposed as a patch")
    rejected = Version(version)
    upgrades = []
    for release in releases["releases"]:
        parsed = release["parsed"]
        if parsed is None or parsed <= rejected:
            continue
        if parsed.is_prerelease or parsed.is_devrelease:
            block["excluded"].append({"version": release["version"], "rule": "PRE_RELEASE", "reason": "pre-release"})
        elif release["yanked"]:
            block["excluded"].append({"version": release["version"], "rule": "YANKED",
                                      "reason": f"yanked: {release['yanked_reason']}"})
        elif not release["has_wheel"]:
            block["excluded"].append({"version": release["version"], "rule": "NO_WHEEL", "reason": "no wheel on PyPI"})
        else:
            upgrades.append(release)
    if not upgrades:
        return "NO_SAFE_CANDIDATE", f"no newer release of {name} with a wheel that is not yanked"

    screen = package_advisories(name, run.advisory_cache_dir, live=run.live_advisories, osv=run.osv, now=run.now)
    block["advisory_screen"] = {key: screen.get(key) for key in ("result", "rule", "reason", "mode", "retrieved_at",
                                                                  "age_hours", "response_sha256", "advisory_count")}
    if screen["result"] != "OK":
        return screen["rule"], f"no usable package-wide OSV answer for {name}: {screen['reason']}"
    candidates = []
    for release in upgrades:
        matches = [match_advisory(name, release["version"], vuln) for vuln in screen["vulnerabilities"]]
        affected = [m["id"] for m in matches if m["status"] == "AFFECTED"]
        unknown = [m["id"] for m in matches if m["status"] == "UNKNOWN"]
        if affected:
            block["excluded"].append({"version": release["version"], "rule": "ADVISORY_AFFECTED",
                                      "reason": f"{len(affected)} advisories: {summarise_ids(affected)}"})
        elif unknown:
            block["excluded"].append({"version": release["version"], "rule": "ADVISORY_RANGE_UNKNOWN",
                                      "reason": f"{len(unknown)} advisory ranges cannot be evaluated: {summarise_ids(unknown)}"})
        else:
            candidates.append(release)
    candidates.sort(key=lambda release: (release["parsed"].major != rejected.major, release["parsed"]))
    if not candidates:
        return "NO_SAFE_CANDIDATE", f"every newer release of {name} with a wheel is affected by a known advisory"

    budget = block["budget"]
    budget.update(max_candidates=run.max_candidates, seconds=run.budget_seconds)
    for position, release in enumerate(candidates):
        if len(block["candidates_tried"]) >= run.max_candidates:
            budget["stopped_by"] = "candidates"
        elif run.clock() - started >= run.budget_seconds:
            budget["stopped_by"] = "time"
        if budget["stopped_by"]:
            block["not_tried"] = [left["version"] for left in candidates[position:]]
            break
        outcome, pin = _check_pin(name, version, release["version"], package, files, work, run)
        block["candidates_tried"].append(outcome)
        if pin:
            block["pin"] = pin
            block["not_tried"] = [left["version"] for left in candidates[position + 1:]]
            if pin["parsed"].major != rejected.major:
                block["limitations"].append(f"major version change ({rejected.major} -> {pin['parsed'].major}), "
                                            "may break the project; project tests not run")
            del pin["parsed"]
            break
    budget["tried"] = len(block["candidates_tried"])
    budget["elapsed_s"] = round(run.clock() - started, 3)
    if block["pin"]:
        return None, None
    if budget["stopped_by"]:
        return "BUDGET_EXHAUSTED", (f"the repair budget ({run.max_candidates} candidates, {run.budget_seconds} s) ended "
                                    f"after {budget['tried']} candidates without a safe one")
    return "NO_SAFE_CANDIDATE", f"none of the {budget['tried']} candidates passed the re-check"


def _check_pin(name, rejected, candidate, package, files, work, run):
    """(candidate record, pin proposal or None): the patch applied to the copy and re-checked with `verify_request`."""
    record = {"version": candidate, "outcome": "SKIPPED", "status": None, "stage": None, "rule": None, "reason": None,
              "escalated": False}

    def skip(status, stage, rule, reason, escalated=False):
        record.update(status=status, stage=stage, rule=rule, reason=reason, escalated=escalated)
        return record, None

    wheel = release_wheel(name, candidate, transport=run.transport)
    if wheel["result"] != "OK":
        return skip("UNRESOLVED", "artifact", wheel["rule"], wheel["reason"])
    requirement = f"{name}=={candidate}"
    requirements = files.pin_requirements(name, rejected, candidate, wheel["sha256"])
    lock = files.pin_lockfile(name, rejected, candidate, wheel["sha256"])
    policy = _policy_for_pin(run.policy, name, rejected, candidate)
    try:
        request, shown = files.apply(requirements, lock, fallback=["pip", "install", requirement])
        checked = verify_request(request, files.root, policy["policy"], None, transport=run.transport,
                                 quarantine_dir=work / "quarantine" / candidate, advisory_cache_dir=run.advisory_cache_dir,
                                 live_advisories=run.live_advisories, osv=run.osv, knowledge=run.knowledge,
                                 environment=run.environment, lockfile_name=files.lockfile_name)
    finally:
        files.restore()
    found = next((p for p in checked.get("packages") or [] if canonicalize_name(str(p.get("package"))) == name
                  and _same_version(p.get("version"), candidate)), None)
    if checked["status"] != "VERIFIED" or checked.get("escalated") or found is None or found["status"] != "VERIFIED":
        source = found if found is not None and found["status"] != "VERIFIED" else checked
        return skip(source["status"], source["stage"], source["rule"], source["reason"], bool(checked.get("escalated")))
    artifact = (found.get("evidence") or {}).get("artifact") or {}
    if artifact.get("sha256") != wheel["sha256"] or artifact.get("registry_sha256") not in (None, wheel["sha256"]):
        return skip("UNRESOLVED", "artifact", "RECHECK_DIGEST_DIFFERS",
                    f"the re-checked wheel has sha256 {artifact.get('sha256')}; the registry lists {wheel['sha256']}")
    record.update(outcome="PROPOSED", status="VERIFIED", stage=checked["stage"], rule=checked["rule"], reason=checked["reason"])
    pin = {"requirement": requirement, "name": name, "version": candidate, "parsed": Version(candidate),
           "requirements_file": files.requirements_file,
           "requirements_diff": requirements["diff"] if requirements else None,
           "pip_command": None if requirements else f"pip install {requirement}",
           "lockfile_entry": lock and {"file": files.lockfile_name, "before": lock["before"], "after": lock["after"]},
           "policy": policy["summary"], "recheck": _recheck_evidence(checked, found, shown, wheel)}
    return record, pin


def _search_removal(block, verdict, package, name, version, files, work, run):
    reason = _removal_problem(verdict, package, name, version, files)
    if reason:
        block["removal_reason"] = reason
        return
    requirements = files.remove_requirement(name, version)
    lock = files.remove_lockfile_entry(name, version)
    try:
        request, shown = files.apply(requirements, lock)
        checked = verify_request(request, files.root, copy.deepcopy(run.policy), None, transport=run.transport,
                                 quarantine_dir=work / "quarantine" / "removal", advisory_cache_dir=run.advisory_cache_dir,
                                 live_advisories=run.live_advisories, osv=run.osv, knowledge=run.knowledge,
                                 environment=run.environment, lockfile_name=files.lockfile_name)
    finally:
        files.restore()
    if checked["status"] != "VERIFIED":
        block["removal_reason"] = f"the removal did not pass the re-check: {checked['status']} {checked['rule']}: {checked['reason']}"
        return
    block["removal"] = {"name": name, "version": version, "requirements_file": files.requirements_file,
                        "requirements_diff": requirements["diff"],
                        "lockfile_entry": lock and {"file": files.lockfile_name, "before": lock["before"], "after": None},
                        "policy": {"changed": False, "added": [], "removed": [],
                                   "approved_requirements": {"before": list(run.policy.get("approved_requirements") or []),
                                                             "after": list(run.policy.get("approved_requirements") or [])}},
                        "recheck": _recheck_evidence(checked, None, shown, None)}
    block["limitations"].append(REMOVAL_LIMITATION)


def _removal_problem(verdict, package, name, version, files):
    """Why the package may not be removed, or None when it may."""
    if package.get("rule") == "HASH_MISMATCH":
        return "the wheel failed its hash check, so its import names cannot be trusted; removal is never proposed for it"
    contract = (package.get("evidence") or {}).get("contract")
    if not isinstance(contract, dict) or not contract.get("import_names"):
        return "the package's import names are not known, so the project's use of it cannot be checked"
    project = (verdict or {}).get("project") or {}
    if project.get("result") != "OK" or contract.get("sources_digest") != project.get("sources_digest"):
        return "the project's source was not fully read, so an unseen import cannot be ruled out"
    for key, how in (("imports", "imported"), ("star_imports", "star-imported"), ("call_sites", "called"),
                     ("references", "referenced")):
        used = contract.get(key) or []
        if used:
            first = used[0]
            return f"the project uses it: {how} at {first.get('file')}:{first.get('line')}"
    if files.requirements_file is None:
        return "the request was a pip command; there is no requirements line to remove"
    if files.requirement_line(name, version) is None:
        return f"{name}=={version} is not a line of {files.requirements_file} (it may come from an included file)"
    for other in (verdict or {}).get("packages") or []:
        if other is package:
            continue
        tree = (other.get("evidence") or {}).get("tree") or {}
        if tree.get("result") != "OK":
            return (f"the dependency tree of {other.get('package')}=={other.get('version')} is not complete, so it may "
                    f"depend on {name}")
        nodes = tree.get("nodes") or []
        if any(canonicalize_name(str(node.get("name"))) == name for node in nodes):
            return f"{other.get('package')}=={other.get('version')} depends on it (its dependency tree contains {name})"
    return files.lockfile_dependents_problem(name)


# --- project copy ------------------------------------------------------------------------------------------------

def copy_project(source: Path, target: Path) -> dict:
    """Copy `source` to `target` without following any symbolic link. Returns what was copied and skipped.

    A link whose target lies inside the project is recreated as a relative link (it is never followed, so the
    copy reads it exactly as the project does). A link that points outside the project is not copied. The
    directories `context_extractor` does not read are not copied either: dot-directories (`.git`, `.env` folders),
    virtual environments, `__pycache__`, `node_modules`. Only regular files are copied.
    """
    root = source.resolve(strict=True)
    if not stat.S_ISDIR(os.lstat(root).st_mode):
        raise NotADirectoryError(str(source))
    summary = {"files": 0, "bytes": 0, "skipped_symlinks": [], "symlinks_kept": [], "skipped_directories": [],
               "matches_project": None}
    target.mkdir(parents=True)
    for base, directories, names in os.walk(root, followlinks=False):
        here = Path(base)
        relative_base = here.relative_to(root)
        kept = []
        for name in sorted(directories) + sorted(names):
            path, relative = here / name, (relative_base / name).as_posix()
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode):
                _copy_link(root, path, target / relative_base / name, relative, summary)
            elif stat.S_ISDIR(info.st_mode):
                if name.startswith(".") or name in COPY_SKIPPED or _is_virtualenv(path):
                    summary["skipped_directories"].append(relative)
                else:
                    (target / relative_base / name).mkdir()
                    kept.append(name)
            elif stat.S_ISREG(info.st_mode):
                summary["files"] += 1
                summary["bytes"] += info.st_size
                if summary["files"] > MAX_COPY_FILES or summary["bytes"] > MAX_COPY_BYTES:
                    raise OSError(f"the project is over the copy budget ({MAX_COPY_FILES} files, {MAX_COPY_BYTES} bytes)")
                shutil.copyfile(path, target / relative_base / name, follow_symlinks=False)
        directories[:] = [name for name in directories if name in kept]
    return summary


def _copy_link(root: Path, path: Path, destination: Path, relative: str, summary: dict) -> None:
    pointed = os.readlink(path)
    resolved = (path.parent / pointed).resolve()   # where it ends up; nothing is opened or read through it
    if resolved != root and root not in resolved.parents:
        summary["skipped_symlinks"].append({"path": relative, "reason": "points outside the project"})
        return
    os.symlink(os.path.relpath(resolved, path.parent.resolve()), destination)
    summary["symlinks_kept"].append(relative)


def _copy_problem(verdict, project_dir: Path, copied: Path, requirements_file, lockfile_name):
    """None when the copy reads exactly as the project did for the verdict; otherwise why not.

    Compared: the project context (result, rule, sources digest), and the bytes of the lockfile and of the
    requirements file. A lockfile or requirements file that is a link out of the project is not copied, so the
    re-check would run without it: that is a difference, not a pass.
    """
    for relative in [lockfile_name] + ([requirements_file] if requirements_file else []):
        if _file_digest(project_dir / relative) != _file_digest(copied / relative):
            return (f"{relative} in the project copy differs from the project's (for example a link out of the "
                    "project, which is not copied); a re-check of the copy would not be about this project")
    original = (verdict or {}).get("project") or {}
    now = extract_project_context(copied)
    seen = (now["result"], now["rule"], now["sources_digest"])
    expected = (original.get("result"), original.get("rule"), original.get("sources_digest"))
    if seen != expected:
        return (f"the project copy does not read like the project did (project {expected[0]} {expected[1]}, "
                f"copy {seen[0]} {seen[1]}); a re-check of the copy would not be about this project")
    return None


def _read_text(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def _file_digest(path: Path):
    """(exists, SHA-256 of the bytes) of a file as the pipeline would read it; ("unreadable", reason) on an error."""
    try:
        return True, hashlib.sha256(path.read_bytes()).hexdigest()
    except FileNotFoundError:
        return False, None
    except OSError as exc:
        return "unreadable", exc.strerror or str(exc)


def _work_parent(work_dir):
    if work_dir is None:
        return None
    Path(work_dir).mkdir(parents=True, exist_ok=True)
    return str(work_dir)


class _ProjectFiles:
    """The requirements file and lockfile of the project copy: patches as text, applied and restored in place."""

    def __init__(self, root: Path, requirements_file, lockfile_name):
        self.root, self.requirements_file, self.lockfile_name = root, requirements_file, lockfile_name
        self.requirements_path = root / requirements_file if requirements_file else None
        self.lockfile_path = root / lockfile_name
        # Bytes, decoded without newline translation: a CRLF file keeps its line endings in the patch and the diff.
        self.requirements_text = (_read_text(self.requirements_path)
                                  if self.requirements_path is not None and self.requirements_path.is_file() else None)
        self.lockfile_text = _read_text(self.lockfile_path) if self.lockfile_path.is_file() else None
        self.lockfile = load_json_file(self.lockfile_path)

    # requirements
    def requirement_line(self, name, version):
        """(entry, first line, end line) of the one requirement line `name==version`, or None."""
        if self.requirements_text is None:
            return None
        found = [entry for entry in parse_requirements_text(self.requirements_text, self.requirements_file)
                 if entry.get("kind") == "requirement" and entry.get("canonical_name") == name
                 and _same_version(entry.get("version"), version)]
        if len(found) != 1:
            return None
        lines = self.requirements_text.splitlines(keepends=True)
        start = int(str(found[0]["origin"]).rsplit(":", 1)[1]) - 1
        end = start + 1
        while end <= len(lines) and lines[end - 1].rstrip("\r\n").endswith("\\"):
            end += 1
        return found[0], start, min(end, len(lines))

    def pin_requirements(self, name, rejected, candidate, sha256):
        """The requirements text with the rejected line pinned to `candidate`; None without a requirements file."""
        if self.requirements_file is None:
            return None
        entry, start, end = self.requirement_line(name, rejected)
        lines = self.requirements_text.splitlines(keepends=True)
        last = lines[end - 1]
        ending = "\r\n" if last.endswith("\r\n") else "\n" if last.endswith("\n") else ""
        extras = f"[{','.join(entry['extras'])}]" if entry.get("extras") else ""
        line = f"{entry['name']}{extras}=={candidate}"
        if entry.get("marker"):
            line += f" ; {entry['marker']}"
        if entry.get("hashes"):
            line += f" --hash=sha256:{sha256}"
        return self._patched(lines[:start] + [line + ending] + lines[end:])

    def remove_requirement(self, name, version):
        _, start, end = self.requirement_line(name, version)
        lines = self.requirements_text.splitlines(keepends=True)
        return self._patched(lines[:start] + lines[end:])

    def _patched(self, lines):
        text = "".join(lines)
        diff = "".join(difflib.unified_diff(self.requirements_text.splitlines(keepends=True), text.splitlines(keepends=True),
                                            fromfile=f"a/{self.requirements_file}", tofile=f"b/{self.requirements_file}"))
        return {"text": text, "diff": diff}

    # lockfile
    def pin_lockfile(self, name, rejected, candidate, sha256):
        if not isinstance(self.lockfile, dict) or not isinstance(self.lockfile.get("packages"), list):
            return None
        lockfile = copy.deepcopy(self.lockfile)
        after = {"name": name, "version": candidate, "ecosystem": "PyPI", "sha256": sha256}
        position = self._locked(lockfile, name, rejected)
        before = lockfile["packages"][position] if position is not None else None
        if position is None:
            lockfile["packages"].append(after)
        else:
            lockfile["packages"][position] = after
        return {"before": copy.deepcopy(before), "after": after, "lockfile": lockfile}

    def remove_lockfile_entry(self, name, version):
        if not isinstance(self.lockfile, dict) or not isinstance(self.lockfile.get("packages"), list):
            return None
        lockfile = copy.deepcopy(self.lockfile)
        position = self._locked(lockfile, name, version)
        if position is None:
            return None
        before = lockfile["packages"].pop(position)
        if isinstance(lockfile.get("edges"), list):
            lockfile["edges"] = [edge for edge in lockfile["edges"]
                                 if not (isinstance(edge, dict) and canonicalize_name(str(edge.get("source"))) == name)]
        return {"before": before, "after": None, "lockfile": lockfile}

    def lockfile_dependents_problem(self, name):
        """Why the lockfile cannot rule out a dependent of `name`, or None when nothing in it depends on `name`."""
        if self.lockfile is None:
            return "the project has no lockfile, so packages that depend on it cannot be ruled out"
        if not isinstance(self.lockfile, dict) or not isinstance(self.lockfile.get("packages"), list):
            return "the project lockfile cannot be read, so packages that depend on it cannot be ruled out"
        others = [entry for entry in self.lockfile["packages"]
                  if not (isinstance(entry, dict) and canonicalize_name(str(entry.get("name"))) == name)]
        edges = self.lockfile.get("edges")
        if edges is None:
            if others:
                return "the lockfile locks other packages but records no dependencies (no edges), so a dependent cannot be ruled out"
            return None
        if not isinstance(edges, list) or not all(isinstance(edge, dict) and isinstance(edge.get("source"), str)
                                                  and isinstance(edge.get("target"), str) for edge in edges):
            return "the lockfile's edges are not a list of {source, target}, so a dependent cannot be ruled out"
        dependents = sorted({edge["source"] for edge in edges if canonicalize_name(edge["target"]) == name
                             and canonicalize_name(edge["source"]) != name})
        if dependents:
            return f"the lockfile records that {', '.join(dependents)} depends on it"
        return None

    @staticmethod
    def _locked(lockfile, name, version):
        for position, entry in enumerate(lockfile["packages"]):
            if (isinstance(entry, dict) and str(entry.get("ecosystem", "")).lower() == "pypi"
                    and canonicalize_name(str(entry.get("name"))) == name and _same_version(entry.get("version"), version)):
                return position
        return None

    # applying a patch to the copy for one re-check
    def apply(self, requirements, lock, fallback=None):
        """Write the patch into the copy; return (request for `verify_request`, the request as text)."""
        if lock is not None:
            self.lockfile_path.write_bytes((json.dumps(lock["lockfile"], indent=2) + "\n").encode("utf-8"))
        if requirements is not None:
            before = snapshot_requirements(self.requirements_path)
            self.requirements_path.write_bytes(requirements["text"].encode("utf-8"))
            after = snapshot_requirements(self.requirements_path)
            before["path"] = after["path"] = self.requirements_file
            return {"requirements_edit": {"before": before, "after": after}}, f"requirements edit of {self.requirements_file}"
        return fallback, " ".join(fallback)

    def restore(self):
        if self.lockfile_text is not None:
            self.lockfile_path.write_bytes(self.lockfile_text.encode("utf-8"))
        if self.requirements_text is not None:
            self.requirements_path.write_bytes(self.requirements_text.encode("utf-8"))


# --- small pieces ------------------------------------------------------------------------------------------------

def _policy_for_pin(policy, name, rejected, candidate):
    """The policy as it would be after the patch, and a summary of the change to `approved_requirements`."""
    patched = copy.deepcopy(policy)
    before = list(policy.get("approved_requirements") or [])
    after = list(before)
    wanted = Version(candidate)
    covered = any((entry := _approved_entry(item)) is not None and entry.name == name
                  and entry.specifier.contains(wanted, prereleases=True) for item in before)
    added, removed = [], []
    if not covered:
        exact = next((i for i, item in enumerate(after) if (entry := _approved_entry(item)) is not None
                      and entry.name == name and _is_exact_pin(entry.specifier, rejected)), None)
        new = f"{name}=={candidate}"
        if exact is None:
            after.append(new)
        else:
            removed.append(after[exact])
            after[exact] = new
        added.append(new)
    patched["approved_requirements"] = after
    return {"policy": patched, "summary": {"changed": bool(added or removed), "added": added, "removed": removed,
                                           "approved_requirements": {"before": before, "after": after}}}


def _recheck_evidence(checked, package, shown, wheel) -> dict:
    evidence = (package or {}).get("evidence") or {}
    artifact, tree = evidence.get("artifact") or {}, evidence.get("tree") or {}
    return {"request": shown, "status": checked["status"], "stage": checked["stage"], "rule": checked["rule"],
            "reason": checked["reason"], "escalated": bool(checked.get("escalated")),
            "policy_version": checked.get("policy_version"), "analyzer_version": checked.get("analyzer_version"),
            "fast_gate_ms": checked.get("fast_gate_ms"),
            "package": None if package is None else {
                "status": package["status"], "rule": package["rule"], "sha256": artifact.get("sha256"),
                "registry_sha256": wheel["sha256"] if wheel else None, "filename": artifact.get("filename"),
                "subtree_digest": tree.get("subtree_digest"),
                "tree_nodes": [{k: node.get(k) for k in ("name", "version", "sha256")} for node in tree.get("nodes") or []],
                "advisories": [{k: a.get(k) for k in ("name", "version", "result", "rule", "advisory_count", "mode",
                                                      "retrieved_at", "response_sha256")}
                               for a in evidence.get("advisories") or []],
                "contract_rule": (evidence.get("contract") or {}).get("rule")}}


def _is_exact_pin(specifier, version) -> bool:
    """`specifier` is one `==` clause for exactly `version` (`==5.1` matches 5.1.0)."""
    clauses = list(specifier)
    return (len(clauses) == 1 and clauses[0].operator == "==" and "*" not in clauses[0].version
            and _same_version(clauses[0].version, version))


def _same_version(left, right) -> bool:
    try:
        return Version(str(left)) == Version(str(right))
    except InvalidVersion:
        return False


def _block(result, rule, reason, name, version, package) -> dict:
    package = package if isinstance(package, dict) else {}
    return {"schema": SCHEMA, "result": result, "rule": rule, "reason": reason, "package": name, "version": version,
            "rejected": {key: package.get(key) for key in ("status", "stage", "rule", "reason")},
            "applied": False, "gate_decision_changed": False, "pin": None, "removal": None, "removal_reason": None,
            "candidates_tried": [], "excluded": [], "not_tried": [],
            "budget": {"max_candidates": None, "seconds": None, "tried": 0, "elapsed_s": None, "stopped_by": None},
            "registry": None, "advisory_screen": None, "project_copy": None, "limitations": list(LIMITATIONS)}


def _finish(block, result, rule, reason) -> dict:
    block.update(result=result, rule=rule, reason=reason)
    return block
