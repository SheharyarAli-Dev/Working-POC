"""C3: known-vulnerability check against OSV, with real version-range matching.

`check_advisories(name, version, cache_dir)` asks `backend.integrations.osv_adapter.OSV` (live
query, or its dated and digest-checked cache) and judges every advisory in the answer with
`backend.threat_repo.package_records.affected`, which follows OSV's event model:
`introduced` (inclusive), `fixed` (exclusive), `last_affected` (inclusive), `limit` (exclusive).

    INVALID_REQUEST          name or version is not usable                           -> UNRESOLVED
    ADVISORIES_UNAVAILABLE   no OSV answer: offline with no cache, a damaged cache,
                             or only PyPI's advisory list (it has no ranges)         -> UNRESOLVED
    ADVISORIES_STALE         the cached answer is older than `max_age_days`,
                             or dated in the future                                  -> UNRESOLVED
    ADVISORIES_INVALID       the answer is not a list of advisories with ids         -> UNRESOLVED
    KNOWN_VULNERABILITY      at least one advisory's range contains the version      -> REJECTED
    RANGE_UNSUPPORTED        an advisory has only ranges that cannot be evaluated
                             (GIT, unknown type, unparseable version)                -> UNRESOLVED
    RANGE_DISAGREEMENT       OSV returned an advisory for this version, but its
                             ranges do not contain the version                       -> UNRESOLVED
    NO_KNOWN_VULNERABILITY   none of the above                                       -> OK

OSV answers per version: it returns only the advisories it considers to affect that version.
The range check here is therefore a second, independent reading of the same advisory. When
both agree the version is affected -> REJECTED. When they do not agree, or the range cannot be
evaluated here, nothing is concluded -> UNRESOLVED. Withdrawn advisories are listed, not counted.

This check is never cached with the verdict: advisories change while the artifact does not.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path

from packaging.utils import canonicalize_name

from backend.cavr.pypi_client import request_problem
from backend.integrations.osv_adapter import OSV
from backend.orchestrator.hashing import digest
from backend.threat_repo.package_records import affected

MAX_AGE_DAYS = 30
FIRST_IDS = 3  # how many advisory ids a one-line summary names; the result always holds all of them
FUTURE_TOLERANCE_DAYS = 0.01  # about 15 minutes of clock difference


def check_advisories(name, version, cache_dir, live: bool = False, max_age_days: float = MAX_AGE_DAYS, osv=None) -> dict:
    """Judge `name==version` against OSV. Every result has the same keys.

    `cache_dir` is where the adapter keeps its dated answers. With `live=True` OSV is asked
    first and the cache is the fallback; with `live=False` only the cache is read. `osv` is
    any object with the adapter's `query` method (tests pass a stub).
    """
    fields = {"name": name if isinstance(name, str) else None, "version": version if isinstance(version, str) else None}

    def result(outcome, rule, reason, **more):
        return _result(outcome, rule, reason, **{**fields, **more})

    problem = request_problem(name, version)
    if problem:
        return result("UNRESOLVED", "INVALID_REQUEST", problem)
    name, version = canonicalize_name(name), version.strip()
    fields = {"name": name, "version": version, "mode": "UNAVAILABLE"}

    try:
        answer = (osv or OSV(cache_dir)).query(name, version, "PyPI", live=live, max_age_days=max_age_days)
    except Exception as exc:  # the adapter does not guard its cache reads; any failure means no answer
        return result("UNRESOLVED", "ADVISORIES_UNAVAILABLE", f"advisory lookup failed: {type(exc).__name__}: {exc}")
    if not isinstance(answer, dict) or answer.get("available") is not True:
        error = answer.get("error") if isinstance(answer, dict) else None
        age = _cached_age_days(cache_dir, name, version)
        if age is not None and age > max_age_days:
            return result("UNRESOLVED", "ADVISORIES_STALE", age_days=round(age, 2), live_error=error,
                          reason=f"the cached OSV answer is {age:.1f} days old; the limit is {max_age_days}")
        return result("UNRESOLVED", "ADVISORIES_UNAVAILABLE", f"no OSV answer for {name} {version}: {error or 'no answer'}",
                      live_error=error)

    age = _age_days(answer.get("retrieved_at"))
    fields.update(mode=answer.get("mode"), source=answer.get("source"), retrieved_at=answer.get("retrieved_at"),
                  age_days=None if age is None else round(age, 2), response_sha256=answer.get("response_sha256"),
                  live_error=answer.get("live_error"))
    if answer.get("osv_available") is False or str(answer.get("mode", "")).startswith("PYPI"):
        return result("UNRESOLVED", "ADVISORIES_UNAVAILABLE",
                      "OSV could not be asked; only PyPI's advisory list is available, which has no version ranges to check")
    if age is None or age > max_age_days or age < -FUTURE_TOLERANCE_DAYS:
        return result("UNRESOLVED", "ADVISORIES_STALE",
                      f"the OSV answer is dated {answer.get('retrieved_at')!r}; it must be at most {max_age_days} days old")

    vulns = answer.get("vulnerabilities")
    if not isinstance(vulns, list) or not all(isinstance(v, dict) and isinstance(v.get("id"), str) and v["id"] for v in vulns):
        return result("UNRESOLVED", "ADVISORIES_INVALID", "the OSV answer is not a list of advisories with ids")
    matches = sorted((match_advisory(name, version, vuln) for vuln in vulns), key=lambda match: match["id"])
    by_status = lambda *statuses: [match for match in matches if match["status"] in statuses]
    fields.update(advisory_count=len(vulns), affected=by_status("AFFECTED"), unknown=by_status("UNKNOWN"),
                  not_affected=by_status("NOT_AFFECTED", "OTHER_PACKAGE"),
                  withdrawn=[match["id"] for match in by_status("WITHDRAWN")])

    if fields["affected"]:
        ids = [match["id"] for match in fields["affected"]]
        return result("REJECTED", "KNOWN_VULNERABILITY",
                      f"{name} {version} is affected by {len(ids)} known advisories: {summarise_ids(ids)}")
    if fields["unknown"]:
        ids = [match["id"] for match in fields["unknown"]]
        return result("UNRESOLVED", "RANGE_UNSUPPORTED",
                      f"{len(ids)} advisories have ranges that cannot be evaluated: {summarise_ids(ids)}")
    if fields["not_affected"]:
        ids = [match["id"] for match in fields["not_affected"]]
        return result("UNRESOLVED", "RANGE_DISAGREEMENT",
                      f"OSV lists {len(ids)} advisories for {name} {version} whose ranges do not contain it: {summarise_ids(ids)}")
    return result("OK", "NO_KNOWN_VULNERABILITY", f"OSV lists no advisory that affects {name} {version}")


def summarise_ids(ids, limit: int | None = None) -> str:
    """`A, B, C and 94 more`: the first `limit` ids (default FIRST_IDS) and how many are left out.

    Only for a line a person reads. The lists in the result (`affected`, `unknown`,
    `not_affected`) are never shortened, so the JSON always holds every id.
    """
    limit = FIRST_IDS if limit is None else limit
    ids = [str(advisory_id) for advisory_id in ids]
    left_out = len(ids) - limit
    return ", ".join(ids[:limit]) + (f" and {left_out} more" if left_out > 0 else "")


def match_advisory(name: str, version: str, vuln: dict) -> dict:
    """Does one OSV advisory affect `name` `version`?

    `status` is AFFECTED, NOT_AFFECTED, UNKNOWN (a range cannot be evaluated), WITHDRAWN, or
    OTHER_PACKAGE (the advisory has no PyPI entry for this package).
    """
    name = canonicalize_name(name)
    entries = [entry for entry in vuln.get("affected") or [] if _is_for(entry, name)] if isinstance(vuln.get("affected"), list) else []
    match = {"id": vuln.get("id"), "status": None, "summary": vuln.get("summary"),
             "aliases": sorted(a for a in vuln.get("aliases") or [] if isinstance(a, str)) if isinstance(vuln.get("aliases"), list) else [],
             "fixed_versions": sorted({event["fixed"] for entry in entries for item in _ranges(entry) or []
                                       for event in item["events"] if isinstance(event.get("fixed"), str)})}
    if vuln.get("withdrawn"):
        match["status"] = "WITHDRAWN"
    elif not entries:
        match["status"] = "OTHER_PACKAGE"
    else:
        answers = [_entry_affects(version, entry) for entry in entries]
        match["status"] = "AFFECTED" if True in answers else "UNKNOWN" if None in answers else "NOT_AFFECTED"
    return match


# --- internals ---------------------------------------------------------------

def _result(outcome, rule, reason, name=None, version=None, mode=None, source=None, retrieved_at=None, age_days=None,
            response_sha256=None, live_error=None, advisory_count=None, affected=None, unknown=None,
            not_affected=None, withdrawn=None) -> dict:
    return {"result": outcome, "rule": rule, "reason": reason, "ecosystem": "PyPI", "name": name, "version": version,
            "mode": mode, "source": source, "retrieved_at": retrieved_at, "age_days": age_days,
            "response_sha256": response_sha256, "live_error": live_error, "advisory_count": advisory_count,
            "affected": affected or [], "unknown": unknown or [], "not_affected": not_affected or [],
            "withdrawn": withdrawn or []}


def _is_for(entry, name: str) -> bool:
    package = entry.get("package") if isinstance(entry, dict) else None
    return (isinstance(package, dict) and package.get("ecosystem") == "PyPI"
            and isinstance(package.get("name"), str) and canonicalize_name(package["name"]) == name)


def _ranges(entry: dict):
    """The entry's ranges when they have the expected shape, otherwise None."""
    ranges = entry.get("ranges", [])
    well_formed = isinstance(ranges, list) and all(
        isinstance(item, dict) and isinstance(item.get("events", []), list)
        and all(isinstance(event, dict) for event in item.get("events", [])) for item in ranges)
    return [{**item, "events": item.get("events", [])} for item in ranges] if well_formed else None


def _entry_affects(version: str, entry: dict):
    """True / False / None (cannot tell) for one `affected` entry of an advisory."""
    ranges, versions = _ranges(entry), entry.get("versions", [])
    if ranges is None or not isinstance(versions, list):
        return None
    try:
        return affected(version, {"versions": versions, "ranges": ranges, "ecosystem": "PyPI"})
    except Exception:  # a shape `affected` does not expect: cannot tell
        return None


def _age_days(retrieved_at):
    try:
        moment = datetime.fromisoformat(retrieved_at)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - moment).total_seconds() / 86400
    except (TypeError, ValueError):
        return None


def _cached_age_days(cache_dir, name: str, version: str):
    """Age of the adapter's cache file for this query, or None when there is no readable one."""
    query = {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
    try:
        value = json.loads((Path(cache_dir) / (digest(query) + ".json")).read_text(encoding="utf-8"))
        return _age_days(value["retrieved_at"])
    except (OSError, ValueError, TypeError, KeyError):
        return None
