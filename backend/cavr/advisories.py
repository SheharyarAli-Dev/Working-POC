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

`package_advisories(name, cache_dir)` is the package-wide answer (every advisory, no version) that the
repair search uses to leave affected releases out before re-checking any. It is stale after 24 hours.
It talks to OSV itself, because the adapter in `backend/integrations/` only asks per version.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
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


# --- the package-wide answer: every advisory of a package, for the repair search ------------------------------------

PACKAGE_MAX_AGE_HOURS = 24
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
MAX_OSV_PAGES = 20


def package_query(name: str) -> dict:
    """The OSV query for every advisory of `name` (no version)."""
    return {"package": {"name": canonicalize_name(name), "ecosystem": "PyPI"}}


def package_cache_path(cache_dir, name: str) -> Path:
    return Path(cache_dir) / ("package-" + digest(package_query(name)) + ".json")


def package_advisories(name, cache_dir, live: bool = False, osv=None, max_age_hours: float = PACKAGE_MAX_AGE_HOURS,
                       now=None) -> dict:
    """Every OSV advisory of `name`, whatever the version. Used by the repair search to leave affected releases out.

    OK `PACKAGE_ADVISORIES_READ` with `vulnerabilities`; otherwise UNRESOLVED: INVALID_REQUEST,
    ADVISORIES_UNAVAILABLE (no answer), ADVISORIES_STALE (older than `max_age_hours`, 24 by default, or dated in
    the future) or ADVISORIES_INVALID. The answer comes from `osv.query_package(name, live=live)` when `osv` is
    given (an `osv` without that method has no answer: a test stub never reaches the network), else from OSV
    itself (`live`) with the dated, digest-checked cache in `cache_dir` as the fallback, in the adapter's format.
    `now` replaces the clock (a function that returns an aware datetime).
    """
    fields = {"name": name if isinstance(name, str) else None, "mode": "UNAVAILABLE", "retrieved_at": None,
              "age_hours": None, "response_sha256": None, "advisory_count": None, "vulnerabilities": None,
              "live_error": None}

    def result(outcome, rule, reason):
        return {"result": outcome, "rule": rule, "reason": reason, "ecosystem": "PyPI", **fields}

    problem = request_problem(name, "0")
    if problem:
        return result("UNRESOLVED", "INVALID_REQUEST", problem)
    name = fields["name"] = canonicalize_name(name)
    try:
        if osv is not None:
            query = getattr(osv, "query_package", None)
            if query is None:
                return result("UNRESOLVED", "ADVISORIES_UNAVAILABLE", "the OSV client given cannot answer a package-wide query")
            answer = query(name, live=live)
        else:
            answer = _package_answer(name, cache_dir, live)
    except Exception as exc:  # any failure means no answer
        return result("UNRESOLVED", "ADVISORIES_UNAVAILABLE", f"package-wide advisory lookup failed: {type(exc).__name__}: {exc}")
    if not isinstance(answer, dict) or answer.get("available") is not True:
        error = answer.get("error") if isinstance(answer, dict) else None
        return result("UNRESOLVED", "ADVISORIES_UNAVAILABLE", f"no package-wide OSV answer for {name}: {error or 'no answer'}")
    fields.update(mode=answer.get("mode"), retrieved_at=answer.get("retrieved_at"),
                  response_sha256=answer.get("response_sha256"), live_error=answer.get("live_error"))
    try:
        moment = datetime.fromisoformat(answer["retrieved_at"])
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        age = ((now() if now else datetime.now(timezone.utc)) - moment).total_seconds() / 3600
    except (KeyError, TypeError, ValueError):
        age = None
    fields["age_hours"] = None if age is None else round(age, 2)
    if age is None or age > max_age_hours or age < -FUTURE_TOLERANCE_DAYS * 24:
        return result("UNRESOLVED", "ADVISORIES_STALE",
                      f"the package-wide OSV answer is dated {answer.get('retrieved_at')!r}; it must be at most "
                      f"{max_age_hours} hours old")
    vulns = answer.get("vulnerabilities")
    if not isinstance(vulns, list) or not all(isinstance(v, dict) and isinstance(v.get("id"), str) and v["id"] for v in vulns):
        return result("UNRESOLVED", "ADVISORIES_INVALID", "the package-wide OSV answer is not a list of advisories with ids")
    fields.update(vulnerabilities=vulns, advisory_count=len(vulns))
    return result("OK", "PACKAGE_ADVISORIES_READ", f"OSV lists {len(vulns)} advisories for {name} (all versions)")


def _package_answer(name: str, cache_dir, live: bool) -> dict:
    """OSV's package-wide answer: live (stored in the cache) or from the cache. The age is judged by the caller."""
    query = package_query(name)
    path = package_cache_path(cache_dir, name)
    error = None
    if live:
        try:
            vulns, pages, request = [], [], query
            with httpx.Client(timeout=8) as client:
                for _ in range(MAX_OSV_PAGES):
                    response = client.post(OSV_QUERY_URL, json=request)
                    response.raise_for_status()
                    page = response.json()
                    pages.append(page)
                    vulns.extend(page.get("vulns", []))
                    if not page.get("next_page_token"):
                        break
                    request = {**query, "page_token": page["next_page_token"]}
                else:
                    raise ValueError("OSV pagination budget exceeded; incomplete evidence")
            body = {"vulns": vulns, "pages": pages}
            value = {"query": query, "retrieved_at": datetime.now(timezone.utc).isoformat(), "source": OSV_QUERY_URL,
                     "response": body, "response_sha256": digest(body)}
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value, indent=2), encoding="utf-8")
            return {**value, "available": True, "mode": "LIVE", "vulnerabilities": vulns}
        except Exception as exc:  # fall back to the cache
            error = f"{type(exc).__name__}: {exc}"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"available": False, "error": error or "no cached package-wide answer"}
    if not isinstance(value, dict) or value.get("query") != query or value.get("response_sha256") != digest(value.get("response")):
        return {"available": False, "error": "the cached package-wide answer is damaged (query or digest differs)"}
    return {**value, "available": True, "mode": "DATED CACHE", "live_error": error,
            "vulnerabilities": (value.get("response") or {}).get("vulns")}


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
