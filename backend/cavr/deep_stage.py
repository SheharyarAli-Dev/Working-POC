"""Stage 8b: deep analysis behind the fast gate's escalation (PR 2 of docs/cavr-m2-plan.md). Fail closed.

`pipeline.verify_request(..., deep=analyzer)` calls `run_deep` only for a package whose fast analysis is an
escalated UNRESOLVED (a sink the contract does not allow, reachable from the project's call sites). Its
answer replaces that one verdict. A package that is VERIFIED, REJECTED, BLOCKed, or UNRESOLVED for any other
reason (no OSV answer, a hash mismatch, an unknown contract, ...) never reaches this stage, so a deep
VERIFIED can never lift those.

A deep analyzer is any object with:

    version    non-empty str    its own version
    image_id   non-empty str    the sandbox image it runs in (PR 3 sets it from the real image ID)
    budget     dict             its limits; `package_seconds` (> 0) is required, e.g. Q8's
                                {"runs": 8, "run_seconds": 20, "package_seconds": 120}
    analyse(package) -> dict    {"status": VERIFIED / REJECTED / UNRESOLVED, "rule": str, "reason": str,
                                 "evidence": dict (optional)}

`identity(deep)` is what goes into the cache key's `analyzer_version`, so a new image, version or budget is a
cache miss while the key keeps its 8 fields. Without a full identity there is no key: the package is
UNRESOLVED and the analyzer is never called.

    DEEP_IDENTITY_UNKNOWN   version, image ID or budget missing or unusable   -> UNRESOLVED, not called
    INTERNAL_ERROR          `analyse` raised                                  -> UNRESOLVED
    DEEP_NO_RESULT          `analyse` returned nothing (None)                 -> UNRESOLVED
    DEEP_RESULT_INVALID     not a dict, unknown status, empty rule or reason,
                            evidence that is not a dict                       -> UNRESOLVED
    DEEP_BUDGET_EXCEEDED    the call took longer than `package_seconds`, by the
                            host's clock (never the analyzer's own report) and
                            the answer was not REJECTED                       -> UNRESOLVED
    otherwise               the analyzer's own status, rule and reason

A REJECTED answer stays REJECTED when the budget was exceeded: a violation that was observed is a violation
(Q8: any violation -> REJECTED; anything incomplete -> UNRESOLVED).
"""
from __future__ import annotations

import time

from backend.orchestrator.hashing import digest

STATUSES = ("VERIFIED", "REJECTED", "UNRESOLVED")
CLOCK = time.monotonic  # the host's clock; tests replace it


def identity(deep) -> str | None:
    """`<version>;image:<image id>;budget:<digest>` of a deep analyzer, or None when any part is missing.

    Never raises: an attribute that raises, or a budget that cannot be digested, is "no identity".
    """
    try:
        version, image_id, budget = (getattr(deep, name, None) for name in ("version", "image_id", "budget"))
        if not (isinstance(version, str) and version.strip() and isinstance(image_id, str) and image_id.strip()):
            return None
        if not isinstance(budget, dict) or not _positive(budget.get("package_seconds")):
            return None
        return f"{version};image:{image_id};budget:{digest(budget)}"
    except Exception:
        return None


def run_deep(deep, package: dict) -> dict:
    """The deep verdict for one escalated package. Always {status, stage, rule, reason, evidence, elapsed_seconds}."""
    if identity(deep) is None:
        return _result("UNRESOLVED", "DEEP_IDENTITY_UNKNOWN",
                       "the deep analyzer has no complete identity (version, image ID and a budget with package_seconds), "
                       "so its verdict cannot be keyed; it was not run")
    limit = deep.budget["package_seconds"]
    started = CLOCK()
    try:
        answer = deep.analyse(package)
    except Exception as exc:  # a fault in the deep stage is "unknown", never a pass
        return _result("UNRESOLVED", "INTERNAL_ERROR", f"the deep analysis failed: {type(exc).__name__}: {exc}",
                       elapsed=CLOCK() - started)
    elapsed = CLOCK() - started
    if answer is None:
        return _result("UNRESOLVED", "DEEP_NO_RESULT", "the deep analyzer returned no result", elapsed=elapsed)
    problem = _invalid(answer)
    if problem:
        return _result("UNRESOLVED", "DEEP_RESULT_INVALID", f"the deep result is not usable: {problem}", elapsed=elapsed)
    if elapsed > limit and answer["status"] != "REJECTED":
        return _result("UNRESOLVED", "DEEP_BUDGET_EXCEEDED",
                       f"the deep analysis took {elapsed:.1f} s, over the budget of {limit} s per package; "
                       f"its answer ({answer['status']}) is incomplete", evidence=answer.get("evidence") or {}, elapsed=elapsed)
    return _result(answer["status"], answer["rule"], answer["reason"], evidence=answer.get("evidence") or {}, elapsed=elapsed)


def _invalid(answer) -> str | None:
    if not isinstance(answer, dict):
        return f"a {type(answer).__name__}, not a dict"
    if answer.get("status") not in STATUSES:
        return f"status {answer.get('status')!r} is not one of {', '.join(STATUSES)}"
    for key in ("rule", "reason"):
        if not isinstance(answer.get(key), str) or not answer[key].strip():
            return f"no {key}"
    if "evidence" in answer and not isinstance(answer["evidence"], dict):
        return "evidence is not a dict"
    return None


def _positive(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0


def _result(status, rule, reason, evidence=None, elapsed=None) -> dict:
    return {"status": status, "stage": "deep", "rule": rule, "reason": reason, "evidence": evidence or {},
            "elapsed_seconds": None if elapsed is None else round(elapsed, 3)}
