"""Verdict cache keyed on the 8-field digest.

A verdict is reused only when all eight things it was judged from are the same:

    ecosystem          "PyPI" (the only one CAVR verifies in M1)
    name               canonical distribution name (`Foo_Bar` and `foo-bar` are one name)
    version            the release (`1.0` and `1.0.0` are one release)
    artifact_sha256    SHA-256 of the downloaded wheel            (pypi_client, step 4)
    subtree_digest     the whole dependency tree under it         (dep_tree, step 6)
    contract_digest    the project's use of it and what is allowed (capability_contract, step 9)
    policy_version     digest of the project policy               (requirement_gate, step 3)
    analyzer_version   the code and rules that judged it          (set by the pipeline, step 11)

`cache_key(fields)` is the SHA-256 of the canonical JSON of those eight values. A field that is
missing or not well formed gives no key at all, so nothing is looked up and nothing is stored
(`KEY_INCOMPLETE`): two requests whose tree or contract is unknown can never share an entry.

`store` keeps only VERIFIED and REJECTED. UNRESOLVED and BLOCK are never stored: UNRESOLVED is
"not known yet" and must be worked out again, and BLOCK is decided by the gate before there is
an artifact to key on.

Each row carries an integrity digest over the key, the eight fields, the status, the verdict
text and the time it was stored. `lookup` recomputes the key from the row's own columns and
the integrity digest from the row; a row that does not agree with itself, or with the key it
is filed under, is ignored (`ROW_TAMPERED`) and the request is analysed again. The digest is
not keyed: it catches damage and edits of single columns, not someone who can rewrite the
whole row and its digest. For that reason the pipeline still re-checks the artifact hash and
the advisories on every hit.

Neither function raises: a database error is `CACHE_UNAVAILABLE`, which is a miss.
"""
from __future__ import annotations
import json
import re
import sqlite3
from datetime import datetime, timezone

from packaging.utils import canonicalize_name, canonicalize_version
from packaging.version import InvalidVersion, Version

from backend.cavr.pypi_client import request_problem
from backend.orchestrator.hashing import digest

KEY_FIELDS = ("ecosystem", "name", "version", "artifact_sha256", "subtree_digest", "contract_digest", "policy_version",
              "analyzer_version")
DIGEST_FIELDS = ("artifact_sha256", "subtree_digest", "contract_digest", "policy_version")
CACHEABLE = ("VERIFIED", "REJECTED")
MAX_VERDICT_BYTES = 2 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
STORAGE_ERRORS = (sqlite3.Error, OSError, AttributeError, TypeError)


def cache_key(fields):
    """(key, normalised fields, None), or (None, None, reason) when the eight fields are not all usable."""
    if not isinstance(fields, dict) or set(fields) != set(KEY_FIELDS):
        return None, None, f"the cache key needs exactly these fields: {', '.join(KEY_FIELDS)}"
    for field in KEY_FIELDS:
        if not isinstance(fields[field], str) or not fields[field].strip():
            return None, None, f"{field} is missing"
    if fields["ecosystem"].strip().lower() != "pypi":
        return None, None, f"ecosystem {fields['ecosystem']!r} is not verified by CAVR"
    problem = request_problem(fields["name"].strip(), fields["version"].strip())
    if problem:
        return None, None, f"name / version: {problem}"
    normalised = {"ecosystem": "PyPI", "name": canonicalize_name(fields["name"].strip()),
                  "version": str(Version(fields["version"].strip())), "analyzer_version": fields["analyzer_version"].strip()}
    for field in DIGEST_FIELDS:
        value = fields[field].strip().lower()
        if not SHA256.fullmatch(value):
            return None, None, f"{field} is not a SHA-256 digest"
        normalised[field] = value
    normalised = {field: normalised[field] for field in KEY_FIELDS}
    # `1.0` and `1.0.0` are the same release: the key is made from the canonical form.
    key = digest({**normalised, "version": canonicalize_version(Version(normalised["version"]))})
    return key, normalised, None


def lookup(storage, fields) -> dict:
    """The stored verdict for these eight fields, if there is a sound one. Every result has the same keys."""
    key, normalised, problem = cache_key(fields)
    if key is None:
        return _lookup(False, "KEY_INCOMPLETE", problem)
    try:
        row = storage.get_cached_verdict(key)
    except STORAGE_ERRORS as exc:
        return _lookup(False, "CACHE_UNAVAILABLE", f"verdict cache cannot be read: {type(exc).__name__}: {exc}", key)
    if row is None:
        return _lookup(False, "MISS", "no stored verdict for this key", key, fields=normalised)
    verdict, problem = _sound(row, key)
    if problem:
        return _lookup(False, "ROW_TAMPERED", "stored row ignored: " + problem, key, fields=normalised)
    return _lookup(True, "HIT", f"stored {verdict['status']} verdict from {row['stored_at']}", key, verdict, row["stored_at"],
                   {field: row[field] for field in KEY_FIELDS})


def store(storage, fields, verdict) -> dict:
    """Store a VERIFIED or REJECTED verdict under the 8-field key. Every result has the same keys."""
    key, normalised, problem = cache_key(fields)
    if key is None:
        return _stored(False, "KEY_INCOMPLETE", problem)
    if not isinstance(verdict, dict) or verdict.get("status") not in CACHEABLE:
        status = verdict.get("status") if isinstance(verdict, dict) else None
        return _stored(False, "NOT_CACHEABLE", f"only {' and '.join(CACHEABLE)} are cached, not {status!r}", key)
    try:
        text = json.dumps(verdict, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        return _stored(False, "NOT_CACHEABLE", f"the verdict is not plain JSON: {exc}", key)
    if len(text.encode()) > MAX_VERDICT_BYTES:
        return _stored(False, "NOT_CACHEABLE", f"the verdict is larger than {MAX_VERDICT_BYTES} bytes", key)
    row = {"cache_key": key, **normalised, "status": verdict["status"], "verdict_json": text,
           "stored_at": datetime.now(timezone.utc).isoformat()}
    row["integrity"] = row_integrity(row)
    try:
        storage.put_cached_verdict(row)
    except STORAGE_ERRORS as exc:
        return _stored(False, "CACHE_UNAVAILABLE", f"verdict cache cannot be written: {type(exc).__name__}: {exc}", key)
    return _stored(True, "STORED", f"{verdict['status']} verdict stored", key, row["stored_at"])


def row_integrity(row: dict) -> str:
    """SHA-256 over everything in a row except the integrity digest itself."""
    return digest({column: row[column] for column in ("cache_key", *KEY_FIELDS, "status", "verdict_json", "stored_at")})


# --- internals ---------------------------------------------------------------

def _lookup(hit, rule, reason, key=None, verdict=None, stored_at=None, fields=None) -> dict:
    return {"hit": hit, "rule": rule, "reason": reason, "key": key, "verdict": verdict, "stored_at": stored_at, "fields": fields}


def _stored(stored, rule, reason, key=None, stored_at=None) -> dict:
    return {"stored": stored, "rule": rule, "reason": reason, "key": key, "stored_at": stored_at}


def _sound(row, key: str):
    """(verdict, None) when the row agrees with itself and with `key`; otherwise (None, what is wrong)."""
    try:
        if row["integrity"] != row_integrity(row):
            return None, "its integrity digest does not match its content"
        if row["cache_key"] != key or cache_key({field: row[field] for field in KEY_FIELDS})[0] != key:
            return None, "its key fields do not give the key it is stored under"
        if row["status"] not in CACHEABLE:
            return None, f"status {row['status']!r} is never cached"
        verdict = json.loads(row["verdict_json"])
    except (KeyError, TypeError, ValueError, InvalidVersion, RecursionError) as exc:
        return None, f"it cannot be read ({type(exc).__name__})"
    if not isinstance(verdict, dict) or verdict.get("status") != row["status"]:
        return None, "its verdict does not have the status of the row"
    return verdict, None
