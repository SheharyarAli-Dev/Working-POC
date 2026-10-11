"""8-field verdict cache (plan step 10). Every test uses a real SQLite file in a tmp directory."""
import json
import sqlite3

import pytest

from backend.cavr import verdict_cache
from backend.cavr.storage import CavrStorage
from backend.cavr.verdict_cache import KEY_FIELDS, cache_key, lookup, store

FIELDS = {
    "ecosystem": "PyPI",
    "name": "pypdf",
    "version": "6.19.0",
    "artifact_sha256": "a" * 64,
    "subtree_digest": "b" * 64,
    "contract_digest": "c" * 64,
    "policy_version": "d" * 64,
    "analyzer_version": "cavr-pipeline/1",
}
CHANGED = {
    "ecosystem": "npm",
    "name": "pypdf2",
    "version": "6.19.1",
    "artifact_sha256": "1" * 64,
    "subtree_digest": "2" * 64,
    "contract_digest": "3" * 64,
    "policy_version": "4" * 64,
    "analyzer_version": "cavr-pipeline/2",
}
VERIFIED = {"status": "VERIFIED", "reason": "all checks passed", "evidence": {"artifact": {"sha256": "a" * 64}, "sinks": [1, 2]}}
REJECTED = {"status": "REJECTED", "reason": "hash mismatch", "evidence": {}}


@pytest.fixture
def storage(tmp_path):
    return CavrStorage(tmp_path / "cavr.sqlite3")


def outcome(result):
    return result["hit"], result["rule"]


def sql(storage, statement, *parameters):
    with storage.connect() as connection:
        rows = connection.execute(statement, parameters).fetchall()
        connection.commit()
    return rows


# --- the key ---------------------------------------------------------------------------------------------

def test_the_key_has_exactly_the_eight_fields():
    assert KEY_FIELDS == ("ecosystem", "name", "version", "artifact_sha256", "subtree_digest", "contract_digest",
                          "policy_version", "analyzer_version")
    key, normalised, problem = cache_key(FIELDS)
    assert problem is None and len(key) == 64 and normalised == FIELDS
    assert cache_key(dict(reversed(list(FIELDS.items()))))[0] == key


@pytest.mark.parametrize("same", [{"name": "PyPDF"}, {"name": "PYPDF"}, {"version": "6.19"}, {"version": "6.19.0.0"},
                                  {"version": " 6.19.0 "}, {"ecosystem": "pypi"}, {"artifact_sha256": "A" * 64}])
def test_spellings_of_the_same_release_give_the_same_key(same):
    assert cache_key({**FIELDS, **same})[0] == cache_key(FIELDS)[0]


def test_name_canonicalisation_in_the_key():
    assert cache_key({**FIELDS, "name": "Foo_Bar"})[0] == cache_key({**FIELDS, "name": "foo-bar"})[0]
    assert cache_key({**FIELDS, "name": "Foo_Bar"})[1]["name"] == "foo-bar"


@pytest.mark.parametrize("field", KEY_FIELDS)
def test_each_field_changes_the_key(field):
    # Another ecosystem gives no key at all, which is also not the same key.
    assert cache_key({**FIELDS, field: CHANGED[field]})[0] != cache_key(FIELDS)[0]


@pytest.mark.parametrize("field", KEY_FIELDS)
@pytest.mark.parametrize("bad", [None, "", 5, ["x"]])
def test_a_missing_or_malformed_field_gives_no_key(field, bad):
    key, normalised, problem = cache_key({**FIELDS, field: bad})
    assert key is None and normalised is None and field in problem


@pytest.mark.parametrize("change", [{"ecosystem": "npm"}, {"name": "../x"}, {"version": "not-a-version"}, {"version": "1.0+local"},
                                    {"artifact_sha256": "abc"}, {"subtree_digest": "z" * 64}, {"contract_digest": "c" * 63},
                                    {"policy_version": "2026.1"}, {"analyzer_version": " "}])
def test_unusable_values_give_no_key(change):
    assert cache_key({**FIELDS, **change})[0] is None


def test_a_missing_or_extra_field_gives_no_key():
    assert cache_key({key: value for key, value in FIELDS.items() if key != "subtree_digest"})[0] is None
    assert cache_key({**FIELDS, "ninth": "x"})[0] is None
    assert cache_key(None)[0] is None and cache_key("pypdf")[0] is None


# --- hit and miss ------------------------------------------------------------------------------------------

def test_hit_on_identical_inputs(storage):
    assert outcome(lookup(storage, FIELDS)) == (False, "MISS")
    stored = store(storage, FIELDS, VERIFIED)
    assert (stored["stored"], stored["rule"]) == (True, "STORED")
    hit = lookup(storage, dict(FIELDS))
    assert outcome(hit) == (True, "HIT")
    assert hit["verdict"] == VERIFIED and hit["key"] == stored["key"] == cache_key(FIELDS)[0]
    assert hit["stored_at"] == stored["stored_at"] and hit["fields"] == FIELDS


def test_hit_through_another_spelling_of_the_same_release(storage):
    store(storage, FIELDS, VERIFIED)
    assert outcome(lookup(storage, {**FIELDS, "name": "PyPDF", "version": "6.19"})) == (True, "HIT")


@pytest.mark.parametrize("field", KEY_FIELDS)
def test_miss_when_one_field_changes(storage, field):
    store(storage, FIELDS, VERIFIED)
    changed = {**FIELDS, field: CHANGED[field]}
    result = lookup(storage, changed)
    # A value the cache cannot key (another ecosystem) is not looked up at all; it is still not a hit.
    assert outcome(result) == ((False, "KEY_INCOMPLETE") if field == "ecosystem" else (False, "MISS"))
    assert result["verdict"] is None
    # The original entry is still there.
    assert outcome(lookup(storage, FIELDS)) == (True, "HIT")


def test_rejected_is_cached_too(storage):
    assert store(storage, FIELDS, REJECTED)["stored"] is True
    assert lookup(storage, FIELDS)["verdict"] == REJECTED


def test_a_new_verdict_for_the_same_key_replaces_the_old_one(storage):
    store(storage, FIELDS, VERIFIED)
    store(storage, FIELDS, REJECTED)
    assert lookup(storage, FIELDS)["verdict"]["status"] == "REJECTED"
    assert sql(storage, "SELECT COUNT(*) FROM verdict_cache")[0][0] == 1


def test_the_cache_survives_a_new_storage_object(storage, tmp_path):
    store(storage, FIELDS, VERIFIED)
    assert outcome(lookup(CavrStorage(tmp_path / "cavr.sqlite3"), FIELDS)) == (True, "HIT")
    assert outcome(lookup(CavrStorage(tmp_path / "other.sqlite3"), FIELDS)) == (False, "MISS")


def test_the_returned_verdict_is_a_copy(storage):
    verdict = json.loads(json.dumps(VERIFIED))
    store(storage, FIELDS, verdict)
    verdict["status"] = "REJECTED"
    first = lookup(storage, FIELDS)["verdict"]
    first["evidence"]["sinks"].append(3)
    assert lookup(storage, FIELDS)["verdict"] == VERIFIED


def test_incomplete_key_is_neither_looked_up_nor_stored(storage):
    incomplete = {**FIELDS, "subtree_digest": None}
    stored = store(storage, incomplete, VERIFIED)
    assert (stored["stored"], stored["rule"]) == (False, "KEY_INCOMPLETE") and "subtree_digest" in stored["reason"]
    assert outcome(lookup(storage, incomplete)) == (False, "KEY_INCOMPLETE")
    assert sql(storage, "SELECT COUNT(*) FROM verdict_cache")[0][0] == 0


# --- what may be stored -------------------------------------------------------------------------------------

@pytest.mark.parametrize("status", ["UNRESOLVED", "BLOCK", "PERMITTED", "OK", "verified", "", None])
def test_only_verified_and_rejected_are_stored(storage, status):
    stored = store(storage, FIELDS, {"status": status, "reason": "x"})
    assert (stored["stored"], stored["rule"]) == (False, "NOT_CACHEABLE")
    assert outcome(lookup(storage, FIELDS)) == (False, "MISS")
    assert sql(storage, "SELECT COUNT(*) FROM verdict_cache")[0][0] == 0


def test_unresolved_does_not_replace_a_stored_verdict(storage):
    store(storage, FIELDS, VERIFIED)
    assert store(storage, FIELDS, {"status": "UNRESOLVED"})["stored"] is False
    assert lookup(storage, FIELDS)["verdict"] == VERIFIED


@pytest.mark.parametrize("verdict", [None, "VERIFIED", ["VERIFIED"], {"reason": "no status"},
                                     {"status": "VERIFIED", "bad": {1, 2}}, {"status": "VERIFIED", "bad": float("nan")}])
def test_a_verdict_that_is_not_a_json_object_is_not_stored(storage, verdict):
    stored = store(storage, FIELDS, verdict)
    assert (stored["stored"], stored["rule"]) == (False, "NOT_CACHEABLE")
    assert outcome(lookup(storage, FIELDS)) == (False, "MISS")


def test_an_oversized_verdict_is_not_stored(storage, monkeypatch):
    monkeypatch.setattr(verdict_cache, "MAX_VERDICT_BYTES", 100)
    stored = store(storage, FIELDS, {"status": "VERIFIED", "evidence": "x" * 200})
    assert (stored["stored"], stored["rule"]) == (False, "NOT_CACHEABLE")


# --- tampered rows are ignored ---------------------------------------------------------------------------------

def tamper_verdict(storage):
    forged = json.dumps({**REJECTED, "status": "VERIFIED"}, sort_keys=True, separators=(",", ":"))
    sql(storage, "UPDATE verdict_cache SET verdict_json=?, status='VERIFIED'", forged)


def tamper_status_column(storage):
    sql(storage, "UPDATE verdict_cache SET status='VERIFIED'")


def tamper_key_field(storage):
    sql(storage, "UPDATE verdict_cache SET artifact_sha256=?", "f" * 64)


def tamper_stored_at(storage):
    sql(storage, "UPDATE verdict_cache SET stored_at='2020-01-01T00:00:00+00:00'")


def tamper_integrity(storage):
    sql(storage, "UPDATE verdict_cache SET integrity=?", "0" * 64)


def tamper_json(storage):
    sql(storage, "UPDATE verdict_cache SET verdict_json='{not json'")


@pytest.mark.parametrize("tamper", [tamper_verdict, tamper_status_column, tamper_key_field, tamper_stored_at, tamper_integrity,
                                    tamper_json])
def test_tampered_row_is_ignored(storage, tamper):
    store(storage, FIELDS, REJECTED)
    assert outcome(lookup(storage, FIELDS)) == (True, "HIT")
    tamper(storage)
    result = lookup(storage, FIELDS)
    assert outcome(result) == (False, "ROW_TAMPERED") and result["verdict"] is None
    # A fresh verdict can be stored over the bad row.
    assert store(storage, FIELDS, REJECTED)["stored"] is True
    assert outcome(lookup(storage, FIELDS)) == (True, "HIT")


def test_a_row_moved_under_another_key_is_ignored(storage):
    """Copy the VERIFIED row of one release under the key of another: each column is genuine, the row is not."""
    other = {**FIELDS, "artifact_sha256": "e" * 64}
    store(storage, FIELDS, VERIFIED)
    store(storage, other, REJECTED)
    good_key, bad_key = cache_key(FIELDS)[0], cache_key(other)[0]
    columns = "ecosystem, name, version, artifact_sha256, subtree_digest, contract_digest, policy_version, analyzer_version, status, verdict_json, stored_at, integrity"
    sql(storage, "DELETE FROM verdict_cache WHERE cache_key=?", bad_key)
    sql(storage, f"INSERT INTO verdict_cache(cache_key, {columns}) SELECT ?, {columns} FROM verdict_cache WHERE cache_key=?",
        bad_key, good_key)
    assert outcome(lookup(storage, other)) == (False, "ROW_TAMPERED")
    assert outcome(lookup(storage, FIELDS)) == (True, "HIT")


def test_a_forged_row_whose_fields_do_not_give_its_key_is_ignored(storage):
    """A VERIFIED row of one release filed under the key of another, with the plain integrity digest recomputed."""
    other = {**FIELDS, "artifact_sha256": "e" * 64}
    store(storage, FIELDS, VERIFIED)
    forged = dict(sql(storage, "SELECT * FROM verdict_cache")[0])
    forged["cache_key"] = cache_key(other)[0]
    forged["integrity"] = verdict_cache.row_integrity(forged)
    storage.put_cached_verdict(forged)
    assert forged["integrity"] == verdict_cache.row_integrity(dict(sql(storage, "SELECT * FROM verdict_cache WHERE cache_key=?",
                                                                       forged["cache_key"])[0]))
    result = lookup(storage, other)
    assert outcome(result) == (False, "ROW_TAMPERED") and "key fields" in result["reason"]


def test_a_row_with_a_status_that_is_never_cached_is_ignored(storage):
    store(storage, FIELDS, VERIFIED)
    row = dict(sql(storage, "SELECT * FROM verdict_cache")[0])
    verdict = {"status": "UNRESOLVED"}
    forged = {**row, "status": "UNRESOLVED", "verdict_json": json.dumps(verdict, sort_keys=True, separators=(",", ":"))}
    forged["integrity"] = verdict_cache.row_integrity(forged)  # the attacker recomputes the plain digest
    sql(storage, "UPDATE verdict_cache SET status=?, verdict_json=?, integrity=?", forged["status"], forged["verdict_json"],
        forged["integrity"])
    assert outcome(lookup(storage, FIELDS)) == (False, "ROW_TAMPERED")


# --- the cache never raises ---------------------------------------------------------------------------------------

def test_database_failure_is_a_miss_not_an_exception(storage):
    store(storage, FIELDS, VERIFIED)
    sql(storage, "DROP TABLE verdict_cache")
    assert outcome(lookup(storage, FIELDS)) == (False, "CACHE_UNAVAILABLE")
    stored = store(storage, FIELDS, VERIFIED)
    assert (stored["stored"], stored["rule"]) == (False, "CACHE_UNAVAILABLE")


def test_storage_without_the_cache_methods_is_a_miss(storage):
    assert outcome(lookup(None, FIELDS)) == (False, "CACHE_UNAVAILABLE")
    assert store(object(), FIELDS, VERIFIED)["rule"] == "CACHE_UNAVAILABLE"


def test_the_table_is_created_in_an_existing_database(tmp_path):
    path = tmp_path / "old.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, package TEXT NOT NULL,"
                           " action TEXT NOT NULL, user TEXT NOT NULL, reason TEXT, timestamp TEXT NOT NULL)")
    storage = CavrStorage(path)
    assert store(storage, FIELDS, VERIFIED)["stored"] is True and outcome(lookup(storage, FIELDS)) == (True, "HIT")


def test_every_result_has_the_same_keys(storage):
    miss, stored = lookup(storage, FIELDS), store(storage, FIELDS, VERIFIED)
    assert set(miss) == set(lookup(storage, FIELDS)) == set(lookup(storage, None))
    assert set(stored) == set(store(storage, None, VERIFIED)) == set(store(storage, FIELDS, None))
