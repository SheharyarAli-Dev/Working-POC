"""FR-10: the evidence record hash covers every field of the record (PR 19 of docs/cavr-m2-plan.md, Q1 option a).

A record written now carries `hash_version: 2`; its SHA-256 covers seq, ts, phase, substep, type, data, prev_hash and the
version itself. A record without `hash_version` was written before this change (SABLE keeps its chains on disk): it is
checked with the old hash, which does not cover ts or substep, and `verify_chain` reports it as a legacy record. A
legacy record after a version-2 record is refused: a chain cannot go back to the weaker hash.
"""
import copy
import hashlib
import json

import pytest

from backend.cavr.assurance import (GENESIS_HASH, HASH_VERSION, EvidenceChain, compute_record_hash,
                                    compute_record_hash_v1, verify_chain)


def chain(n=3) -> list[dict]:
    built = EvidenceChain("run-test")
    for i in range(n):
        built.add_record(phase=f"P{i}", event_type=f"type_{i}", data={"i": i, "nested": {"x": [1, 2]}}, substep=f"Step{i}")
    return built.records


def legacy_chain(n=3) -> list[dict]:
    """Records as `EvidenceChain` wrote them before PR 19: no hash_version, the old hash."""
    records, prev = [], GENESIS_HASH
    for i in range(n):
        seq, data = i + 1, {"i": i}
        digest = hashlib.sha256(f"{seq}|P{i}|type_{i}|{json.dumps(data, sort_keys=True)}|{prev}".encode()).hexdigest()
        records.append({"seq": seq, "ts": 1700000000.0 + i, "phase": f"P{i}", "substep": f"Step{i}", "type": f"type_{i}",
                        "data": data, "prev_hash": prev, "sha256": digest})
        prev = digest
    return records


def test_a_new_record_carries_version_2_and_its_hash_covers_every_field():
    (record,) = chain(1)
    assert record["hash_version"] == HASH_VERSION == 2
    assert record["sha256"] == compute_record_hash(record)
    records = chain()
    assert verify_chain(records) == {"intact": True, "total_records": 3, "verified_links": 3, "legacy_records": 0,
                                     "terminal_digest": records[-1]["sha256"],
                                     "message": "Cryptographic evidence chain verified intact (3/3 blocks verified)."}


def test_an_unchanged_chain_is_intact_and_its_terminal_digest_is_the_last_hash():
    records = chain()
    result = verify_chain(records)
    assert result["intact"] is True and result["terminal_digest"] == records[-1]["sha256"]


@pytest.mark.parametrize("field, value", [
    ("ts", 1.0), ("substep", "Forged"),                       # not covered before PR 19
    ("seq", 99), ("phase", "PX"), ("type", "forged"), ("data", {"i": 1, "nested": {"x": [1, 3]}}),
])
def test_changing_any_one_field_of_a_record_is_detected(field, value):
    records = chain()
    records[1][field] = value
    result = verify_chain(records)
    assert result["intact"] is False and result["broken_link_seq"] == (99 if field == "seq" else 2)
    assert result["error"].startswith("Digest mismatch")


def test_a_ts_change_of_one_microsecond_is_detected():
    records = chain()
    records[0]["ts"] += 1e-6
    assert verify_chain(records)["intact"] is False


def test_changing_prev_hash_or_the_stored_hash_is_detected():
    records = chain()
    records[2]["prev_hash"] = "f" * 64
    assert verify_chain(records)["error"].startswith("Link discontinuity")
    records = chain()
    records[0]["sha256"] = "0" * 64
    assert verify_chain(records)["intact"] is False


def test_removing_hash_version_from_a_new_record_is_detected():
    """Without the version the record is checked with the old hash, which gives another digest."""
    records = chain(1)
    del records[0]["hash_version"]
    assert verify_chain(records)["intact"] is False


def test_an_unknown_hash_version_is_refused():
    records = chain(1)
    records[0]["hash_version"] = 3
    result = verify_chain(records)
    assert result["intact"] is False and "hash_version" in result["error"]


def test_a_legacy_chain_still_verifies_and_is_reported_as_legacy():
    records = legacy_chain()
    assert records[0]["sha256"] == compute_record_hash_v1(records[0])
    result = verify_chain(records)
    assert result["intact"] is True and result["legacy_records"] == 3
    assert "3 legacy" in result["message"] and "ts and substep" in result["message"]


def test_a_legacy_record_does_not_cover_ts_or_substep_but_does_cover_data():
    """What option (a) accepts for old records, stated as a test: only the old fields are protected."""
    records = legacy_chain()
    records[1]["ts"], records[1]["substep"] = 1.0, "Forged"
    assert verify_chain(records)["intact"] is True
    records[1]["data"] = {"i": 42}
    assert verify_chain(records)["intact"] is False


def test_a_chain_can_continue_from_legacy_records_with_version_2():
    records = legacy_chain(2)
    built = EvidenceChain("run-mixed")
    built.records, built.last_hash = copy.deepcopy(records), records[-1]["sha256"]
    built.add_record(phase="P9", event_type="later", data={"ok": True}, substep="Later")
    result = verify_chain(built.records)
    assert result["intact"] is True and result["legacy_records"] == 2 and built.records[-1]["hash_version"] == 2


def test_a_legacy_record_after_a_version_2_record_is_refused():
    """Otherwise a forger could rewrite the tail of a new chain with the weaker hash."""
    records = chain(2)
    tail = records[1]
    del tail["hash_version"]
    tail["sha256"] = compute_record_hash_v1(tail)
    result = verify_chain(records)
    assert result["intact"] is False and result["broken_link_seq"] == 2 and "legacy" in result["error"]


def test_an_empty_chain():
    assert verify_chain([])["intact"] is True



def test_a_legacy_record_without_seq_is_checked_with_its_position():
    """As before PR 19: a legacy record with no `seq` is hashed with its 1-based position."""
    records = legacy_chain(2)
    for record in records:
        del record["seq"]
    assert verify_chain(records)["intact"] is True
