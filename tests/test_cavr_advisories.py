"""C3 OSV check with real version ranges (plan step 7). Offline.

Two kinds of advisory data are used and kept apart:
- RECORDED: real api.osv.dev responses in tests/test_cavr_data/: pypdf 5.1.0 (97 advisories, 2026-10-10),
  pypdf 6.21.4 (none, 2026-11-22) and pypdf 6.19.0 (18, 2026-11-22). The 6.19.0 answer of 2026-10-10
  (none) is a historical snapshot and is only checked to be labelled as one. Only `retrieved_at` is set by the tests, because
  the cache refuses data older than `max_age_days`.
- SYNTHETIC: hand-written advisories for range shapes the recorded data does not contain
  (last_affected, several ranges, GIT-only). Their ids start with "SYNTH-".
"""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from backend.cavr.advisories import FIRST_IDS, check_advisories, match_advisory, summarise_ids
from backend.integrations.osv_adapter import OSV
from backend.orchestrator.hashing import digest

DATA = Path(__file__).parent / "test_cavr_data"
RECORDED_5_1_0 = json.loads((DATA / "osv-pypdf-5.1.0.json").read_text())["response"]["vulns"]
RECORDED_6_21_4 = json.loads((DATA / "osv-pypdf-6.21.4.json").read_text())["response"]
RECORDED_6_19_0_NOW = json.loads((DATA / "osv-pypdf-6.19.0-2026-11-22.json").read_text())["response"]
# Historical snapshot (2026-10-10, no advisories then): only checked to be labelled as such below.
HISTORICAL_6_19_0 = json.loads((DATA / "osv-pypdf-6.19.0.json").read_text())
FIXED_IN_6_19_0 = next(v for v in RECORDED_5_1_0 if v["id"] == "GHSA-php9-fj8v-98fj")  # introduced 0, fixed 6.19.0


def outcome(result):
    return result["result"], result["rule"]


def synthetic(advisory_id, *ranges, name="demo", versions=None, **more):
    affected = {"package": {"name": name, "ecosystem": "PyPI"}, "ranges": list(ranges)}
    if versions is not None:
        affected["versions"] = versions
    return {"id": advisory_id, "summary": "synthetic test advisory", "affected": [affected], **more}


def ecosystem(*events):
    return {"type": "ECOSYSTEM", "events": list(events)}


def write_cache(cache_dir, name, version, vulns, age_days=0.0, **overrides):
    """Write a cache entry in the exact format `OSV.query(live=True)` writes."""
    query = {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
    body = {"vulns": list(vulns), "pages": [{"vulns": list(vulns)}]}
    value = {"query": query, "retrieved_at": (datetime.now(timezone.utc) - timedelta(days=age_days)).isoformat(),
             "source": "https://api.osv.dev/v1/query", "response": body, "response_sha256": digest(body), **overrides}
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / (digest(query) + ".json")
    path.write_text(json.dumps(value))
    return path


def check(tmp_path, name, version, vulns, **args):
    write_cache(tmp_path / "osv", name, version, vulns)
    return check_advisories(name, version, tmp_path / "osv", **args)


class StubOSV:
    """Stands in for the adapter where the test needs a live answer or a failure."""

    def __init__(self, answer):
        self.answer, self.calls = answer, []

    def query(self, name, version, ecosystem="PyPI", live=False, max_age_days=30):
        self.calls.append((name, version, ecosystem, live, max_age_days))
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def live_answer(vulns):
    body = {"vulns": vulns, "pages": [{"vulns": vulns}]}
    return {"query": {}, "retrieved_at": datetime.now(timezone.utc).isoformat(), "source": "https://api.osv.dev/v1/query",
            "response": body, "response_sha256": digest(body), "available": True, "mode": "LIVE", "vulnerabilities": vulns}


# --- RECORDED: pypdf ----------------------------------------------------------------------------

def test_recorded_pypdf_5_1_0_is_rejected_with_the_advisory_ids(tmp_path):
    result = check(tmp_path, "pypdf", "5.1.0", RECORDED_5_1_0)
    assert outcome(result) == ("REJECTED", "KNOWN_VULNERABILITY")
    assert result["advisory_count"] == 97 and len(result["affected"]) == 97
    ids = [entry["id"] for entry in result["affected"]]
    assert ids == sorted(ids) and "GHSA-7hfw-26vp-jp8m" in ids and "PYSEC-2026-1830" in ids
    assert result["unknown"] == [] and result["not_affected"] == []
    assert result["mode"] == "DATED CACHE" and result["age_days"] < 1
    entry = next(e for e in result["affected"] if e["id"] == "GHSA-php9-fj8v-98fj")
    assert entry["fixed_versions"] == ["6.19.0"] and "CVE-2026-102998" in entry["aliases"]
    assert "GHSA-23w6-3w8w-8484" in result["reason"]


def test_a_long_advisory_list_is_a_count_and_the_first_three_ids_in_the_reason_and_whole_in_the_result(tmp_path):
    result = check(tmp_path, "pypdf", "5.1.0", RECORDED_5_1_0)
    ids = [entry["id"] for entry in result["affected"]]
    assert FIRST_IDS == 3 and len(ids) == 97
    assert result["reason"] == f"pypdf 5.1.0 is affected by 97 known advisories: {ids[0]}, {ids[1]}, {ids[2]} and 94 more"
    assert not any(advisory_id in result["reason"] for advisory_id in ids[3:])
    # The evidence is not shortened: every one of the 97 is in the result with its aliases and fixed versions.
    assert all(entry["id"] and "fixed_versions" in entry and "aliases" in entry for entry in result["affected"])


@pytest.mark.parametrize("count, expected", [(0, ""), (1, "A-1"), (2, "A-1, A-2"), (3, "A-1, A-2, A-3"),
                                             (4, "A-1, A-2, A-3 and 1 more"), (97, "A-1, A-2, A-3 and 94 more")])
def test_summarise_ids_names_the_first_three_and_counts_the_rest(count, expected):
    assert summarise_ids([f"A-{number}" for number in range(1, count + 1)]) == expected


def test_the_other_reasons_that_list_ids_are_summarised_the_same_way(tmp_path):
    git_only = [synthetic(f"SYNTH-07{number:02d}", {"type": "GIT", "events": [{"introduced": "0"}]}) for number in range(1, 6)]
    unknown = check(tmp_path / "a", "demo", "1.0", git_only)
    assert outcome(unknown) == ("UNRESOLVED", "RANGE_UNSUPPORTED") and len(unknown["unknown"]) == 5
    assert unknown["reason"].endswith(": SYNTH-0701, SYNTH-0702, SYNTH-0703 and 2 more")
    outside = [synthetic(f"SYNTH-08{number:02d}", ecosystem({"introduced": "2.0"})) for number in range(1, 5)]
    disagreement = check(tmp_path / "b", "demo", "1.0", outside)
    assert outcome(disagreement) == ("UNRESOLVED", "RANGE_DISAGREEMENT") and len(disagreement["not_affected"]) == 4
    assert disagreement["reason"].endswith(": SYNTH-0801, SYNTH-0802, SYNTH-0803 and 1 more")


def test_recorded_pypdf_6_21_4_has_no_known_vulnerability(tmp_path):
    assert RECORDED_6_21_4 == {}  # how OSV answers when it knows nothing for the version
    result = check(tmp_path, "pypdf", "6.21.4", RECORDED_6_21_4.get("vulns", []))
    assert outcome(result) == ("OK", "NO_KNOWN_VULNERABILITY")
    assert result["advisory_count"] == 0 and result["affected"] == []
    assert len(result["response_sha256"]) == 64 and result["retrieved_at"]


def test_recorded_pypdf_6_19_0_of_2026_11_22_is_rejected_by_its_ranges(tmp_path):
    vulns = RECORDED_6_19_0_NOW["vulns"]
    result = check(tmp_path, "pypdf", "6.19.0", vulns)
    assert outcome(result) == ("REJECTED", "KNOWN_VULNERABILITY")
    # Every one of the 18 advisories OSV returned is confirmed by this module's own range check.
    assert len(vulns) == 18 and sorted(entry["id"] for entry in result["affected"]) == sorted(v["id"] for v in vulns)


def test_historical_6_19_0_snapshot_is_labelled_and_is_not_the_current_answer():
    assert HISTORICAL_6_19_0["historical_snapshot"] is True and "HISTORICAL SNAPSHOT" in HISTORICAL_6_19_0["note"]
    assert HISTORICAL_6_19_0["recorded_at"] == "2026-10-10" and HISTORICAL_6_19_0["response"] == {}
    assert RECORDED_6_19_0_NOW["vulns"]  # OSV's answer of 2026-11-22 is not empty


def test_every_recorded_advisory_matches_5_1_0_and_most_do_not_match_6_19_0():
    assert all(match_advisory("pypdf", "5.1.0", vuln)["status"] == "AFFECTED" for vuln in RECORDED_5_1_0)
    statuses = [match_advisory("pypdf", "6.19.0", vuln)["status"] for vuln in RECORDED_5_1_0]
    assert set(statuses) == {"NOT_AFFECTED"}


# --- introduced / fixed (RECORDED advisory GHSA-php9-fj8v-98fj: introduced 0, fixed 6.19.0) --------

@pytest.mark.parametrize("version, status", [
    ("0.1", "AFFECTED"),
    ("5.1.0", "AFFECTED"),
    ("6.18.1", "AFFECTED"),
    ("6.19.0rc1", "AFFECTED"),
    ("6.19.0", "NOT_AFFECTED"),     # the fixed version itself is just outside the range
    ("6.19", "NOT_AFFECTED"),
    ("6.19.0.post1", "NOT_AFFECTED"),
    ("7.0.0", "NOT_AFFECTED"),
])
def test_introduced_fixed_range(version, status):
    assert match_advisory("pypdf", version, FIXED_IN_6_19_0)["status"] == status


@pytest.mark.parametrize("version, status", [
    ("1.9", "NOT_AFFECTED"),        # just below `introduced`
    ("2.0", "AFFECTED"),
    ("2.5", "AFFECTED"),
    ("3.0", "NOT_AFFECTED"),        # `fixed` is exclusive
])
def test_introduced_above_zero(version, status):
    vuln = synthetic("SYNTH-1", ecosystem({"introduced": "2.0"}, {"fixed": "3.0"}))
    assert match_advisory("demo", version, vuln)["status"] == status


def test_the_old_rule_that_any_less_or_equal_range_affects_every_version_is_gone():
    # The dashboard path marked every version affected whenever a range contained "<=".
    vuln = synthetic("SYNTH-2", ecosystem({"introduced": "0"}, {"last_affected": "3.5.21"}))
    assert match_advisory("demo", "3.5.21", vuln)["status"] == "AFFECTED"
    assert match_advisory("demo", "4.0.0", vuln)["status"] == "NOT_AFFECTED"


# --- last_affected (SYNTHETIC) ---------------------------------------------------------------------

@pytest.mark.parametrize("version, status", [
    ("1.0", "AFFECTED"),
    ("1.4.9", "AFFECTED"),
    ("1.5", "AFFECTED"),            # `last_affected` is inclusive
    ("1.5.0", "AFFECTED"),
    ("1.5.1", "NOT_AFFECTED"),      # just outside
    ("0.9", "NOT_AFFECTED"),
])
def test_last_affected_range(version, status):
    vuln = synthetic("SYNTH-3", ecosystem({"introduced": "1.0"}, {"last_affected": "1.5"}))
    assert match_advisory("demo", version, vuln)["status"] == status


# --- multi-range (SYNTHETIC) -------------------------------------------------------------------------

@pytest.mark.parametrize("version, status", [
    ("1.1", "AFFECTED"),            # first interval
    ("1.2", "NOT_AFFECTED"),        # between the intervals
    ("1.9", "NOT_AFFECTED"),
    ("2.0", "AFFECTED"),            # second interval, same range object
    ("2.3", "NOT_AFFECTED"),
    ("3.1", "AFFECTED"),            # second range object, open ended
    ("9.0", "AFFECTED"),
])
def test_multi_range(version, status):
    vuln = synthetic("SYNTH-4",
                     ecosystem({"introduced": "1.0"}, {"fixed": "1.2"}, {"introduced": "2.0"}, {"fixed": "2.3"}),
                     ecosystem({"introduced": "3.0"}))
    assert match_advisory("demo", version, vuln)["status"] == status


def test_several_affected_entries_any_match_counts():
    vuln = synthetic("SYNTH-5", ecosystem({"introduced": "0"}, {"fixed": "1.0"}))
    vuln["affected"].append({"package": {"name": "Demo", "ecosystem": "PyPI"}, "ranges": [ecosystem({"introduced": "5.0"})]})
    assert match_advisory("demo", "5.1", vuln)["status"] == "AFFECTED"
    assert match_advisory("demo", "2.0", vuln)["status"] == "NOT_AFFECTED"


# --- unsupported range types -> UNKNOWN -> UNRESOLVED (SYNTHETIC) ---------------------------------------

GIT_ONLY = synthetic("SYNTH-6", {"type": "GIT", "repo": "https://example.invalid/demo.git",
                                 "events": [{"introduced": "0"}, {"fixed": "8d2f1c0"}]})


def test_git_only_range_is_unknown():
    match = match_advisory("demo", "1.0", GIT_ONLY)
    assert match["status"] == "UNKNOWN"


def test_git_only_range_is_unresolved(tmp_path):
    result = check(tmp_path, "demo", "1.0", [GIT_ONLY])
    assert outcome(result) == ("UNRESOLVED", "RANGE_UNSUPPORTED")
    assert [entry["id"] for entry in result["unknown"]] == ["SYNTH-6"]


def test_git_range_next_to_a_matching_ecosystem_range_is_affected():
    vuln = synthetic("SYNTH-7", GIT_ONLY["affected"][0]["ranges"][0], ecosystem({"introduced": "0"}, {"fixed": "2.0"}))
    assert match_advisory("demo", "1.0", vuln)["status"] == "AFFECTED"
    # D-1: the ECOSYSTEM range decides release versions; the GIT range next to it is left out (was UNKNOWN).
    assert match_advisory("demo", "2.0", vuln)["status"] == "NOT_AFFECTED"


@pytest.mark.parametrize("vuln", [
    synthetic("SYNTH-8", ecosystem({"introduced": "0"}, {"fixed": "not-a-version"})),
    synthetic("SYNTH-10", {"type": "MADE_UP", "events": [{"introduced": "0"}]}),
    synthetic("SYNTH-11"),                                             # no ranges, no versions
    synthetic("SYNTH-12", {"type": "ECOSYSTEM", "events": "everything"}),
    {"id": "SYNTH-13", "affected": [{"package": {"name": "demo", "ecosystem": "PyPI"}, "ranges": "all"}]},
])
def test_range_that_cannot_be_evaluated_is_unknown(vuln):
    assert match_advisory("demo", "1.0", vuln)["status"] == "UNKNOWN"


def test_unknown_event_after_introduced_counts_as_affected():
    # `package_records.affected` leaves the range open when it meets an event it does not know,
    # so the answer errs on the affected side (REJECTED), never on the clean side.
    vuln = synthetic("SYNTH-9", ecosystem({"introduced": "0"}, {"until": "2.0"}))
    assert match_advisory("demo", "1.0", vuln)["status"] == "AFFECTED"
    assert match_advisory("demo", "9.0", vuln)["status"] == "AFFECTED"


def test_explicit_versions_list():
    vuln = synthetic("SYNTH-14", versions=["1.0", "1.1"])
    assert match_advisory("demo", "1.1", vuln)["status"] == "AFFECTED"
    assert match_advisory("demo", "1.2", vuln)["status"] == "NOT_AFFECTED"


# --- D-1: GIT ranges next to an ECOSYSTEM range or a `versions` list ------------------------------------
# docs/evaluation/cavr-m2-evaluation.md, "Found defect D-1". A GIT range describes commits; for a PyPI release the
# ECOSYSTEM range or the enumerated `versions` list decides. RECORDED: the package-wide urllib3 answer of the
# evaluation (2026-11-25, response_sha256 3c505122...). Everything else here is SYNTHETIC (ids SYNTH-D1-*).

EVALUATION_OSV = Path(__file__).parent.parent / "docs" / "evaluation" / "recordings" / "osv"


def recorded_package_advisory(item, advisory_id):
    """One advisory of the package-wide OSV answer recorded in run 1 of an evaluation item."""
    import gzip
    recording = json.loads(gzip.decompress((EVALUATION_OSV / f"{item}-run1.json.gz").read_bytes()))
    answer = next(value for key, value in recording.items() if key.startswith("package-"))
    return next(vuln for vuln in answer["response"]["vulns"] if vuln["id"] == advisory_id)


GIT_CLOSED = {"type": "GIT", "repo": "https://example.invalid/demo.git", "events": [{"introduced": "0"}, {"fixed": "8d2f1c0"}]}
GIT_OPEN = {"type": "GIT", "repo": "https://example.invalid/demo.git", "events": [{"introduced": "3a9e7b1"}]}


@pytest.mark.skipif(not (EVALUATION_OSV / "urllib3-2.2.1-run1.json.gz").is_file(), reason="no evaluation recording")
@pytest.mark.parametrize("version, status", [("2.8.0", "NOT_AFFECTED"), ("2.0.5", "AFFECTED"), ("1.26.16", "AFFECTED"),
                                             ("2.0.6", "NOT_AFFECTED"), ("1.26.17", "NOT_AFFECTED")])
def test_recorded_pysec_2023_192_is_read_from_its_ecosystem_range_and_versions(version, status):
    vuln = recorded_package_advisory("urllib3-2.2.1", "PYSEC-2023-192")   # GIT (2 fixes) + ECOSYSTEM + 85 versions
    assert {r["type"] for e in vuln["affected"] for r in e["ranges"]} == {"GIT", "ECOSYSTEM"}
    assert match_advisory("urllib3", version, vuln)["status"] == status


def test_open_git_range_with_versions_is_unknown_for_every_unlisted_version():
    vuln = synthetic("SYNTH-D1-1", GIT_OPEN, versions=["1.0", "1.1"])
    assert match_advisory("demo", "1.1", vuln)["status"] == "AFFECTED"     # listed
    # Open: a release published after OSV enumerated `versions` could contain the commit. Cannot tell.
    assert match_advisory("demo", "1.2", vuln)["status"] == "UNKNOWN"
    assert match_advisory("demo", "9.0", vuln)["status"] == "UNKNOWN"
    # Not listed and below the highest listed: still UNKNOWN. An open GIT range with no ECOSYSTEM range is never
    # left out (fix rule 1), so only a listed version is decided.
    assert match_advisory("demo", "0.9", vuln)["status"] == "UNKNOWN"


@pytest.mark.parametrize("ranges", [[GIT_CLOSED], [GIT_OPEN], [GIT_CLOSED, GIT_OPEN]])
@pytest.mark.parametrize("versions", [None, []])
def test_git_only_entry_without_versions_stays_unknown(ranges, versions):
    vuln = synthetic("SYNTH-D1-2", *ranges, versions=versions)
    for version in ("0.1", "1.0", "9.0"):
        assert match_advisory("demo", version, vuln)["status"] == "UNKNOWN"


def test_closed_git_only_entry_is_read_from_its_versions_list():
    vuln = synthetic("SYNTH-D1-3", GIT_CLOSED, versions=["1.0", "1.1"])
    assert match_advisory("demo", "1.0", vuln)["status"] == "AFFECTED"
    assert match_advisory("demo", "1.1", vuln)["status"] == "AFFECTED"
    assert match_advisory("demo", "1.2", vuln)["status"] == "NOT_AFFECTED"
    assert match_advisory("demo", "0.9", vuln)["status"] == "NOT_AFFECTED"


def test_closed_and_open_git_ranges_together_stay_unknown_for_an_unlisted_version():
    vuln = synthetic("SYNTH-D1-4", GIT_CLOSED, GIT_OPEN, versions=["1.0"])
    assert match_advisory("demo", "1.0", vuln)["status"] == "AFFECTED"
    assert match_advisory("demo", "2.0", vuln)["status"] == "UNKNOWN"     # the open one is not left out


@pytest.mark.parametrize("closing", [{"fixed": "8d2f1c0"}, {"limit": "8d2f1c0"}])
def test_git_closing_events_are_fixed_and_limit(closing):
    git = {"type": "GIT", "events": [{"introduced": "0"}, closing]}
    assert match_advisory("demo", "2.0", synthetic("SYNTH-D1-5", git, versions=["1.0"]))["status"] == "NOT_AFFECTED"
    last = {"type": "GIT", "events": [{"introduced": "0"}, {"last_affected": "8d2f1c0"}]}  # not a closing event in the fix
    assert match_advisory("demo", "2.0", synthetic("SYNTH-D1-6", last, versions=["1.0"]))["status"] == "UNKNOWN"


def test_open_git_range_next_to_an_ecosystem_range_is_read_from_the_ecosystem_range():
    vuln = synthetic("SYNTH-D1-7", GIT_OPEN, ecosystem({"introduced": "1.0"}))
    assert match_advisory("demo", "1.5", vuln)["status"] == "AFFECTED"
    assert match_advisory("demo", "0.9", vuln)["status"] == "NOT_AFFECTED"


@pytest.mark.parametrize("version, listed", [("2.0.0", "2.0"), ("2.0", "2.0.0"), ("1.0.0", "v1.0"), ("1.0.post0", "1.0.post0")])
def test_versions_list_is_compared_as_versions_not_strings(version, listed):
    vuln = synthetic("SYNTH-D1-8", GIT_CLOSED, versions=["0.5", listed])
    assert match_advisory("demo", version, vuln)["status"] == "AFFECTED"
    assert match_advisory("demo", version, synthetic("SYNTH-D1-9", versions=[listed]))["status"] == "AFFECTED"


@pytest.mark.parametrize("junk", ["not a version", 7, None])
def test_a_versions_list_with_an_item_that_is_not_a_version_is_not_an_enumeration(junk):
    """Review MINOR 1: such a list cannot be trusted to enumerate the releases, so the closed GIT range stays in."""
    vuln = synthetic("SYNTH-D1-10", GIT_CLOSED, versions=[junk, "1.0"])
    assert match_advisory("demo", "1.0", vuln)["status"] == "AFFECTED"      # a listed version is still found
    assert match_advisory("demo", "2.0", vuln)["status"] == "UNKNOWN"       # an unlisted one cannot be told
    if isinstance(junk, str):
        assert match_advisory("demo", junk, vuln)["status"] == "AFFECTED"  # exact string, as before


@pytest.mark.parametrize("degenerate", [ecosystem(), ecosystem({"fixed": "1.5"}), ecosystem({"limit": "1.5"}),
                                        ecosystem({"last_affected": "1.5"})])
def test_an_ecosystem_range_without_introduced_does_not_replace_the_git_range(degenerate):
    """Review MINOR 2: an ECOSYSTEM range that opens nothing says nothing about releases; the GIT range stays in."""
    vuln = synthetic("SYNTH-D1-15", GIT_CLOSED, degenerate)
    for version in ("1.0", "2.0"):
        assert match_advisory("demo", version, vuln)["status"] == "UNKNOWN"
    with_introduced = synthetic("SYNTH-D1-16", GIT_CLOSED, degenerate, ecosystem({"introduced": "3.0"}))
    assert match_advisory("demo", "2.0", with_introduced)["status"] == "NOT_AFFECTED"   # a real range decides


@pytest.mark.parametrize("vuln", [
    synthetic("SYNTH-D1-11", GIT_CLOSED, ecosystem({"introduced": "0"}, {"fixed": "not-a-version"})),
    synthetic("SYNTH-D1-12", GIT_CLOSED, {"type": "MADE_UP", "events": [{"introduced": "0"}]}, versions=["1.0"]),
    synthetic("SYNTH-D1-13", GIT_CLOSED, ecosystem({"introduced": "0"}, {"until": "0.5"}), versions=["0.1"]),
])
def test_leaving_a_git_range_out_never_hides_another_range_that_cannot_be_evaluated(vuln):
    status = match_advisory("demo", "2.0", vuln)["status"]
    assert status in ("UNKNOWN", "AFFECTED")       # never NOT_AFFECTED: the other range still decides


def test_unparseable_release_version_keeps_the_git_range_unknown():
    vuln = synthetic("SYNTH-D1-14", GIT_CLOSED, versions=["1.0"])
    assert match_advisory("demo", "nope", vuln)["status"] == "UNKNOWN"


# --- D-1 and the fast gate: the verdict for a requested version does not move toward VERIFIED ----------------

@pytest.mark.parametrize("vuln, rule", [
    # OSV returned these for 2.0 but CAVR cannot evaluate them for 2.0: cannot tell -> UNRESOLVED.
    (synthetic("SYNTH-D1-20", GIT_OPEN, versions=["1.0"]), "RANGE_UNSUPPORTED"),
    (synthetic("SYNTH-D1-21", GIT_CLOSED), "RANGE_UNSUPPORTED"),
    (synthetic("SYNTH-D1-22", GIT_OPEN), "RANGE_UNSUPPORTED"),
    (synthetic("SYNTH-D1-23", GIT_CLOSED, versions=[]), "RANGE_UNSUPPORTED"),
    # OSV returned these for 2.0 but their ECOSYSTEM range / versions do not contain 2.0: the two readings disagree
    # -> UNRESOLVED (before the fix the same answers were UNRESOLVED RANGE_UNSUPPORTED).
    (synthetic("SYNTH-D1-24", GIT_CLOSED, ecosystem({"introduced": "0"}, {"fixed": "1.5"})), "RANGE_DISAGREEMENT"),
    (synthetic("SYNTH-D1-25", GIT_CLOSED, versions=["1.0"]), "RANGE_DISAGREEMENT"),
])
def test_an_advisory_osv_returns_that_cavr_does_not_read_as_affected_is_unresolved_never_ok(tmp_path, vuln, rule):
    result = check(tmp_path, "demo", "2.0", [vuln])
    assert outcome(result) == ("UNRESOLVED", rule)
    assert result["result"] != "OK"


def test_an_affected_advisory_next_to_an_open_git_one_still_rejects(tmp_path):
    affected = synthetic("SYNTH-D1-26", GIT_CLOSED, versions=["2.0"])
    result = check(tmp_path, "demo", "2.0", [synthetic("SYNTH-D1-27", GIT_OPEN), affected])
    assert outcome(result) == ("REJECTED", "KNOWN_VULNERABILITY")


def recorded_version_answers():
    """(label, judged entry, OSV answer) for every per-version advisory result in the raw JSON (`runs[].advisories`),
    matched to its recorded answer by (item, run, package name, version) from the recording's `query`. Each judged
    entry must have exactly one recorded answer, with the same response_sha256."""
    import gzip
    from packaging.utils import canonicalize_name
    raw_path = EVALUATION_OSV.parent.parent / "cavr-m2-eval-raw.json"
    if not raw_path.is_file():
        return []
    recorded = {}
    for path in sorted(EVALUATION_OSV.glob("*-run*.json.gz")):
        item, run = path.name[:-len(".json.gz")].rsplit("-run", 1)
        for key, answer in json.loads(gzip.decompress(path.read_bytes())).items():
            query = answer.get("query", {})
            if key.startswith("package-") or "version" not in query:
                continue
            index = (item, int(run), canonicalize_name(query["package"]["name"]), query["version"])
            assert index not in recorded, index
            recorded[index] = answer
    cases = []
    for item in json.loads(raw_path.read_text())["items"]:
        for run in item["runs"]:
            for judged in run.get("advisories") or []:
                index = (item["id"], run["run"], canonicalize_name(judged["name"]), judged["version"])
                answer = recorded[index]                                    # a KeyError fails the collection
                assert answer["response_sha256"] == judged["response_sha256"], index
                cases.append(("{}-run{} {} {}".format(*index), judged, answer))
    return cases


RECORDED_VERSION_ANSWERS = recorded_version_answers()


@pytest.mark.skipif(not RECORDED_VERSION_ANSWERS, reason="no evaluation recording")
def test_every_recorded_per_version_answer_is_judged_as_it_was_in_the_evaluation_run():
    """A REGRESSION GUARD ONLY: the fast gate's advisory decision on the per-version answers of the 2026-11-25 run is
    unchanged. None of these answers holds a GIT range, so this does not test the D-1 change itself; the GIT
    evidence on real data is `test_cavr_eval.py::test_on_the_recorded_package_wide_answers_...`."""
    assert len(RECORDED_VERSION_ANSWERS) == 74                     # every entry of `runs[].advisories` in the raw JSON
    assert len({(label.split()[0], r["response_sha256"]) for label, r, _ in RECORDED_VERSION_ANSWERS}) == 58
    with_advisories = [label for label, _, answer in RECORDED_VERSION_ANSWERS if answer["response"]["vulns"]]
    assert len(with_advisories) == 10                              # 5 REJECTED packages x 2 runs; the rest are empty
    assert not [label for label, _, answer in RECORDED_VERSION_ANSWERS for vuln in answer["response"]["vulns"]
                for entry in vuln.get("affected") or [] for item in entry.get("ranges") or [] if item.get("type") == "GIT"]
    for label, recorded, answer in RECORDED_VERSION_ANSWERS:
        vulns = answer["response"]["vulns"]
        result = check_advisories(recorded["name"], recorded["version"], None, osv=StubOSV(live_answer(vulns)))
        assert (result["result"], result["rule"]) == (recorded["result"], recorded["rule"]), label


def test_advisory_for_another_package_or_ecosystem():
    assert match_advisory("demo", "1.0", synthetic("SYNTH-15", ecosystem({"introduced": "0"}), name="other"))["status"] == "OTHER_PACKAGE"
    npm = synthetic("SYNTH-16", ecosystem({"introduced": "0"}))
    npm["affected"][0]["package"]["ecosystem"] = "npm"
    assert match_advisory("demo", "1.0", npm)["status"] == "OTHER_PACKAGE"
    assert match_advisory("demo", "1.0", {"id": "SYNTH-17"})["status"] == "OTHER_PACKAGE"


def test_package_name_is_matched_canonically():
    vuln = synthetic("SYNTH-18", ecosystem({"introduced": "0"}), name="Foo_Bar")
    assert match_advisory("foo-bar", "1.0", vuln)["status"] == "AFFECTED"


def test_withdrawn_advisory_is_not_a_finding(tmp_path):
    vuln = synthetic("SYNTH-19", ecosystem({"introduced": "0"}), withdrawn="2026-01-01T00:00:00Z")
    assert match_advisory("demo", "1.0", vuln)["status"] == "WITHDRAWN"
    result = check(tmp_path, "demo", "1.0", [vuln])
    assert outcome(result) == ("OK", "NO_KNOWN_VULNERABILITY") and result["withdrawn"] == ["SYNTH-19"]


# --- the decision ----------------------------------------------------------------------------------------

def test_affected_wins_over_unknown(tmp_path):
    affected = synthetic("SYNTH-20", ecosystem({"introduced": "0"}))
    result = check(tmp_path, "demo", "1.0", [GIT_ONLY, affected])
    assert outcome(result) == ("REJECTED", "KNOWN_VULNERABILITY")
    assert [e["id"] for e in result["affected"]] == ["SYNTH-20"] and [e["id"] for e in result["unknown"]] == ["SYNTH-6"]


def test_advisory_osv_returned_but_whose_range_excludes_the_version_is_unresolved(tmp_path):
    # OSV answers per version: it only returns advisories it considers to affect that version. When
    # the range check here says "not affected", the two disagree and nothing is concluded.
    result = check(tmp_path, "pypdf", "6.19.0", [FIXED_IN_6_19_0])
    assert outcome(result) == ("UNRESOLVED", "RANGE_DISAGREEMENT")
    assert [entry["id"] for entry in result["not_affected"]] == ["GHSA-php9-fj8v-98fj"]


def test_advisory_for_another_package_in_the_answer_is_unresolved(tmp_path):
    other = synthetic("SYNTH-21", ecosystem({"introduced": "0"}), name="other")
    assert outcome(check(tmp_path, "demo", "1.0", [other])) == ("UNRESOLVED", "RANGE_DISAGREEMENT")


# --- no data, stale data, damaged data -> UNRESOLVED -----------------------------------------------------

def test_no_data_is_unresolved(tmp_path):
    result = check_advisories("demo", "1.0", tmp_path / "empty-cache")
    assert outcome(result) == ("UNRESOLVED", "ADVISORIES_UNAVAILABLE")
    assert result["mode"] == "UNAVAILABLE" and result["affected"] == []


def test_stale_cache_is_unresolved(tmp_path):
    write_cache(tmp_path / "osv", "demo", "1.0", [], age_days=31)
    result = check_advisories("demo", "1.0", tmp_path / "osv")
    assert outcome(result) == ("UNRESOLVED", "ADVISORIES_STALE")
    assert 30.9 < result["age_days"] < 31.1


def test_cache_just_inside_the_age_limit_is_used(tmp_path):
    write_cache(tmp_path / "osv", "demo", "1.0", [], age_days=29.9)
    assert outcome(check_advisories("demo", "1.0", tmp_path / "osv")) == ("OK", "NO_KNOWN_VULNERABILITY")


def test_max_age_can_be_tightened(tmp_path):
    write_cache(tmp_path / "osv", "demo", "1.0", [], age_days=2)
    assert outcome(check_advisories("demo", "1.0", tmp_path / "osv", max_age_days=1)) == ("UNRESOLVED", "ADVISORIES_STALE")


def test_cache_dated_in_the_future_is_unresolved(tmp_path):
    write_cache(tmp_path / "osv", "demo", "1.0", [], age_days=-400)
    assert outcome(check_advisories("demo", "1.0", tmp_path / "osv")) == ("UNRESOLVED", "ADVISORIES_STALE")


def test_cache_whose_content_was_edited_is_unresolved(tmp_path):
    affected = synthetic("SYNTH-22", ecosystem({"introduced": "0"}))
    path = write_cache(tmp_path / "osv", "demo", "1.0", [affected])
    value = json.loads(path.read_text())
    value["response"]["vulns"] = []          # the advisory is removed, the digest is left as it was
    path.write_text(json.dumps(value))
    assert outcome(check_advisories("demo", "1.0", tmp_path / "osv")) == ("UNRESOLVED", "ADVISORIES_UNAVAILABLE")


def test_cache_entry_for_another_version_is_not_used(tmp_path):
    path = write_cache(tmp_path / "osv", "demo", "2.0", [])
    wanted = {"package": {"name": "demo", "ecosystem": "PyPI"}, "version": "1.0"}
    path.rename(path.with_name(digest(wanted) + ".json"))
    assert outcome(check_advisories("demo", "1.0", tmp_path / "osv")) == ("UNRESOLVED", "ADVISORIES_UNAVAILABLE")


@pytest.mark.parametrize("text", ["not json", "[]", "{}", '{"retrieved_at": "yesterday"}'])
def test_unreadable_cache_file_is_unresolved(tmp_path, text):
    path = write_cache(tmp_path / "osv", "demo", "1.0", [])
    path.write_text(text)
    assert outcome(check_advisories("demo", "1.0", tmp_path / "osv")) == ("UNRESOLVED", "ADVISORIES_UNAVAILABLE")


def test_pypi_registry_fallback_is_not_osv_data(tmp_path):
    # The adapter falls back to PyPI's own advisory list when OSV cannot be asked. That list has no
    # ranges to check, so it does not count as an OSV answer.
    query = {"package": {"name": "demo", "ecosystem": "PyPI"}, "version": "1.0"}
    body = {"vulnerabilities": []}
    cache = tmp_path / "osv"
    cache.mkdir()
    (cache / ("registry-" + digest(query) + ".json")).write_text(json.dumps({
        "query": query, "retrieved_at": datetime.now(timezone.utc).isoformat(), "source": "https://pypi.org/pypi/demo/1.0/json",
        "response": body, "response_sha256": digest(body)}))
    assert OSV(cache).query("demo", "1.0")["mode"].startswith("PYPI")
    result = check_advisories("demo", "1.0", cache)
    assert outcome(result) == ("UNRESOLVED", "ADVISORIES_UNAVAILABLE")
    assert "PyPI" in result["reason"]


@pytest.mark.parametrize("vulns", ["none", None, [5], [{"summary": "no id"}], [{"id": 7}], {"id": "x"}])
def test_malformed_advisory_list_is_unresolved(tmp_path, vulns):
    answer = live_answer([])
    answer["vulnerabilities"] = vulns
    result = check_advisories("demo", "1.0", tmp_path, osv=StubOSV(answer))
    assert outcome(result) == ("UNRESOLVED", "ADVISORIES_INVALID")


@pytest.mark.parametrize("answer", [None, "down", {}, {"available": False, "mode": "UNAVAILABLE", "error": "timed out"},
                                    RuntimeError("adapter crashed")])
def test_adapter_failure_is_unresolved(tmp_path, answer):
    assert outcome(check_advisories("demo", "1.0", tmp_path, osv=StubOSV(answer))) == ("UNRESOLVED", "ADVISORIES_UNAVAILABLE")


# --- live mode goes through the adapter ---------------------------------------------------------------------

def test_live_answer_is_used_and_live_flag_is_passed_on(tmp_path):
    stub = StubOSV(live_answer([synthetic("SYNTH-23", ecosystem({"introduced": "0"}), name="demo")]))
    result = check_advisories("Demo", "1.0", tmp_path, live=True, max_age_days=3, osv=stub)
    assert outcome(result) == ("REJECTED", "KNOWN_VULNERABILITY") and result["mode"] == "LIVE"
    assert stub.calls == [("demo", "1.0", "PyPI", True, 3)]


def test_live_failure_falls_back_to_a_fresh_cache_and_says_so(tmp_path, monkeypatch):
    import backend.integrations.osv_adapter as adapter

    class Down:
        def __init__(self, *args, **kwargs):
            raise OSError("network is unreachable")

    monkeypatch.setattr(adapter.httpx, "Client", Down)
    write_cache(tmp_path / "osv", "demo", "1.0", [], age_days=1)
    result = check_advisories("demo", "1.0", tmp_path / "osv", live=True)
    assert outcome(result) == ("OK", "NO_KNOWN_VULNERABILITY")
    assert result["mode"] == "DATED CACHE" and "unreachable" in result["live_error"]


def test_live_failure_without_a_cache_is_unresolved(tmp_path, monkeypatch):
    import backend.integrations.osv_adapter as adapter

    class Down:
        def __init__(self, *args, **kwargs):
            raise OSError("network is unreachable")

    monkeypatch.setattr(adapter.httpx, "Client", Down)
    result = check_advisories("demo", "1.0", tmp_path / "osv", live=True)
    assert outcome(result) == ("UNRESOLVED", "ADVISORIES_UNAVAILABLE") and "unreachable" in result["reason"]


# --- request and shape ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name, version", [("", "1.0"), ("demo", "nope"), (None, "1.0"), ("demo", None)])
def test_invalid_request_is_unresolved(tmp_path, name, version):
    stub = StubOSV(live_answer([]))
    assert outcome(check_advisories(name, version, tmp_path, osv=stub)) == ("UNRESOLVED", "INVALID_REQUEST")
    assert stub.calls == []


def test_every_result_has_the_same_keys(tmp_path):
    good = check(tmp_path, "pypdf", "5.1.0", RECORDED_5_1_0)
    none = check_advisories("demo", "1.0", tmp_path / "empty")
    bad = check_advisories("demo", "nope", tmp_path / "empty")
    assert set(good) == set(none) == set(bad)
    assert good["ecosystem"] == "PyPI" and good["name"] == "pypdf"
