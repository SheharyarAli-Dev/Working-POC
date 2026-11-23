"""Edge and failure cases of the repair proposal (review of steps M2-3 to M2-5).

The reader functions it adds (`pypi_client.fetch_releases`, `pypi_client.release_wheel`,
`advisories.package_advisories`), the requirements and lockfile patches, the project copy, and the rules that
`tests/test_cavr_repair.py` does not reach. Synthetic `demo` wheels (real zip files) and SYNTH- advisories.
"""
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from backend.cavr import pypi_client, repair_proposal
from backend.cavr.advisories import package_advisories, package_cache_path
from backend.cavr.pypi_client import TransportError, fetch_releases, project_url, registry_url, release_wheel
from backend.cavr.repair_proposal import _ProjectFiles, _policy_for_pin
from test_cavr_repair import LOCKFILE, demo_world, judged, project_state, repair
from test_cavr_support import FakeIndex, build_wheel, file_entry, project_response, registry_response, \
    synthetic_advisory, write_package_osv_cache


# --- pypi_client.fetch_releases / release_wheel ----------------------------------------------------------------------

def test_fetch_releases_reads_yanked_and_wheel_flags(tmp_path):
    index = FakeIndex()
    wheel = build_wheel(tmp_path, "demo", "1.0")
    yanked = {**file_entry(wheel), "yanked": True, "yanked_reason": "bad"}
    sdist = {**file_entry(wheel), "packagetype": "sdist", "filename": "demo-1.1.tar.gz"}
    index.add_project("demo", project_response("demo", {"1.0": [file_entry(wheel)], "1.1": [sdist], "1.2": [yanked],
                                                        "1.3": [], "not-a-version": [file_entry(wheel)]}))
    found = fetch_releases("Demo", transport=index)
    assert (found["result"], found["rule"], found["url"]) == ("OK", "RELEASES_READ", project_url("demo"))
    rows = {r["version"]: (r["yanked"], r["has_wheel"], r["yanked_reason"]) for r in found["releases"]}
    assert rows == {"1.0": (False, True, None), "1.1": (False, False, None), "1.2": (True, False, "bad"),
                    "1.3": (True, False, "no files"), "not-a-version": (False, True, None)}
    assert [r["version"] for r in found["releases"]][-1] == "not-a-version"   # unparsable versions sort last
    assert len(found["response_sha256"]) == 64


@pytest.mark.parametrize("body, rule", [
    (TransportError("HTTP 404", status=404), "PROJECT_NOT_FOUND"),
    (TransportError("connection reset"), "REGISTRY_UNAVAILABLE"),
    (b"{not json", "REGISTRY_INVALID"),
    (json.dumps({"info": {"name": "other"}, "releases": {}}).encode(), "REGISTRY_INVALID"),
    (json.dumps({"info": {"name": "demo"}, "releases": []}).encode(), "REGISTRY_INVALID"),
    (json.dumps({"info": {"name": "demo"}, "releases": {"1.0": ["x"]}}).encode(), "REGISTRY_INVALID"),
])
def test_fetch_releases_failures_are_unresolved(body, rule):
    index = FakeIndex()
    index.routes[project_url("demo")] = body
    found = fetch_releases("demo", transport=index)
    assert (found["result"], found["rule"], found["releases"]) == ("UNRESOLVED", rule, [])


def test_fetch_releases_over_the_size_cap_is_unresolved(monkeypatch):
    index = FakeIndex()
    index.add_project("demo", project_response("demo", {}))
    monkeypatch.setattr(pypi_client, "MAX_REGISTRY_BYTES", 10)
    assert fetch_releases("demo", transport=index)["rule"] == "REGISTRY_INVALID"
    assert fetch_releases("not a name!", transport=index)["rule"] == "INVALID_REQUEST"


def test_release_wheel_names_the_wheel_and_its_registry_digest_without_downloading(tmp_path):
    index = FakeIndex()
    wheel = build_wheel(tmp_path, "demo", "1.0")
    index.add("demo", "1.0", wheel)
    found = release_wheel("demo", "1.0", transport=index)
    assert (found["result"], found["filename"]) == ("OK", wheel.name) and found["sha256"] == file_entry(wheel)["digests"]["sha256"]
    assert index.downloads() == []


@pytest.mark.parametrize("change, rule", [
    (lambda r: r["info"].update(yanked=True), "YANKED"),
    (lambda r: r["urls"][0].update(yanked=True), "YANKED"),
    (lambda r: r["urls"][0].update(digests={}), "REGISTRY_DIGEST_MISSING"),
    (lambda r: r["urls"].clear(), "NO_WHEEL"),
    (lambda r: r["info"].update(version="9.9"), "REGISTRY_INVALID"),
])
def test_release_wheel_failures_are_unresolved(tmp_path, change, rule):
    index = FakeIndex()
    wheel = build_wheel(tmp_path, "demo", "1.0")
    response = registry_response("demo", "1.0", [file_entry(wheel)])
    change(response)
    index.add("demo", "1.0", response=response)
    assert (release_wheel("demo", "1.0", transport=index)["result"], release_wheel("demo", "1.0", transport=index)["rule"]) == ("UNRESOLVED", rule)
    assert release_wheel("demo", "2.0", transport=index)["rule"] == "RELEASE_NOT_FOUND"


# --- advisories.package_advisories -----------------------------------------------------------------------------

def test_package_advisories_reads_a_fresh_cache(tmp_path):
    write_package_osv_cache(tmp_path, "demo", [synthetic_advisory("SYNTH-E-1", "demo", fixed="2")])
    found = package_advisories("Demo", tmp_path)
    assert (found["result"], found["rule"], found["mode"], found["advisory_count"]) == ("OK", "PACKAGE_ADVISORIES_READ", "DATED CACHE", 1)


def test_package_advisories_without_a_cache_or_with_a_damaged_one_is_unavailable(tmp_path):
    assert package_advisories("demo", tmp_path)["rule"] == "ADVISORIES_UNAVAILABLE"
    path = write_package_osv_cache(tmp_path, "demo", [])
    value = json.loads(path.read_text())
    value["response"]["vulns"].append({"id": "SYNTH-SNEAKED-IN"})       # digest no longer matches
    path.write_text(json.dumps(value))
    assert package_advisories("demo", tmp_path)["rule"] == "ADVISORIES_UNAVAILABLE"


def test_package_advisories_invalid_list_future_date_and_bad_name(tmp_path):
    class Stub:
        def __init__(self, answer):
            self.answer = answer

        def query_package(self, name, live=False):
            return self.answer

    now = datetime.now(timezone.utc).isoformat()
    assert package_advisories("demo", tmp_path, osv=Stub({"available": True, "retrieved_at": now,
                                                          "vulnerabilities": [{"no": "id"}]}))["rule"] == "ADVISORIES_INVALID"
    future = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    assert package_advisories("demo", tmp_path, osv=Stub({"available": True, "retrieved_at": future,
                                                          "vulnerabilities": []}))["rule"] == "ADVISORIES_STALE"
    assert package_advisories("demo", tmp_path, osv=Stub({"available": True, "retrieved_at": "yesterday",
                                                          "vulnerabilities": []}))["rule"] == "ADVISORIES_STALE"
    assert package_advisories("demo", tmp_path, osv=Stub({"available": True, "retrieved_at": now,
                                                          "vulnerabilities": []}))["result"] == "OK"
    assert package_advisories("not a name!", tmp_path)["rule"] == "INVALID_REQUEST"


def test_package_advisories_stub_without_a_package_query_never_reaches_the_network(tmp_path):
    class PerVersionOnly:
        def query(self, *args, **kwargs):
            raise AssertionError("not called")

    found = package_advisories("demo", tmp_path, live=True, osv=PerVersionOnly())
    assert (found["result"], found["rule"]) == ("UNRESOLVED", "ADVISORIES_UNAVAILABLE")
    assert not package_cache_path(tmp_path, "demo").exists()


# --- requirements, lockfile and policy patches ---------------------------------------------------------------------

def files_for(tmp_path, requirements, lockfile=None):
    (tmp_path / "requirements.txt").write_bytes(requirements.encode())
    if lockfile is not None:
        (tmp_path / LOCKFILE).write_text(json.dumps(lockfile))
    return _ProjectFiles(tmp_path, "requirements.txt", LOCKFILE)


def test_pin_rewrites_a_continued_line_with_extras_marker_and_hash_and_keeps_crlf(tmp_path):
    text = ('# pinned\r\nPyPDF[crypto]==6.19.0 ; python_version >= "3.8" \\\r\n    --hash=sha256:' + "a" * 64 +
            "\r\nrequests==2.31.0\r\n")
    files = files_for(tmp_path, text)
    patched = files.pin_requirements("pypdf", "6.19.0", "6.21.4", "b" * 64)
    assert patched["text"] == ('# pinned\r\nPyPDF[crypto]==6.21.4 ; python_version >= "3.8" --hash=sha256:' + "b" * 64 +
                               "\r\nrequests==2.31.0\r\n")
    assert "-PyPDF[crypto]==6.19.0" in patched["diff"] and "+PyPDF[crypto]==6.21.4" in patched["diff"]


def test_remove_deletes_every_physical_line_of_the_requirement(tmp_path):
    files = files_for(tmp_path, "a==1\ndemo==1.0 \\\n  --hash=sha256:" + "c" * 64 + "\nb==2\n")
    assert files.remove_requirement("demo", "1.0")["text"] == "a==1\nb==2\n"


def test_requirement_line_must_be_exactly_one_line(tmp_path):
    assert files_for(tmp_path, "demo==1.0 ; python_version < '3'\ndemo==1.0 ; python_version >= '3'\n").requirement_line("demo", "1.0") is None
    assert files_for(tmp_path, "demo==2.0\n").requirement_line("demo", "1.0") is None


def test_lockfile_patches(tmp_path):
    lockfile = {"packages": [{"name": "Demo", "version": "1.0", "ecosystem": "PyPI", "sha256": "0" * 64},
                             {"name": "top", "version": "1", "ecosystem": "PyPI"}],
                "edges": [{"source": "demo", "target": "helper"}, {"source": "top", "target": "x"}]}
    files = files_for(tmp_path, "demo==1.0\n", lockfile)
    pinned = files.pin_lockfile("demo", "1.0", "1.1", "d" * 64)
    assert pinned["before"]["sha256"] == "0" * 64
    assert pinned["lockfile"]["packages"][0] == {"name": "demo", "version": "1.1", "ecosystem": "PyPI", "sha256": "d" * 64}
    removed = files.remove_lockfile_entry("demo", "1.0")
    assert [p["name"] for p in removed["lockfile"]["packages"]] == ["top"]
    assert removed["lockfile"]["edges"] == [{"source": "top", "target": "x"}]   # the removed package's own edges go too
    assert files.lockfile_dependents_problem("demo") is None
    assert "top" in files_for(tmp_path, "x\n", {**lockfile, "edges": [{"source": "top", "target": "DEMO"}]}).lockfile_dependents_problem("demo")
    assert "not a list" in files_for(tmp_path, "x\n", {**lockfile, "edges": "all"}).lockfile_dependents_problem("demo")
    assert "no lockfile" in _ProjectFiles(tmp_path / "missing", None, LOCKFILE).lockfile_dependents_problem("demo")


def test_policy_exact_pin_is_matched_by_version_not_by_text():
    policy = {"approved_requirements": ["demo==1", "other>=1"], "denied_packages": []}
    patched = _policy_for_pin(policy, "demo", "1.0", "1.1")
    assert patched["summary"]["removed"] == ["demo==1"] and patched["summary"]["added"] == ["demo==1.1"]
    assert patched["policy"]["approved_requirements"] == ["demo==1.1", "other>=1"]
    assert policy["approved_requirements"] == ["demo==1", "other>=1"]          # the caller's policy is untouched
    wildcard = _policy_for_pin({"approved_requirements": ["demo==1.*"]}, "demo", "1.0", "2.0")["summary"]
    assert wildcard["removed"] == [] and wildcard["added"] == ["demo==2.0"]   # a wildcard is not an exact pin


# --- rules the main tests do not reach -----------------------------------------------------------------------------

def test_pre_release_is_excluded(tmp_path):
    world = demo_world(tmp_path, versions=("1.0", "1.1rc1", "1.2"))
    verdict, package = judged(world)
    block = repair(world, verdict, package)
    assert {"version": "1.1rc1", "rule": "PRE_RELEASE", "reason": "pre-release"} in block["excluded"]
    assert block["pin"]["version"] == "1.2"


def test_advisory_range_that_cannot_be_evaluated_excludes_the_release(tmp_path):
    world = demo_world(tmp_path)
    git = {"id": "SYNTH-GIT-1", "affected": [{"package": {"name": "demo", "ecosystem": "PyPI"},
                                              "ranges": [{"type": "GIT", "events": [{"introduced": "abc123"}]}]}]}
    write_package_osv_cache(world.osv_dir, "demo", [synthetic_advisory("SYNTH-REPAIR-1", "demo", fixed="1.1"), git])
    verdict, package = judged(world)
    block = repair(world, verdict, package)
    assert {e["version"]: e["rule"] for e in block["excluded"]} == {"1.1": "ADVISORY_RANGE_UNKNOWN", "1.2": "ADVISORY_RANGE_UNKNOWN"}
    assert (block["result"], block["rule"]) == ("NO_REPAIR_FOUND", "NO_SAFE_CANDIDATE")


def test_requirement_from_an_included_file_gives_no_pin(tmp_path):
    world = demo_world(tmp_path)
    (world.project / "base.txt").write_text("demo==1.0\n")
    (world.project / "requirements.txt").write_text("-r base.txt\n")
    verdict, package = judged(world)
    assert package["package"] == "demo" and package["status"] == "REJECTED"
    block = repair(world, verdict, package)
    assert (block["result"], block["rule"]) == ("NO_REPAIR_FOUND", "REQUIREMENT_LINE_NOT_FOUND")
    assert block["candidates_tried"] == []


def test_recheck_wheel_that_differs_from_the_registry_listing_is_skipped(tmp_path, monkeypatch):
    world = demo_world(tmp_path)
    (world.project / LOCKFILE).unlink()          # without a lockfile only the digest comparison can catch it
    verdict, package = judged(world)
    real = repair_proposal.release_wheel
    monkeypatch.setattr(repair_proposal, "release_wheel", lambda *a, **k: {**real(*a, **k), "sha256": "e" * 64})
    block = repair(world, verdict, package)
    assert {c["rule"] for c in block["candidates_tried"]} == {"RECHECK_DIGEST_DIFFERS"} and block["pin"] is None


def test_removal_is_not_proposed_when_another_package_of_the_request_depends_on_it(tmp_path):
    world = demo_world(tmp_path, used=False)
    world.add("top", "1.0", requires=("demo==1.0",))
    (world.project / "requirements.txt").write_text("demo==1.0\ntop==1.0\n")
    verdict, package = judged(world)
    block = repair(world, verdict, next(p for p in verdict["packages"] if p["package"] == "demo"))
    assert block["removal"] is None and "top==1.0 depends on it" in block["removal_reason"]


def test_removal_is_not_proposed_when_another_package_has_no_complete_tree(tmp_path):
    world = demo_world(tmp_path, used=False)
    world.add("top", "1.0")
    del world.index.routes[registry_url("top", "1.0")]       # top cannot be read: its tree is not complete
    (world.project / "requirements.txt").write_text("demo==1.0\ntop==1.0\n")
    verdict, package = judged(world)
    block = repair(world, verdict, next(p for p in verdict["packages"] if p["package"] == "demo"))
    assert block["removal"] is None and "not complete" in block["removal_reason"]


# --- the project copy --------------------------------------------------------------------------------------------

def test_lockfile_that_links_out_of_the_project_gives_no_repair_found(tmp_path):
    """Review blocker: the link is not copied, so a re-check would run without the project's lockfile."""
    world = demo_world(tmp_path)
    outside = tmp_path / "outside" / LOCKFILE
    outside.parent.mkdir()
    os.replace(world.project / LOCKFILE, outside)
    os.symlink(outside, world.project / LOCKFILE)
    verdict, package = judged(world)
    assert verdict["lockfile"]["present"] is True and package["status"] == "REJECTED"
    block = repair(world, verdict, package)
    assert (block["result"], block["rule"]) == ("NO_REPAIR_FOUND", "COPY_DIFFERS") and LOCKFILE in block["reason"]


def test_requirements_file_that_links_out_of_the_project_gives_no_repair_found(tmp_path):
    """`pip install -r` refuses a linked requirements file, but a requirements edit is read through the link.
    Judged first, then the file becomes a link out of the project: the copy check must see it."""
    world = demo_world(tmp_path)
    verdict, package = judged(world)
    outside = tmp_path / "outside" / "requirements.txt"
    outside.parent.mkdir()
    os.replace(world.project / "requirements.txt", outside)
    os.symlink(outside, world.project / "requirements.txt")
    block = repair(world, verdict, package)
    assert (block["result"], block["rule"]) == ("NO_REPAIR_FOUND", "COPY_DIFFERS")


def test_virtualenv_dot_directories_and_node_modules_are_not_copied(tmp_path):
    world = demo_world(tmp_path)
    world.write(".venv/pyvenv.cfg", "home = /usr\n")
    world.write("env/pyvenv.cfg", "home = /usr\n")
    world.write("env/lib/site.py", "X = 1\n")
    world.write(".secrets/.env", "TOKEN=do-not-copy\n")
    world.write("node_modules/a/index.js", "1\n")
    verdict, package = judged(world)
    state = project_state(world.project)
    block = repair(world, verdict, package)
    assert block["result"] == "PROPOSED", block["reason"]
    assert set(block["project_copy"]["skipped_directories"]) >= {".venv", "env", ".secrets", "node_modules"}
    assert project_state(world.project) == state


def test_project_over_the_copy_budget_gives_no_repair_found(tmp_path, monkeypatch):
    world = demo_world(tmp_path)
    verdict, package = judged(world)
    monkeypatch.setattr(repair_proposal, "MAX_COPY_FILES", 1)
    block = repair(world, verdict, package)
    assert (block["result"], block["rule"]) == ("NO_REPAIR_FOUND", "COPY_FAILED") and "copy budget" in block["reason"]
