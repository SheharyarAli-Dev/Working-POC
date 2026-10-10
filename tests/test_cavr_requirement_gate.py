"""C2 requirement gate: fail-closed policy check (plan step 3)."""
import copy
import json
import re

import pytest

from backend.cavr import requirement_gate
from backend.cavr.capture import parse_pip_command
from backend.cavr.manifest_parser import capture_requirements_edit, snapshot_requirements
from backend.cavr.requirement_gate import (
    check_requirement_gate,
    evaluate_capture,
    evaluate_requirement,
    gate_from_files,
    policy_problems,
    policy_version,
)

POLICY = {
    "approved_requirements": ["a==1.0", "b>=1,<2", "c", "Foo_Bar==1.0", "d==1", "d==3", "evil-pkg==1"],
    "denied_packages": [{"name": "evil-pkg", "reason": "typosquat"}, {"name": "Bad_Name"}],
}
LOCKFILE = {
    "lock_version": 1,
    "packages": [
        {"name": "a", "version": "1.0", "sha256": "0" * 64, "ecosystem": "PyPI"},
        {"name": "Foo.Bar", "version": "1", "sha256": "0" * 64, "ecosystem": "pypi"},
        {"name": "c", "version": "7", "sha256": "0" * 64, "ecosystem": "LOCAL"},
    ],
    "edges": [],
}


def verdict(requirement, policy=POLICY, lockfile=None):
    decision = evaluate_requirement(requirement, policy, lockfile)
    return decision["result"], decision["rule"]


# --- policy missing or invalid -> UNRESOLVED -----------------------------------

def test_missing_policy_is_unresolved():
    decision = evaluate_requirement("a==1.0", None)
    assert (decision["result"], decision["rule"]) == ("UNRESOLVED", "POLICY_MISSING")
    assert decision["policy_version"] is None


@pytest.mark.parametrize("policy", [
    [],
    "policy",
    {},
    {"approved_requirements": ["a==1.0"]},
    {"denied_packages": []},
    {"approved_requirements": "a==1.0", "denied_packages": []},
    {"approved_requirements": [1], "denied_packages": []},
    {"approved_requirements": ["a==1.0", "not a requirement"], "denied_packages": []},
    {"approved_requirements": ["a @ https://example.invalid/a.whl"], "denied_packages": []},
    {"approved_requirements": ['a==1.0; python_version > "3"'], "denied_packages": []},
    {"approved_requirements": ["a[x]==1.0"], "denied_packages": []},
    {"approved_requirements": ["a==1.0"], "denied_packages": {}},
    {"approved_requirements": ["a==1.0"], "denied_packages": ["evil-pkg"]},
    {"approved_requirements": ["a==1.0"], "denied_packages": [{"reason": "no name"}]},
    {"approved_requirements": ["a==1.0"], "denied_packages": [{"name": ""}]},
    {"approved_requirements": ["a==1.0"], "denied_packages": [{"name": "evil-pkg==1"}]},
    {"approved_requirements": ["a==1.0"], "denied_packages": [{"name": 5}]},
])
def test_invalid_policy_is_unresolved_even_for_an_entry_that_looks_allowed(policy):
    decision = evaluate_requirement("a==1.0", policy)
    assert (decision["result"], decision["rule"]) == ("UNRESOLVED", "POLICY_INVALID")
    assert decision["evidence"]["problems"]
    assert decision["policy_version"] is None
    assert policy_problems(policy)


def test_invalid_policy_does_not_block_or_permit_a_denied_name_either():
    policy = {"approved_requirements": ["broken =="], "denied_packages": [{"name": "evil-pkg"}]}
    assert verdict("evil-pkg==1", policy) == ("UNRESOLVED", "POLICY_INVALID")


def test_valid_policy_has_no_problems():
    assert policy_problems(POLICY) == []
    assert policy_problems({"approved_requirements": [], "denied_packages": []}) == []


# --- denylist -> BLOCK ------------------------------------------------------------

def test_denylisted_name_is_blocked_even_when_it_is_also_on_the_allowlist():
    decision = evaluate_requirement("evil-pkg==1", POLICY)
    assert (decision["result"], decision["rule"]) == ("BLOCK", "DENYLIST")
    assert decision["evidence"]["denied_package"] == {"name": "evil-pkg", "reason": "typosquat"}
    assert "typosquat" in decision["reason"]


@pytest.mark.parametrize("requirement", ["Evil_Pkg==1", "evil.pkg==9", "EVIL-PKG", "evil-pkg>=1", "bad-name==1"])
def test_denylist_matches_on_the_canonical_name_whatever_the_version(requirement):
    assert verdict(requirement) == ("BLOCK", "DENYLIST")


# --- not pinned with == -> BLOCK ----------------------------------------------------

@pytest.mark.parametrize("requirement", ["a", "a>=1.0", "a==1.*", "a~=1.0", "a>=1.0,<=1.0", "a===1.0", "a===", "a!=2", "c"])
def test_unpinned_requirement_is_blocked(requirement):
    assert verdict(requirement) == ("BLOCK", "NOT_PINNED")


def test_pinned_flag_in_the_record_is_not_trusted():
    forged = {"name": "a", "specifier": ">=1.0", "pinned": True, "version": "1.0"}
    assert verdict(forged) == ("BLOCK", "NOT_PINNED")


# --- allowlist: canonical name + specifier -> BLOCK when not on it --------------------

def test_name_not_on_the_allowlist_is_blocked():
    decision = evaluate_requirement("zzz==1.0", POLICY)
    assert (decision["result"], decision["rule"]) == ("BLOCK", "NOT_ON_ALLOWLIST")
    assert decision["evidence"]["approved_for_name"] == []


def test_wrong_version_of_an_allowed_name_is_blocked():
    decision = evaluate_requirement("a==2.0", POLICY)
    assert (decision["result"], decision["rule"]) == ("BLOCK", "NOT_ON_ALLOWLIST")
    assert decision["evidence"]["approved_for_name"] == ["a==1.0"]
    assert "2.0" in decision["reason"]


def test_exact_allowed_pin_is_permitted():
    decision = evaluate_requirement("a==1.0", POLICY)
    assert (decision["result"], decision["rule"]) == ("PERMITTED", "ALLOWED")
    assert decision["package"] == "a" and decision["version"] == "1.0"
    assert decision["evidence"]["approved_requirement"] == "a==1.0"
    assert decision["evidence"]["lockfile"] is None


@pytest.mark.parametrize("requirement, expected", [
    ("a==1", "PERMITTED"),          # 1 and 1.0 are the same version
    ("a==1.0.0", "PERMITTED"),
    ("a==1.0.1", "BLOCK"),
    ("a==1.0.post1", "BLOCK"),
    ("b==1", "PERMITTED"),
    ("b==1.9.9", "PERMITTED"),
    ("b==2", "BLOCK"),
    ("b==0.9", "BLOCK"),
    ("c==0.0.1", "PERMITTED"),      # an entry with no specifier allows any pinned version
    ("d==1", "PERMITTED"),          # two entries for one name: either may match
    ("d==3", "PERMITTED"),
    ("d==2", "BLOCK"),
])
def test_requested_version_must_satisfy_an_allowlist_specifier(requirement, expected):
    assert verdict(requirement)[0] == expected


@pytest.mark.parametrize("requirement", ["foo-bar==1.0", "Foo_Bar==1.0", "FOO.BAR==1.0", "foo__bar==1.0"])
def test_allowlist_name_is_canonicalised_on_both_sides(requirement):
    decision = evaluate_requirement(requirement, POLICY)
    assert decision["result"] == "PERMITTED"
    assert decision["package"] == "foo-bar"


def test_capture_record_is_accepted_as_input():
    (requirement,) = parse_pip_command("pip install Foo_Bar==1.0")["requirements"]
    assert verdict(requirement) == ("PERMITTED", "ALLOWED")


# --- lockfile present and name/version not in it -> BLOCK -----------------------------

def test_no_lockfile_skips_the_lockfile_rule():
    assert verdict("b==1.5", lockfile=None) == ("PERMITTED", "ALLOWED")


def test_name_and_version_in_the_lockfile_is_permitted():
    decision = evaluate_requirement("a==1.0", POLICY, LOCKFILE)
    assert decision["result"] == "PERMITTED"
    assert decision["evidence"]["lockfile"] == {"name": "a", "version": "1.0"}


def test_lockfile_names_and_versions_are_normalised():
    assert verdict("foo_bar==1.0", lockfile=LOCKFILE) == ("PERMITTED", "ALLOWED")


def test_name_missing_from_the_lockfile_is_blocked():
    decision = evaluate_requirement("b==1.5", POLICY, LOCKFILE)
    assert (decision["result"], decision["rule"]) == ("BLOCK", "NOT_IN_LOCKFILE")
    assert decision["evidence"]["locked_versions"] == []


def test_other_version_in_the_lockfile_is_blocked():
    lockfile = copy.deepcopy(LOCKFILE)
    lockfile["packages"][0]["version"] = "0.9"
    decision = evaluate_requirement("a==1.0", POLICY, lockfile)
    assert (decision["result"], decision["rule"]) == ("BLOCK", "NOT_IN_LOCKFILE")
    assert decision["evidence"]["locked_versions"] == ["0.9"]


def test_lockfile_entry_of_another_ecosystem_does_not_count():
    # `c` is locked as a LOCAL vendored file; that must not authorise a PyPI download of `c`.
    assert verdict("c==7", lockfile=LOCKFILE) == ("BLOCK", "NOT_IN_LOCKFILE")


def test_empty_lockfile_blocks_everything():
    assert verdict("a==1.0", lockfile={"packages": []}) == ("BLOCK", "NOT_IN_LOCKFILE")


@pytest.mark.parametrize("lockfile", [
    [],
    {},
    "lock",
    {"packages": {}},
    {"packages": ["a==1.0"]},
    {"packages": [{"name": "a"}]},
    {"packages": [{"name": "a", "version": 1.0, "ecosystem": "PyPI"}]},
    {"packages": [{"name": "a", "version": "1.0"}]},
    {"packages": [{"name": "a", "version": "not-a-version", "ecosystem": "PyPI"}]},
])
def test_invalid_lockfile_is_unresolved(lockfile):
    assert verdict("a==1.0", lockfile=lockfile) == ("UNRESOLVED", "LOCKFILE_INVALID")


def test_rule_order_block_reasons_come_before_the_lockfile_check():
    assert verdict("evil-pkg==1", lockfile={}) == ("BLOCK", "DENYLIST")
    assert verdict("a>=1", lockfile={}) == ("BLOCK", "NOT_PINNED")
    assert verdict("zzz==1", lockfile={}) == ("BLOCK", "NOT_ON_ALLOWLIST")


# --- the request itself is not a named requirement -> UNRESOLVED ----------------------

@pytest.mark.parametrize("requirement", [
    "", "not a requirement", "git+https://example.invalid/a.git", "./a", "a @ https://example.invalid/a.whl",
    {}, {"specifier": "==1.0"}, {"name": "a", "specifier": "=="}, {"name": 3, "specifier": "==1"}, None, 7,
])
def test_request_that_is_not_a_named_requirement_is_unresolved(requirement):
    assert verdict(requirement) == ("UNRESOLVED", "REQUIREMENT_INVALID")


# --- policy_version -----------------------------------------------------------------

def test_policy_version_is_a_sha256_of_the_canonical_json_and_is_on_every_decision():
    version = policy_version(POLICY)
    assert re.fullmatch(r"[0-9a-f]{64}", version)
    for requirement in ("a==1.0", "evil-pkg==1", "a", "zzz==1", ""):
        assert evaluate_requirement(requirement, POLICY)["policy_version"] == version


def test_policy_version_ignores_key_order_and_whitespace():
    reordered = json.loads(json.dumps({"denied_packages": POLICY["denied_packages"],
                                       "approved_requirements": POLICY["approved_requirements"]}, indent=4))
    assert policy_version(reordered) == policy_version(POLICY)


@pytest.mark.parametrize("change", [
    lambda p: p["approved_requirements"].append("zzz==1"),
    lambda p: p["approved_requirements"].__setitem__(0, "a==1.1"),
    lambda p: p["denied_packages"].pop(),
    lambda p: p["denied_packages"][0].__setitem__("reason", "other"),
    lambda p: p.__setitem__("policy_version", "2026.2"),
])
def test_policy_version_changes_with_any_change_to_the_policy(change):
    changed = copy.deepcopy(POLICY)
    change(changed)
    assert policy_version(changed) != policy_version(POLICY)


# --- a whole capture record -----------------------------------------------------------

def test_capture_with_only_permitted_requirements_is_permitted():
    decision = evaluate_capture(parse_pip_command("pip install a==1.0 b==1.5"), POLICY)
    assert (decision["result"], decision["rule"]) == ("PERMITTED", "ALLOWED")
    assert [d["result"] for d in decision["decisions"]] == ["PERMITTED", "PERMITTED"]
    assert decision["policy_version"] == policy_version(POLICY)


def test_one_blocked_requirement_blocks_the_capture():
    decision = evaluate_capture(parse_pip_command("pip install a==1.0 zzz==1"), POLICY)
    assert (decision["result"], decision["rule"]) == ("BLOCK", "NOT_ON_ALLOWLIST")
    assert "zzz" in decision["reason"]
    assert [d["result"] for d in decision["decisions"]] == ["PERMITTED", "BLOCK"]


def test_unpinned_requirement_from_a_capture_is_blocked():
    decision = evaluate_capture(parse_pip_command("pip install a"), POLICY)
    assert (decision["result"], decision["rule"]) == ("BLOCK", "NOT_PINNED")


def test_incomplete_capture_is_unresolved_even_when_its_named_requirements_are_allowed():
    record = parse_pip_command("pip install a==1.0 git+https://example.invalid/x.git")
    decision = evaluate_capture(record, POLICY)
    assert (decision["result"], decision["rule"]) == ("UNRESOLVED", "CAPTURE_INCOMPLETE")
    assert decision["evidence"]["unsupported"] == record["unsupported"]


def test_incomplete_capture_with_a_denied_name_is_blocked():
    decision = evaluate_capture(parse_pip_command("pip install evil-pkg==1 ./local"), POLICY)
    assert (decision["result"], decision["rule"]) == ("BLOCK", "DENYLIST")


def test_capture_with_no_requirements_and_incomplete_is_unresolved():
    decision = evaluate_capture(parse_pip_command("pip download a==1.0"), POLICY)
    assert (decision["result"], decision["rule"]) == ("UNRESOLVED", "CAPTURE_INCOMPLETE")


def test_capture_without_the_complete_flag_is_unresolved():
    record = parse_pip_command("pip install a==1.0")
    del record["complete"]
    assert evaluate_capture(record, POLICY)["rule"] == "CAPTURE_INCOMPLETE"
    assert evaluate_capture({}, POLICY)["rule"] == "CAPTURE_INCOMPLETE"
    assert evaluate_capture(None, POLICY)["rule"] == "CAPTURE_INCOMPLETE"


def test_capture_is_unresolved_without_a_policy_and_judges_nothing():
    decision = evaluate_capture(parse_pip_command("pip install a==1.0"), None)
    assert (decision["result"], decision["rule"]) == ("UNRESOLVED", "POLICY_MISSING")
    assert decision["decisions"] == []


def test_capture_with_an_invalid_lockfile_is_unresolved():
    decision = evaluate_capture(parse_pip_command("pip install a==1.0"), POLICY, {"packages": {}})
    assert (decision["result"], decision["rule"]) == ("UNRESOLVED", "LOCKFILE_INVALID")


def test_edit_that_only_removes_lines_has_nothing_to_verify(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("a==1.0\nb==1.5\n")
    before = snapshot_requirements(path)
    path.write_text("a==1.0\n")
    decision = evaluate_capture(capture_requirements_edit(before, snapshot_requirements(path)), POLICY)
    assert (decision["result"], decision["rule"]) == ("PERMITTED", "NOTHING_TO_VERIFY")
    assert decision["decisions"] == []


def test_edit_that_adds_an_unlisted_package_is_blocked(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("a==1.0\n")
    before = snapshot_requirements(path)
    path.write_text("a==1.0\nzzz==1\n")
    decision = evaluate_capture(capture_requirements_edit(before, snapshot_requirements(path)), POLICY)
    assert (decision["result"], decision["rule"]) == ("BLOCK", "NOT_ON_ALLOWLIST")


# --- policy and lockfile read from real files ------------------------------------------

def write(path, value):
    path.write_text(value if isinstance(value, str) else json.dumps(value))
    return path


def test_gate_from_files_permits_with_a_real_policy_and_lockfile(tmp_path):
    policy = write(tmp_path / "policy.json", POLICY)
    lock = write(tmp_path / "dependencies.lock.json", LOCKFILE)
    assert gate_from_files("a==1.0", policy, lock)["result"] == "PERMITTED"
    assert gate_from_files(parse_pip_command("pip install a==1.0"), policy, lock)["result"] == "PERMITTED"
    assert gate_from_files("b==1.5", policy, lock)["rule"] == "NOT_IN_LOCKFILE"


def test_missing_policy_file_is_unresolved(tmp_path):
    decision = gate_from_files("a==1.0", tmp_path / "nope.json")
    assert (decision["result"], decision["rule"]) == ("UNRESOLVED", "POLICY_MISSING")


@pytest.mark.parametrize("content", ["", "{not json", "[]", "null", b"\xff\xfe".decode("latin-1")])
def test_unreadable_policy_file_is_unresolved(tmp_path, content):
    path = tmp_path / "policy.json"
    path.write_bytes(content.encode("latin-1"))
    decision = gate_from_files("a==1.0", path)
    assert (decision["result"], decision["rule"]) == ("UNRESOLVED", "POLICY_INVALID")
    assert decision["policy_version"] is None


def test_policy_path_that_is_a_directory_is_unresolved(tmp_path):
    assert gate_from_files("a==1.0", tmp_path)["rule"] == "POLICY_INVALID"


def test_missing_lockfile_file_skips_the_rule(tmp_path):
    policy = write(tmp_path / "policy.json", POLICY)
    assert gate_from_files("b==1.5", policy, tmp_path / "dependencies.lock.json")["result"] == "PERMITTED"


def test_unreadable_lockfile_file_is_unresolved(tmp_path):
    policy = write(tmp_path / "policy.json", POLICY)
    lock = write(tmp_path / "dependencies.lock.json", "{not json")
    decision = gate_from_files("a==1.0", policy, lock)
    assert (decision["result"], decision["rule"]) == ("UNRESOLVED", "LOCKFILE_INVALID")
    assert gate_from_files(parse_pip_command("pip install a==1.0"), policy, lock)["rule"] == "LOCKFILE_INVALID"


def test_lockfile_containing_json_null_is_unresolved_not_skipped(tmp_path):
    policy = write(tmp_path / "policy.json", POLICY)
    lock = write(tmp_path / "dependencies.lock.json", "null")
    assert gate_from_files("a==1.0", policy, lock)["rule"] == "LOCKFILE_INVALID"


def test_real_project_lockfile_format_is_understood(tmp_path):
    from backend.config import ROOT
    policy = write(tmp_path / "policy.json", {"approved_requirements": ["pypdf>=6,<7"], "denied_packages": []})
    lock = ROOT / "demo_project" / "InvoiceHub" / "dependencies.lock.json"
    assert gate_from_files("pypdf==6.19.0", policy, lock)["result"] == "PERMITTED"
    assert gate_from_files("pypdf==6.18.0", policy, lock)["rule"] == "NOT_IN_LOCKFILE"


# --- the dashboard entry point (backend/cavr/api.py) ------------------------------------

LEGACY_KEYS = {"result", "status", "matched_rule", "rule_checked", "policy_file_excerpt", "reason"}


def test_shipped_policy_file_is_valid():
    policy = json.loads(requirement_gate.POLICY_PATH.read_text(encoding="utf-8"))
    assert policy_problems(policy) == []


def test_dashboard_gate_with_the_shipped_policy():
    denied = check_requirement_gate("requests-security", "2.31.0")
    assert (denied["result"], denied["matched_rule"], denied["status"]) == ("BLOCK", "DENYLIST", "FAIL")
    allowed = check_requirement_gate("pdf-clean-extractor", "1.0.0")
    assert (allowed["result"], allowed["status"]) == ("PERMITTED", "PASS")
    unlisted = check_requirement_gate("dormant-exfil", "1.2.0")
    assert (unlisted["result"], unlisted["matched_rule"]) == ("BLOCK", "NOT_ON_ALLOWLIST")
    wrong_version = check_requirement_gate("requests", "2.0.0")
    assert (wrong_version["result"], wrong_version["matched_rule"]) == ("BLOCK", "NOT_ON_ALLOWLIST")
    for decision in (denied, allowed, unlisted, wrong_version):
        assert LEGACY_KEYS <= decision.keys()


def test_dashboard_gate_no_longer_fails_open_without_a_policy(tmp_path, monkeypatch):
    monkeypatch.setattr(requirement_gate, "POLICY_PATH", tmp_path / "nope.json")
    decision = check_requirement_gate("requests", "2.31.0")
    assert (decision["result"], decision["status"], decision["matched_rule"]) == ("UNRESOLVED", "FAIL", "POLICY_MISSING")
    assert LEGACY_KEYS <= decision.keys()


def test_dashboard_gate_no_longer_fails_open_on_a_broken_policy(tmp_path, monkeypatch):
    path = tmp_path / "policy.json"
    path.write_text("{broken")
    monkeypatch.setattr(requirement_gate, "POLICY_PATH", path)
    decision = check_requirement_gate("requests", "2.31.0")
    assert (decision["result"], decision["status"]) == ("UNRESOLVED", "FAIL")


# --- found by the batch review: a malformed capture record must not be permitted --------

@pytest.mark.parametrize("record", [
    {"requirements": ("zzz==1",), "complete": True, "unsupported": [], "errors": []},
    {"requirements": None, "complete": True, "unsupported": [], "errors": []},
    {"requirements": "evil-pkg==1", "complete": True, "unsupported": [], "errors": []},
    {"complete": True, "unsupported": [], "errors": []},
    {"complete": True},
    [],
    "a==1.0",
])
def test_capture_whose_requirements_are_not_a_list_is_unresolved(record):
    decision = evaluate_capture(record, POLICY)
    assert (decision["result"], decision["rule"]) == ("UNRESOLVED", "CAPTURE_INCOMPLETE")
    assert decision["decisions"] == []


def test_gate_from_files_does_not_permit_a_record_with_a_string_of_requirements(tmp_path):
    policy = write(tmp_path / "policy.json", POLICY)
    record = {"requirements": "evil-pkg==1", "complete": True, "unsupported": [], "errors": []}
    assert gate_from_files(record, policy)["result"] == "UNRESOLVED"


@pytest.mark.parametrize("field, value", [
    ("unsupported", [{"raw": "./x", "reason": "local path requirement", "origin": "command"}]),
    ("errors", [{"raw": "??", "reason": "malformed requirement", "origin": "command"}]),
    ("unsupported", None),
    ("errors", "none"),
])
def test_complete_flag_is_not_trusted_when_the_record_lists_problems(field, value):
    record = parse_pip_command("pip install a==1.0")
    assert evaluate_capture(record, POLICY)["result"] == "PERMITTED"
    record[field] = value
    assert record["complete"] is True
    decision = evaluate_capture(record, POLICY)
    assert (decision["result"], decision["rule"]) == ("UNRESOLVED", "CAPTURE_INCOMPLETE")


@pytest.mark.parametrize("field", ["unsupported", "errors"])
def test_capture_without_its_problem_lists_is_unresolved(field):
    record = parse_pip_command("pip install a==1.0")
    del record[field]
    assert evaluate_capture(record, POLICY)["rule"] == "CAPTURE_INCOMPLETE"


@pytest.mark.parametrize("source", ["pip_command", None, "something_else"])
def test_empty_capture_is_permitted_only_for_a_requirements_edit(source):
    record = {"source": source, "requirements": [], "unsupported": [], "errors": [], "complete": True}
    decision = evaluate_capture(record, POLICY)
    assert (decision["result"], decision["rule"]) == ("UNRESOLVED", "CAPTURE_INCOMPLETE")
    record["source"] = "requirements_edit"
    assert evaluate_capture(record, POLICY)["rule"] == "NOTHING_TO_VERIFY"


def test_edit_with_a_hidden_duplicate_line_is_not_permitted(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text('a==1.0; python_version >= "3"\n')
    before = snapshot_requirements(path)
    path.write_text('a==2.0; python_version >= "3"\na==1.0; python_version >= "3"\n')
    decision = evaluate_capture(capture_requirements_edit(before, snapshot_requirements(path)), POLICY)
    assert (decision["result"], decision["rule"]) == ("UNRESOLVED", "CAPTURE_INCOMPLETE")
