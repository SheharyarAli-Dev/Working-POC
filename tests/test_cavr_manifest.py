"""C1 capture: requirements.txt edits -> capture records (plan step 2)."""
import hashlib

import pytest

from backend.cavr.manifest_parser import (
    capture_requirements_edit,
    detect_manifest_changes,
    parse_requirements_txt,
    read_manifest,
    snapshot_requirements,
)

SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64


def edit(tmp_path, before, after):
    """Snapshot a real file, rewrite it, snapshot again, and capture the edit."""
    path = tmp_path / "requirements.txt"
    if before is not None:
        path.write_text(before)
    first = snapshot_requirements(path)
    if after is None:
        path.unlink()
    else:
        path.write_text(after)
    return capture_requirements_edit(first, snapshot_requirements(path))


def actions(record):
    return [(c["action"], c["package"]) for c in record["changes"]]


def names(record):
    return [(r["canonical_name"], r["version"]) for r in record["requirements"]]


def reasons(record, key):
    return [e["reason"] for e in record[key]]


# --- the five cases named in the plan ------------------------------------------

def test_added_requirement(tmp_path):
    record = edit(tmp_path, "a==1\n", "a==1\nb==2\n")
    assert record["source"] == "requirements_edit"
    assert actions(record) == [("ADDED", "b")]
    assert names(record) == [("b", "2")]
    assert record["requirements"][0]["origin"] == f"{tmp_path / 'requirements.txt'}:2"
    assert record["removed"] == []
    assert record["complete"] is True


def test_version_changed(tmp_path):
    record = edit(tmp_path, "a==1\nb==2\n", "a==1\nb==3\n")
    (change,) = record["changes"]
    assert change["action"] == "VERSION_CHANGED"
    assert change["old_specifier"] == "==2" and change["new_specifier"] == "==3"
    assert names(record) == [("b", "3")]
    assert record["complete"] is True


def test_removed_requirement(tmp_path):
    record = edit(tmp_path, "a==1\nb==2\n", "a==1\n")
    assert actions(record) == [("REMOVED", "b")]
    assert record["requirements"] == []
    assert [(r["canonical_name"], r["version"]) for r in record["removed"]] == [("b", "2")]
    assert record["complete"] is True


def test_unparseable_line_is_reported_and_is_not_a_package(tmp_path):
    record = edit(tmp_path, "a==1\n", "a==1\nthis is not a requirement\nb==2\n")
    assert actions(record) == [("ADDED", "b")]
    (error,) = record["errors"]
    assert error["raw"] == "this is not a requirement"
    assert error["origin"] == f"{tmp_path / 'requirements.txt'}:2"
    assert record["complete"] is False


def test_unpinned_requirement_is_captured_as_unpinned(tmp_path):
    record = edit(tmp_path, "a==1\n", "a==1\nb>=2\nc\n")
    assert actions(record) == [("ADDED", "b"), ("ADDED", "c")]
    assert [r["pinned"] for r in record["requirements"]] == [False, False]
    assert [r["version"] for r in record["requirements"]] == [None, None]
    # Refusing an unpinned requirement is the gate's rule (C2); the capture itself is complete.
    assert record["complete"] is True


# --- the regex fallback is gone ------------------------------------------------

@pytest.mark.parametrize("line", [
    "this is not a requirement",
    "git+https://example.invalid/a.git",
    "https://example.invalid/a-1-py3-none-any.whl",
    "./local/pkg",
    "-e .",
    "a==",
    "a==1 b==2",
    "--index-url https://example.invalid/simple",
])
def test_lines_the_old_regex_fallback_accepted_are_no_longer_packages(line):
    assert parse_requirements_txt(line + "\n") == []
    manifest = read_manifest(line + "\n")
    assert manifest["requirements"] == []
    assert len(manifest["unsupported"]) + len(manifest["errors"]) == 1
    assert detect_manifest_changes("", line + "\n") == []


def test_parse_requirements_txt_keeps_its_old_keys():
    (first, second) = parse_requirements_txt("# c\nFoo_Bar==1.0\nb\n")
    assert (first["name"], first["specifier"], first["raw"]) == ("Foo_Bar", "==1.0", "Foo_Bar==1.0")
    assert (second["name"], second["specifier"]) == ("b", "*")


# --- other edits -----------------------------------------------------------------

def test_no_edit_gives_no_changes(tmp_path):
    record = edit(tmp_path, "a==1\n", "a==1\n")
    assert record["changes"] == [] and record["requirements"] == []
    assert record["changed"] is False
    assert record["complete"] is True


def test_comment_and_order_edits_change_the_file_but_not_the_requirements(tmp_path):
    record = edit(tmp_path, "a==1\nb==2\n", "# pinned\nb==2\n\na==1  # same\n")
    assert record["changed"] is True
    assert record["changes"] == []
    assert record["before_sha256"] != record["after_sha256"]


def test_respelling_a_name_is_not_a_change(tmp_path):
    record = edit(tmp_path, "Foo_Bar==1\n", "foo-bar==1\n")
    assert record["changes"] == []


def test_respelled_name_with_a_new_version_is_one_change_not_add_plus_remove(tmp_path):
    record = edit(tmp_path, "Foo_Bar==1\n", "foo.bar==2\n")
    assert actions(record) == [("VERSION_CHANGED", "foo.bar")]


def test_pin_loosened_to_a_range_is_a_change_to_an_unpinned_requirement(tmp_path):
    record = edit(tmp_path, "a==1\n", "a>=1\n")
    assert actions(record) == [("VERSION_CHANGED", "a")]
    assert record["requirements"][0]["pinned"] is False


def test_hash_change_with_the_same_version_is_reported(tmp_path):
    record = edit(tmp_path, f"a==1 --hash={SHA_A}\n", f"a==1 --hash={SHA_B}\n")
    assert actions(record) == [("MODIFIED", "a")]
    assert record["requirements"][0]["hashes"] == [SHA_B]


def test_extras_change_with_the_same_version_is_reported(tmp_path):
    record = edit(tmp_path, "a==1\n", "a[x]==1\n")
    assert actions(record) == [("MODIFIED", "a")]
    assert record["requirements"][0]["extras"] == ["x"]


def test_same_name_under_two_markers_is_tracked_per_marker(tmp_path):
    before = 'a==1; python_version < "3.8"\na==2; python_version >= "3.8"\n'
    after = 'a==1; python_version < "3.8"\na==3; python_version >= "3.8"\n'
    record = edit(tmp_path, before, after)
    assert actions(record) == [("VERSION_CHANGED", "a")]
    assert names(record) == [("a", "3")]
    assert record["errors"] == []


def test_conflicting_lines_for_one_name_are_an_error(tmp_path):
    record = edit(tmp_path, "a==1\n", "a==1\na==2\n")
    assert any("conflicting" in r for r in reasons(record, "errors"))
    assert record["complete"] is False


def test_include_lines_are_unsupported_in_an_edit(tmp_path):
    (tmp_path / "other.txt").write_text("z==9\n")
    record = edit(tmp_path, "a==1\n", "a==1\n-r other.txt\n-c other.txt\n")
    assert record["changes"] == []
    assert len(record["unsupported"]) == 2
    assert all("not followed" in r for r in reasons(record, "unsupported"))
    assert record["complete"] is False


def test_url_vcs_and_custom_index_lines_are_unsupported(tmp_path):
    record = edit(tmp_path, "a==1\n", "a==1\ngit+https://example.invalid/b.git\n"
                                       "--extra-index-url https://example.invalid/simple\n-e ./c\n")
    assert record["requirements"] == []
    assert len(record["unsupported"]) == 3
    assert record["complete"] is False


def test_unparseable_line_that_was_already_there_is_still_reported(tmp_path):
    record = edit(tmp_path, "a==1\n???\n", "a==1\n???\nb==2\n")
    assert actions(record) == [("ADDED", "b")]
    assert [e["raw"] for e in record["errors"]] == ["???"]
    assert record["complete"] is False


def test_unparseable_line_that_was_fixed_is_not_reported(tmp_path):
    record = edit(tmp_path, "a==1\n???\n", "a==1\nb==2\n")
    assert record["errors"] == []
    assert actions(record) == [("ADDED", "b")]
    assert record["complete"] is True


def test_neutral_option_lines_are_kept_as_options(tmp_path):
    record = edit(tmp_path, "a==1\n", "--pre\na==1\n")
    assert record["options"] == [["--pre", None]]
    assert record["complete"] is True


def test_removed_option_lines_are_listed(tmp_path):
    """Step 12, deferred from the batch 1-3 review: a deleted `--require-hashes` must be visible in the record."""
    record = edit(tmp_path, "--require-hashes\n--pre\na==1\n", "--pre\na==1\nb==2\n")
    assert record["removed_options"] == [["--require-hashes", None]] and record["options"] == [["--pre", None]]
    assert actions(record) == [("ADDED", "b")] and record["complete"] is True
    unchanged = edit(tmp_path, "--pre\na==1\n", "--pre\na==1\nb==2\n")
    assert unchanged["removed_options"] == []
    deleted = edit(tmp_path, "--require-hashes\na==1\n", None)
    assert deleted["removed_options"] == [["--require-hashes", None]]


# --- snapshots ---------------------------------------------------------------------

def test_snapshot_hash_is_the_sha256_of_the_real_bytes(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_bytes(b"a==1\r\nb==2\r\n")
    snap = snapshot_requirements(path)
    assert snap == {"path": str(path), "exists": True, "error": None, "content": "a==1\r\nb==2\r\n",
                    "sha256": hashlib.sha256(b"a==1\r\nb==2\r\n").hexdigest()}


def test_snapshot_of_a_missing_file(tmp_path):
    snap = snapshot_requirements(tmp_path / "requirements.txt")
    assert snap["exists"] is False and snap["sha256"] is None and snap["error"] is None


def test_file_created_means_every_line_is_added(tmp_path):
    record = edit(tmp_path, None, "a==1\nb==2\n")
    assert actions(record) == [("ADDED", "a"), ("ADDED", "b")]
    assert record["before_sha256"] is None
    assert record["complete"] is True


def test_file_deleted_means_every_line_is_removed(tmp_path):
    record = edit(tmp_path, "a==1\nb==2\n", None)
    assert actions(record) == [("REMOVED", "a"), ("REMOVED", "b")]
    assert record["requirements"] == [] and record["after_sha256"] is None
    assert record["files"] == []
    assert record["complete"] is True


def test_edited_file_that_is_not_utf8_is_an_error(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("a==1\n")
    first = snapshot_requirements(path)
    path.write_bytes(b"a==1\nb==2\n\xff\n")
    record = capture_requirements_edit(first, snapshot_requirements(path))
    assert record["requirements"] == [] and record["changes"] == []
    assert any("not UTF-8" in r for r in reasons(record, "errors"))
    assert record["complete"] is False


def test_unreadable_earlier_snapshot_means_everything_is_treated_as_added(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_bytes(b"\xff\xfe")
    first = snapshot_requirements(path)
    path.write_text("a==1\n")
    record = capture_requirements_edit(first, snapshot_requirements(path))
    assert actions(record) == [("ADDED", "a")]
    assert any("earlier snapshot" in r for r in reasons(record, "errors"))
    assert record["complete"] is False


def test_oversized_file_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr("backend.cavr.capture.MAX_REQUIREMENTS_FILE_BYTES", 8)
    record = edit(tmp_path, "a==1\n", "a==1\nb==2\n")
    assert record["requirements"] == []
    assert any("larger than" in r for r in reasons(record, "errors"))


def test_directory_in_place_of_the_file_is_an_error(tmp_path):
    (tmp_path / "requirements.txt").mkdir()
    snap = snapshot_requirements(tmp_path / "requirements.txt")
    assert snap["exists"] is True and "cannot read" in snap["error"]


def test_snapshots_of_two_different_files_are_refused(tmp_path):
    (tmp_path / "a.txt").write_text("a==1\n")
    (tmp_path / "b.txt").write_text("b==1\n")
    with pytest.raises(ValueError):
        capture_requirements_edit(snapshot_requirements(tmp_path / "a.txt"), snapshot_requirements(tmp_path / "b.txt"))


def test_record_lists_the_file_with_its_hash(tmp_path):
    record = edit(tmp_path, "a==1\n", "a==2\n")
    (entry,) = record["files"]
    assert entry["path"] == str(tmp_path / "requirements.txt")
    assert entry["sha256"] == hashlib.sha256(b"a==2\n").hexdigest() == record["after_sha256"]


# --- detect_manifest_changes (text in, change list out) ----------------------------

def test_detect_manifest_changes_shape():
    changes = detect_manifest_changes("a==1\nb==2\nc==3\n", "a==1\nb==5\nd\n")
    assert [(c["action"], c["package"]) for c in changes] == [
        ("VERSION_CHANGED", "b"), ("ADDED", "d"), ("REMOVED", "c")]
    assert changes[1]["specifier"] == "*"
    assert changes[2]["specifier"] == "==3"


def test_pyproject_branch_still_works():
    before = '[project]\ndependencies = ["a==1", "b==2"]\n'
    after = '[project]\ndependencies = ["a==1", "b==3", "c"]\n'
    changes = detect_manifest_changes(before, after, "pyproject.toml")
    assert [(c["action"], c["package"]) for c in changes] == [("VERSION_CHANGED", "b"), ("ADDED", "c")]


# --- found by the batch review: a second line for the same requirement must not vanish ---

@pytest.mark.parametrize("before, after", [
    ('a==1.0; python_version >= "3"\n', 'a==2.0; python_version >= "3"\na==1.0; python_version >= "3"\n'),
    ("a==1\n", "a[x]==1\na==1\n"),
    (f"a==1 --hash={SHA_A}\n", f"a==1 --hash={SHA_B}\na==1 --hash={SHA_A}\n"),
    ("a==1\n", "a==1\nA==1 --hash=" + SHA_A + "\n"),
])
def test_differing_lines_for_the_same_requirement_are_an_error(tmp_path, before, after):
    record = edit(tmp_path, before, after)
    (error,) = record["errors"]
    assert "conflicting" in error["reason"]
    assert error["origin"].endswith(":1, " + str(tmp_path / "requirements.txt") + ":2")
    assert record["complete"] is False


def test_identical_duplicate_lines_are_not_an_error(tmp_path):
    record = edit(tmp_path, "a==1\n", "a==1\nA==1\nb==2\nb==2\n")
    assert record["errors"] == []
    assert actions(record) == [("ADDED", "b")]
    assert record["complete"] is True


def test_read_manifest_reports_one_error_per_duplicated_requirement():
    manifest = read_manifest("a==1\na==2\na==3\nb==1\n")
    assert len(manifest["errors"]) == 1
    assert manifest["errors"][0]["origin"] == "requirements.txt:1, requirements.txt:2"
