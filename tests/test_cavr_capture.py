"""C1 capture: pip install commands -> capture records (plan step 1)."""
import hashlib

import pytest

from backend.cavr.capture import parse_pip_command, parse_requirement

SHA = "sha256:" + "a" * 64


def names(record, key="requirements"):
    return [(r["canonical_name"], r["version"]) for r in record[key]]


def reasons(record, key):
    return [e["reason"] for e in record[key]]


# --- command forms -----------------------------------------------------------

def test_pip_install_with_two_pins():
    record = parse_pip_command("pip install a==1 b==2")
    assert record["source"] == "pip_command"
    assert record["action"] == "install"
    assert names(record) == [("a", "1"), ("b", "2")]
    assert all(r["pinned"] and r["origin"] == "command" for r in record["requirements"])
    assert record["unsupported"] == [] and record["errors"] == []
    assert record["complete"] is True


def test_command_can_be_given_as_an_argument_list():
    record = parse_pip_command(["pip", "install", "a==1"])
    assert names(record) == [("a", "1")]
    assert record["command"] == ["pip", "install", "a==1"]


@pytest.mark.parametrize("command", [
    "python -m pip install a==1",
    "python3 -m pip install a==1",
    "python3.12 -I -m pip install a==1",
    "/usr/bin/python3 -m pip install a==1",
    "pip3 install a==1",
    "pip3.12 install a==1",
    "/home/u/.venv/bin/pip install a==1",
    "py -m pip install a==1",
])
def test_pip_launcher_forms(command):
    record = parse_pip_command(command)
    assert names(record) == [("a", "1")]
    assert record["complete"] is True


@pytest.mark.parametrize("command", [
    "pip --no-cache-dir install a==1",
    "pip -q install -U a==1",
    "pip install --upgrade --no-deps a==1",
    "pip install -qU a==1",
    "pip --timeout 5 install --target out a==1",
    "pip install --target=out a==1",
    "pip install -t out a==1",
])
def test_known_options_do_not_become_requirements(command):
    record = parse_pip_command(command)
    assert names(record) == [("a", "1")]
    assert record["complete"] is True


def test_recognised_options_are_recorded():
    record = parse_pip_command("pip install --upgrade --target out a==1")
    assert record["options"] == [["--upgrade", None], ["--target", "out"]]


def test_name_is_canonicalised_but_the_written_name_is_kept():
    record = parse_pip_command("pip install Foo_Bar==1.0")
    (req,) = record["requirements"]
    assert req["name"] == "Foo_Bar"
    assert req["canonical_name"] == "foo-bar"
    assert req["raw"] == "Foo_Bar==1.0"


def test_extras_and_marker_are_recorded():
    record = parse_pip_command(["pip", "install", 'a[x,b]==1; python_version >= "3"'])
    (req,) = record["requirements"]
    assert req["extras"] == ["b", "x"]
    assert req["marker"] == 'python_version >= "3"'
    assert req["pinned"] is True


@pytest.mark.parametrize("spec", ["a", "a>=1", "a==1.*", "a~=1.0", "a>=1,<2", "a===1", "a!=1"])
def test_anything_but_one_exact_pin_is_recorded_as_unpinned(spec):
    record = parse_pip_command(["pip", "install", spec])
    (req,) = record["requirements"]
    assert req["pinned"] is False
    assert req["version"] is None
    # Unpinned is a gate decision (C2), not a capture failure.
    assert record["complete"] is True


# --- not captured ------------------------------------------------------------

@pytest.mark.parametrize("command, reason", [
    ("pip install https://example.invalid/a-1-py3-none-any.whl", "direct URL"),
    ("pip install git+https://example.invalid/a.git", "VCS"),
    ("pip install git+ssh://git@example.invalid/a.git@v1", "VCS"),
    ("pip install ./a", "local path"),
    ("pip install ../a", "local path"),
    ("pip install /abs/a", "local path"),
    ("pip install ~/a", "local path"),
    ("pip install .", "local path"),
    ("pip install a-1-py3-none-any.whl", "local path"),
    ("pip install a-1.tar.gz", "local path"),
    ("pip install dir/a", "local path"),
    ("pip install -e .", "editable"),
    ("pip install --editable=./a", "editable"),
    ("pip install -i https://example.invalid/simple a==1", "custom index"),
    ("pip install --index-url https://example.invalid/simple a==1", "custom index"),
    ("pip install --index-url=https://example.invalid/simple a==1", "custom index"),
    ("pip install --extra-index-url https://example.invalid/simple a==1", "custom index"),
    ("pip install -f ./wheels a==1", "custom index"),
    ("pip install --find-links ./wheels a==1", "custom index"),
    ("pip install --no-index a==1", "custom index"),
    ("pip install --trusted-host example.invalid a==1", "custom index"),
    ("pip install --no-binary :all: a==1", "source build"),
    ("pip install --frobnicate a==1", "unknown option"),
    ("pip install -Z a==1", "unknown option"),
])
def test_unsupported_forms_are_recorded_not_captured(command, reason):
    record = parse_pip_command(command)
    assert any(reason in r for r in reasons(record, "unsupported")), record["unsupported"]
    assert record["complete"] is False


def test_direct_reference_is_unsupported_not_a_named_requirement():
    record = parse_pip_command(["pip", "install", "a @ https://example.invalid/a-1-py3-none-any.whl"])
    assert record["requirements"] == []
    assert any("direct URL" in r for r in reasons(record, "unsupported"))


def test_unsupported_entry_keeps_what_was_written():
    record = parse_pip_command("pip install -e ./pkg a==1")
    (entry,) = record["unsupported"]
    assert entry["raw"] == "-e ./pkg"
    assert entry["origin"] == "command"
    # The supported requirement next to it is still captured.
    assert names(record) == [("a", "1")]


def test_value_of_a_custom_index_option_is_not_read_as_a_requirement():
    record = parse_pip_command("pip install --index-url https://example.invalid/simple a==1")
    assert names(record) == [("a", "1")]
    assert len(record["unsupported"]) == 1


@pytest.mark.parametrize("command", [
    "pip uninstall a",
    "pip download a==1",
    "pip wheel a==1",
    "pip --version",
    "pip",
])
def test_other_pip_subcommands_capture_no_requirements(command):
    record = parse_pip_command(command)
    assert record["requirements"] == []
    assert record["action"] != "install"
    assert record["complete"] is False


@pytest.mark.parametrize("command", [
    "ls -la",
    "python script.py install a==1",
    "python -m venv install",
    "sudo pip install a==1",
    "",
    [],
])
def test_non_pip_commands_are_errors(command):
    record = parse_pip_command(command)
    assert record["requirements"] == []
    assert any("not a pip command" in r for r in reasons(record, "errors"))
    assert record["complete"] is False


def test_unbalanced_quotes_are_an_error():
    record = parse_pip_command('pip install "a==1')
    assert record["requirements"] == []
    assert any("cannot split" in r for r in reasons(record, "errors"))


def test_install_without_any_requirement_is_an_error():
    record = parse_pip_command("pip install --upgrade")
    assert any("no requirement" in r for r in reasons(record, "errors"))
    assert record["complete"] is False


@pytest.mark.parametrize("spec", ["a==", "==1", "a=1", "a==1 b", "a b==1", "a==abc!", "[x]==1", "a==1;"])
def test_malformed_requirement_is_an_error_not_a_package(spec):
    record = parse_pip_command(["pip", "install", spec])
    assert record["requirements"] == []
    (error,) = record["errors"]
    assert error["raw"] == spec
    assert "malformed" in error["reason"]
    assert record["complete"] is False


def test_option_missing_its_value_is_an_error():
    record = parse_pip_command("pip install a==1 -r")
    assert any("needs a value" in r for r in reasons(record, "errors"))
    assert names(record) == [("a", "1")]
    assert record["complete"] is False


def test_conflicting_pins_for_one_name_are_an_error():
    record = parse_pip_command("pip install a==1 A==2")
    assert any("conflicting" in r for r in reasons(record, "errors"))
    assert record["complete"] is False


def test_same_pin_twice_is_not_a_conflict():
    record = parse_pip_command("pip install a==1 a==1")
    assert record["errors"] == []
    assert record["complete"] is True


# --- -r / -c files -----------------------------------------------------------

def test_requirement_file_is_read_and_expanded(tmp_path):
    reqs = tmp_path / "requirements.txt"
    reqs.write_text("# comment\n\na==1\nb==2  # trailing comment\n")
    record = parse_pip_command("pip install -r requirements.txt c==3", cwd=tmp_path)
    assert names(record) == [("a", "1"), ("b", "2"), ("c", "3")]
    assert record["requirements"][0]["origin"] == f"{reqs}:3"
    assert record["requirements"][1]["origin"] == f"{reqs}:4"
    assert record["requirements"][1]["raw"] == "b==2"
    assert record["complete"] is True


def test_requirement_file_hash_is_the_sha256_of_its_real_bytes(tmp_path):
    reqs = tmp_path / "requirements.txt"
    reqs.write_bytes(b"a==1\n")
    record = parse_pip_command("pip install -r requirements.txt", cwd=tmp_path)
    (entry,) = record["files"]
    assert entry["path"] == str(reqs)
    assert entry["role"] == "requirements"
    assert entry["sha256"] == hashlib.sha256(b"a==1\n").hexdigest()


@pytest.mark.parametrize("option", ["-r reqs.txt", "--requirement reqs.txt", "--requirement=reqs.txt", "-rreqs.txt"])
def test_all_spellings_of_the_requirement_option(tmp_path, option):
    (tmp_path / "reqs.txt").write_text("a==1\n")
    record = parse_pip_command(f"pip install {option}", cwd=tmp_path)
    assert names(record) == [("a", "1")]


def test_nested_requirement_files_resolve_relative_to_the_including_file(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "top.txt").write_text("a==1\n-r sub/mid.txt\n")
    (tmp_path / "sub" / "mid.txt").write_text("b==2\n--requirement leaf.txt\n")
    (tmp_path / "sub" / "leaf.txt").write_text("c==3\n")
    record = parse_pip_command("pip install -r top.txt", cwd=tmp_path)
    assert names(record) == [("a", "1"), ("b", "2"), ("c", "3")]
    assert [f["path"] for f in record["files"]] == [
        str(tmp_path / "top.txt"), str(tmp_path / "sub" / "mid.txt"), str(tmp_path / "sub" / "leaf.txt")]
    assert record["requirements"][2]["origin"] == f"{tmp_path / 'sub' / 'leaf.txt'}:1"
    assert record["complete"] is True


def test_requirement_file_that_includes_itself_is_an_error_and_terminates(tmp_path):
    (tmp_path / "a.txt").write_text("a==1\n-r b.txt\n")
    (tmp_path / "b.txt").write_text("b==2\n-r a.txt\n")
    record = parse_pip_command("pip install -r a.txt", cwd=tmp_path)
    assert names(record) == [("a", "1"), ("b", "2")]
    assert any("includes itself" in r for r in reasons(record, "errors"))
    assert record["complete"] is False


def test_missing_requirement_file_is_an_error(tmp_path):
    record = parse_pip_command("pip install -r nope.txt a==1", cwd=tmp_path)
    (error,) = record["errors"]
    assert "cannot read" in error["reason"]
    assert error["raw"] == "-r nope.txt"
    assert names(record) == [("a", "1")]
    assert record["files"] == []
    assert record["complete"] is False


def test_missing_nested_requirement_file_names_the_including_line(tmp_path):
    (tmp_path / "top.txt").write_text("a==1\n-r gone.txt\n")
    record = parse_pip_command("pip install -r top.txt", cwd=tmp_path)
    (error,) = record["errors"]
    assert error["origin"] == f"{tmp_path / 'top.txt'}:2"
    assert record["complete"] is False


def test_requirement_path_that_is_a_directory_is_an_error(tmp_path):
    (tmp_path / "reqs").mkdir()
    record = parse_pip_command("pip install -r reqs", cwd=tmp_path)
    assert any("cannot read" in r for r in reasons(record, "errors"))


def test_requirement_file_that_is_not_utf8_is_an_error(tmp_path):
    (tmp_path / "reqs.txt").write_bytes(b"a==1\n\xff\xfe\n")
    record = parse_pip_command("pip install -r reqs.txt", cwd=tmp_path)
    assert record["requirements"] == []
    assert any("not UTF-8" in r for r in reasons(record, "errors"))


def test_oversized_requirement_file_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr("backend.cavr.capture.MAX_REQUIREMENTS_FILE_BYTES", 8)
    (tmp_path / "reqs.txt").write_text("a==1\nb==2\n")
    record = parse_pip_command("pip install -r reqs.txt", cwd=tmp_path)
    assert record["requirements"] == []
    assert any("larger than" in r for r in reasons(record, "errors"))


def test_malformed_line_in_a_file_is_reported_with_its_line_number(tmp_path):
    reqs = tmp_path / "reqs.txt"
    reqs.write_text("a==1\nthis is not a requirement\nb==2\n")
    record = parse_pip_command("pip install -r reqs.txt", cwd=tmp_path)
    assert names(record) == [("a", "1"), ("b", "2")]
    (error,) = record["errors"]
    assert error["origin"] == f"{reqs}:2"
    assert error["raw"] == "this is not a requirement"
    assert record["complete"] is False


def test_unsupported_lines_inside_a_file(tmp_path):
    (tmp_path / "reqs.txt").write_text(
        "--index-url https://example.invalid/simple\n"
        "-e ./local\n"
        "git+https://example.invalid/x.git\n"
        "./wheels/x-1-py3-none-any.whl\n"
        "a==1\n")
    record = parse_pip_command("pip install -r reqs.txt", cwd=tmp_path)
    assert names(record) == [("a", "1")]
    assert len(record["unsupported"]) == 4
    assert record["complete"] is False


def test_line_continuation_and_bom(tmp_path):
    (tmp_path / "reqs.txt").write_bytes(b"\xef\xbb\xbfa==1 \\\n  --hash=" + SHA.encode() + b"\nb==2\n")
    record = parse_pip_command("pip install -r reqs.txt", cwd=tmp_path)
    assert names(record) == [("a", "1"), ("b", "2")]
    assert record["requirements"][0]["hashes"] == [SHA]
    assert record["requirements"][1]["origin"].endswith(":3")


def test_hash_options_are_recorded_and_bad_ones_are_errors(tmp_path):
    (tmp_path / "reqs.txt").write_text(f"a==1 --hash={SHA} --hash {SHA}\nb==2 --hash=md5:abc\n")
    record = parse_pip_command("pip install -r reqs.txt", cwd=tmp_path)
    assert record["requirements"][0]["hashes"] == [SHA, SHA]
    assert names(record) == [("a", "1")]
    assert any("hash" in r for r in reasons(record, "errors"))


def test_constraint_file_entries_are_kept_apart_from_requirements(tmp_path):
    (tmp_path / "cons.txt").write_text("b==2\nc==3\n")
    record = parse_pip_command("pip install a==1 -c cons.txt", cwd=tmp_path)
    assert names(record) == [("a", "1")]
    assert names(record, "constraints") == [("b", "2"), ("c", "3")]
    assert record["files"][0]["role"] == "constraints"
    assert record["complete"] is True


def test_constraint_included_from_a_requirement_file(tmp_path):
    (tmp_path / "reqs.txt").write_text("-c cons.txt\na==1\n")
    (tmp_path / "cons.txt").write_text("b==2\n")
    record = parse_pip_command("pip install -r reqs.txt", cwd=tmp_path)
    assert names(record) == [("a", "1")]
    assert names(record, "constraints") == [("b", "2")]


def test_files_nested_inside_a_constraint_file_stay_constraints(tmp_path):
    (tmp_path / "cons.txt").write_text("-r more.txt\n")
    (tmp_path / "more.txt").write_text("b==2\n")
    record = parse_pip_command("pip install a==1 -c cons.txt", cwd=tmp_path)
    assert names(record) == [("a", "1")]
    assert names(record, "constraints") == [("b", "2")]


def test_missing_constraint_file_is_an_error(tmp_path):
    record = parse_pip_command("pip install a==1 -c nope.txt", cwd=tmp_path)
    assert any("cannot read" in r for r in reasons(record, "errors"))
    assert record["complete"] is False


def test_conflict_between_command_line_and_file(tmp_path):
    (tmp_path / "reqs.txt").write_text("a==2\n")
    record = parse_pip_command("pip install a==1 -r reqs.txt", cwd=tmp_path)
    assert any("conflicting" in r for r in reasons(record, "errors"))


def test_same_name_with_different_markers_is_not_a_conflict(tmp_path):
    (tmp_path / "reqs.txt").write_text('a==1; python_version < "3.8"\na==2; python_version >= "3.8"\n')
    record = parse_pip_command("pip install -r reqs.txt", cwd=tmp_path)
    assert names(record) == [("a", "1"), ("a", "2")]
    assert record["errors"] == []


# --- parse_requirement -------------------------------------------------------

def test_parse_requirement_kinds():
    assert parse_requirement("a==1")["kind"] == "requirement"
    assert parse_requirement("git+https://example.invalid/a.git")["kind"] == "unsupported"
    assert parse_requirement("not a requirement")["kind"] == "error"
    assert parse_requirement("")["kind"] == "error"


def test_conflicting_pins_under_the_same_marker_are_an_error(tmp_path):
    (tmp_path / "reqs.txt").write_text('a==1; python_version >= "3"\na==2; python_version >= "3"\n')
    record = parse_pip_command("pip install -r reqs.txt", cwd=tmp_path)
    assert any("conflicting" in r for r in reasons(record, "errors"))
    assert record["complete"] is False
