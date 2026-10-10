"""C3 read wheel metadata safely (plan step 5). Every wheel here is a real zip file on disk."""
import warnings
import zipfile

import pytest

from backend.cavr import wheel_meta
from backend.cavr.wheel_meta import read_wheel
from test_cavr_support import PYPDF_WHEEL, build_wheel


def outcome(result):
    return result["result"], result["rule"]


def add_entry(wheel, name, data=b"x", mode=None):
    """Append one more entry to an existing wheel (duplicates allowed)."""
    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
    if mode is not None:
        info.external_attr = mode << 16
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(wheel, "a", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(info, data)
    return wheel


# --- the real pypdf wheel ----------------------------------------------------------------

def test_pypdf_wheel_metadata():
    result = read_wheel(PYPDF_WHEEL, "pypdf", "6.19.0")
    assert outcome(result) == ("OK", "METADATA_READ")
    assert (result["name"], result["metadata_name"], result["version"]) == ("pypdf", "pypdf", "6.19.0")
    assert result["requires_python"] == ">=3.9"
    assert result["dist_info"] == "pypdf-6.19.0.dist-info"
    assert result["entry_count"] == 64
    assert result["total_uncompressed"] == 1722604
    assert result["wheel_tags"] == ["py3-none-any"] and result["root_is_purelib"] is True
    # flit writes no top_level.txt, so the import names come from RECORD.
    assert result["import_names"] == ["pypdf"] and result["import_names_source"] == "RECORD"
    assert result["undeclared_import_names"] == []
    assert result["native_files"] == [] and result["pth_files"] == []
    assert len(result["requires_dist"]) == 23
    first = result["requires_dist"][0]
    assert first == {"raw": "typing_extensions >= 4.0; python_version < '3.11'", "name": "typing_extensions",
                     "canonical_name": "typing-extensions", "specifier": ">=4.0",
                     "marker": 'python_version < "3.11"', "extras": []}
    assert {entry["canonical_name"] for entry in result["requires_dist"]} >= {"cryptography", "pillow", "fonttools"}
    assert "crypto" in result["provides_extra"]


def test_pypdf_wheel_without_expectations_still_reads():
    result = read_wheel(PYPDF_WHEEL)
    assert outcome(result) == ("OK", "METADATA_READ") and result["name"] == "pypdf"


# --- name and version must be the ones asked for -------------------------------------------

@pytest.mark.parametrize("name, version", [("pypdf2", "6.19.0"), ("pypdf", "6.19.1"), ("requests", "2.0")])
def test_name_or_version_mismatch_is_rejected(name, version):
    result = read_wheel(PYPDF_WHEEL, name, version)
    assert outcome(result) == ("REJECTED", "METADATA_MISMATCH")
    assert result["metadata_name"] == "pypdf" and result["version"] == "6.19.0"


def test_expected_name_and_version_are_compared_canonically(tmp_path):
    wheel = build_wheel(tmp_path, "Foo_Bar", "1.0")
    assert outcome(read_wheel(wheel, "foo-bar", "1.0.0")) == ("OK", "METADATA_READ")
    assert outcome(read_wheel(wheel, "foo.BAR", "1")) == ("OK", "METADATA_READ")


def test_metadata_naming_another_package_than_its_dist_info_is_rejected(tmp_path):
    wheel = build_wheel(tmp_path, "demo", "1.0", metadata="Metadata-Version: 2.1\nName: requests\nVersion: 1.0\n")
    result = read_wheel(wheel)
    assert outcome(result) == ("REJECTED", "METADATA_MISMATCH")
    assert "dist-info" in result["reason"]


def test_metadata_version_differing_from_its_dist_info_is_rejected(tmp_path):
    wheel = build_wheel(tmp_path, "demo", "1.0", metadata="Metadata-Version: 2.1\nName: demo\nVersion: 2.0\n")
    assert outcome(read_wheel(wheel)) == ("REJECTED", "METADATA_MISMATCH")


def test_invalid_expected_version_is_unresolved(tmp_path):
    wheel = build_wheel(tmp_path, "demo", "1.0")
    assert outcome(read_wheel(wheel, "demo", "not a version")) == ("UNRESOLVED", "METADATA_INVALID")


# --- Requires-Dist ---------------------------------------------------------------------------

def test_requires_dist_is_read_with_markers_and_extras(tmp_path):
    wheel = build_wheel(tmp_path, "demo", "1.0", requires=[
        "Left_Pad==1.0", 'win-only>=2; sys_platform == "win32"', 'extra-dep; extra == "fast"', "multi[a,b]>=1,<2"])
    result = read_wheel(wheel, "demo", "1.0")
    assert outcome(result) == ("OK", "METADATA_READ")
    assert [(e["canonical_name"], e["specifier"], e["marker"], e["extras"]) for e in result["requires_dist"]] == [
        ("left-pad", "==1.0", None, []),
        ("win-only", ">=2", 'sys_platform == "win32"', []),
        ("extra-dep", "", 'extra == "fast"', []),
        ("multi", "<2,>=1", None, ["a", "b"]),
    ]


def test_wheel_without_dependencies(tmp_path):
    result = read_wheel(build_wheel(tmp_path, "demo", "1.0"))
    assert outcome(result) == ("OK", "METADATA_READ") and result["requires_dist"] == []
    assert result["requires_python"] is None


@pytest.mark.parametrize("line", ["not a requirement !!", "", "dep @ https://example.invalid/dep.whl", "dep==", "../dep"])
def test_unparseable_or_url_requires_dist_is_unresolved(tmp_path, line):
    wheel = build_wheel(tmp_path, "demo", "1.0", requires=[line])
    result = read_wheel(wheel)
    assert outcome(result) == ("UNRESOLVED", "METADATA_INVALID")
    assert result["requires_dist"] == []


# --- METADATA missing or unusable -> UNRESOLVED ---------------------------------------------------

def test_missing_metadata_is_unresolved(tmp_path):
    wheel = build_wheel(tmp_path, "demo", "1.0", metadata=False)
    assert outcome(read_wheel(wheel, "demo", "1.0")) == ("UNRESOLVED", "METADATA_MISSING")


def test_wheel_without_any_dist_info_is_unresolved(tmp_path):
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("demo/__init__.py", "")
    assert outcome(read_wheel(wheel)) == ("UNRESOLVED", "METADATA_MISSING")


def test_two_dist_info_directories_is_unresolved(tmp_path):
    wheel = build_wheel(tmp_path, "demo", "1.0")
    add_entry(wheel, "other-2.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: other\nVersion: 2.0\n")
    assert outcome(read_wheel(wheel, "demo", "1.0")) == ("UNRESOLVED", "DIST_INFO_AMBIGUOUS")


def test_nested_dist_info_is_not_the_wheels_metadata(tmp_path):
    files = {"demo/__init__.py": "", "demo/vendored-9.dist-info/METADATA": "Name: vendored\nVersion: 9\n"}
    result = read_wheel(build_wheel(tmp_path, "demo", "1.0", files=files), "demo", "1.0")
    assert outcome(result) == ("OK", "METADATA_READ") and result["dist_info"] == "demo-1.0.dist-info"


@pytest.mark.parametrize("metadata", [
    "Metadata-Version: 2.1\nVersion: 1.0\n",
    "Metadata-Version: 2.1\nName: demo\n",
    "Metadata-Version: 2.1\nName: demo\nName: other\nVersion: 1.0\n",
    "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\nVersion: 2.0\n",
    "Metadata-Version: 2.1\nName: demo\nVersion: not-a-version\n",
    "Metadata-Version: 2.1\nName: ../demo\nVersion: 1.0\n",
    "",
    b"Name: demo\nVersion: 1.0\nSummary: \xff\xfe\n",
])
def test_unusable_metadata_is_unresolved(tmp_path, metadata):
    assert outcome(read_wheel(build_wheel(tmp_path, "demo", "1.0", metadata=metadata))) == ("UNRESOLVED", "METADATA_INVALID")


def test_a_line_that_is_not_a_header_inside_the_header_block_is_unresolved(tmp_path):
    # The parser would stop at the second line and silently drop the dependency after it.
    metadata = "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\nthis is not a header\nRequires-Dist: hidden==1\n"
    result = read_wheel(build_wheel(tmp_path, "demo", "1.0", metadata=metadata), "demo", "1.0")
    assert outcome(result) == ("UNRESOLVED", "METADATA_INVALID")
    assert "MissingHeaderBodySeparatorDefect" in result["reason"] and result["requires_dist"] == []


def test_malformed_wheel_file_is_unresolved(tmp_path):
    wheel = build_wheel(tmp_path, "demo", "1.0")
    broken = tmp_path / "broken" / wheel.name
    broken.parent.mkdir()
    with zipfile.ZipFile(wheel) as source, zipfile.ZipFile(broken, "w") as target:
        for info in source.infolist():
            data = source.read(info)
            target.writestr(info, b"Wheel-Version: 1.0\nnot a header\nTag: py3-none-any\n" if info.filename.endswith("/WHEEL") else data)
    assert outcome(read_wheel(broken, "demo", "1.0")) == ("UNRESOLVED", "NOT_A_WHEEL")


def test_requires_dist_after_the_header_block_is_not_a_dependency(tmp_path):
    # Core metadata ends at the first blank line; the rest is the description.
    metadata = "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n\nRequires-Dist: sneaky==1\n"
    result = read_wheel(build_wheel(tmp_path, "demo", "1.0", metadata=metadata))
    assert outcome(result) == ("OK", "METADATA_READ") and result["requires_dist"] == []


def test_missing_wheel_file_is_unresolved(tmp_path):
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("demo/__init__.py", "")
        archive.writestr("demo-1.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n")
    assert outcome(read_wheel(wheel)) == ("UNRESOLVED", "NOT_A_WHEEL")


# --- not a readable zip -> UNRESOLVED ---------------------------------------------------------

def test_file_that_is_not_a_zip_is_unresolved(tmp_path):
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    wheel.write_bytes(b"this is not a zip file")
    assert outcome(read_wheel(wheel)) == ("UNRESOLVED", "NOT_A_WHEEL")


def test_missing_file_and_directory_are_unresolved(tmp_path):
    assert outcome(read_wheel(tmp_path / "nothing.whl")) == ("UNRESOLVED", "NOT_A_WHEEL")
    assert outcome(read_wheel(tmp_path)) == ("UNRESOLVED", "NOT_A_WHEEL")
    assert outcome(read_wheel(None)) == ("UNRESOLVED", "NOT_A_WHEEL")


def test_truncated_wheel_is_unresolved(tmp_path):
    wheel = build_wheel(tmp_path, "demo", "1.0")
    wheel.write_bytes(wheel.read_bytes()[:-30])
    assert outcome(read_wheel(wheel)) == ("UNRESOLVED", "NOT_A_WHEEL")


def test_corrupted_metadata_bytes_are_unresolved(tmp_path):
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    body = b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n"
    with zipfile.ZipFile(wheel, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("demo-1.0.dist-info/METADATA", body)
        archive.writestr("demo-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
    data = wheel.read_bytes()
    wheel.write_bytes(data.replace(b"Name: demo", b"Name: dem0", 1))  # stored, so the CRC no longer fits
    assert outcome(read_wheel(wheel)) == ("UNRESOLVED", "NOT_A_WHEEL")


# --- zip budget -> UNRESOLVED -----------------------------------------------------------------

def test_zip_bomb_is_stopped_by_the_compression_ratio(tmp_path):
    bomb = b"\0" * (30 * 1024 * 1024)
    wheel = build_wheel(tmp_path, "demo", "1.0", files={"demo/__init__.py": "", "demo/blob.bin": bomb}, record=False)
    assert wheel.stat().st_size < 100 * 1024
    result = read_wheel(wheel, "demo", "1.0")
    assert outcome(result) == ("UNRESOLVED", "ZIP_BUDGET")
    assert "ratio" in result["reason"]
    assert result["name"] is None


def test_total_uncompressed_size_budget(tmp_path, monkeypatch):
    wheel = build_wheel(tmp_path, "demo", "1.0", files={"demo/__init__.py": "x = 1\n" * 500})
    monkeypatch.setattr(wheel_meta, "MAX_TOTAL_UNCOMPRESSED", 1000)
    result = read_wheel(wheel)
    assert outcome(result) == ("UNRESOLVED", "ZIP_BUDGET") and "uncompressed" in result["reason"]


def test_entry_count_budget(tmp_path, monkeypatch):
    wheel = build_wheel(tmp_path, "demo", "1.0", files={f"demo/m{i}.py": "" for i in range(10)})
    monkeypatch.setattr(wheel_meta, "MAX_ENTRIES", 5)
    result = read_wheel(wheel)
    assert outcome(result) == ("UNRESOLVED", "ZIP_BUDGET") and "entries" in result["reason"]


def test_oversized_metadata_member_budget(tmp_path, monkeypatch):
    wheel = build_wheel(tmp_path, "demo", "1.0")
    monkeypatch.setattr(wheel_meta, "MAX_MEMBER_BYTES", 10)
    result = read_wheel(wheel)
    assert outcome(result) == ("UNRESOLVED", "ZIP_BUDGET") and "METADATA" in result["reason"]


def test_small_highly_compressible_wheel_is_not_a_bomb(tmp_path):
    # The ratio only counts once the archive is larger than the floor.
    wheel = build_wheel(tmp_path, "demo", "1.0", files={"demo/__init__.py": "\n" * 200_000})
    assert outcome(read_wheel(wheel)) == ("OK", "METADATA_READ")


# --- path checks -> REJECTED --------------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "../evil.py",
    "demo/../../evil.py",
    "/etc/cron.d/evil",
    "C:/Windows/evil.dll",
    "demo\\..\\evil.py",
    "demo/./x.py",
    "demo//x.py",
])
def test_entry_that_escapes_the_install_directory_is_rejected(tmp_path, name):
    wheel = add_entry(build_wheel(tmp_path, "demo", "1.0"), name)
    result = read_wheel(wheel, "demo", "1.0")
    assert outcome(result) == ("REJECTED", "UNSAFE_PATH")
    assert result["name"] is None


def test_symlink_entry_is_rejected(tmp_path):
    wheel = add_entry(build_wheel(tmp_path, "demo", "1.0"), "demo/link.py", b"/etc/passwd", mode=0o120777)
    assert outcome(read_wheel(wheel)) == ("REJECTED", "UNSAFE_PATH")


def test_duplicate_entry_is_unresolved(tmp_path):
    wheel = add_entry(build_wheel(tmp_path, "demo", "1.0"), "demo/__init__.py", b"import os\n")
    assert outcome(read_wheel(wheel)) == ("UNRESOLVED", "DUPLICATE_ENTRY")


def test_entries_differing_only_in_case_are_unresolved(tmp_path):
    wheel = add_entry(build_wheel(tmp_path, "demo", "1.0"), "demo/__INIT__.py", b"import os\n")
    assert outcome(read_wheel(wheel)) == ("UNRESOLVED", "DUPLICATE_ENTRY")


def test_directory_entries_are_allowed(tmp_path):
    wheel = add_entry(build_wheel(tmp_path, "demo", "1.0"), "demo/sub/", b"")
    assert outcome(read_wheel(wheel)) == ("OK", "METADATA_READ")


# --- import names, native files --------------------------------------------------------------------

def test_import_names_from_top_level_txt(tmp_path):
    # The distribution is called python-dateutil-like: its name is not its import name.
    files = {"dateutil/__init__.py": "", "dateutil/parser.py": "", "_dateutil_speedups.py": ""}
    wheel = build_wheel(tmp_path, "python-dateutil", "2.9", files=files, top_level="dateutil\n_dateutil_speedups\n")
    result = read_wheel(wheel, "python-dateutil", "2.9")
    assert result["import_names"] == ["_dateutil_speedups", "dateutil"]
    assert result["import_names_source"] == "top_level.txt"
    assert result["undeclared_import_names"] == []


def test_import_names_from_record_when_there_is_no_top_level_txt(tmp_path):
    files = {"yaml/__init__.py": "", "_yaml/__init__.py": "", "six.py": "", "fast.cpython-312-x86_64-linux-gnu.so": b"\x7fELF"}
    result = read_wheel(build_wheel(tmp_path, "PyYAML", "6.0", files=files), "pyyaml", "6.0")
    assert result["import_names"] == ["_yaml", "fast", "six", "yaml"]
    assert result["import_names_source"] == "RECORD"


def test_import_names_from_the_archive_when_there_is_neither(tmp_path):
    result = read_wheel(build_wheel(tmp_path, "demo", "1.0", files={"pkg/__init__.py": "", "mod.py": ""}, record=False))
    assert result["import_names"] == ["mod", "pkg"]
    assert result["import_names_source"] == "archive"


def test_data_directory_purelib_counts_and_scripts_do_not(tmp_path):
    files = {"demo-1.0.data/purelib/hidden/__init__.py": "", "demo-1.0.data/scripts/run-demo": "#!python\n",
             "demo-1.0.data/platlib/speed.pyd": b"MZ", "README.txt": "", "demo/__init__.py": ""}
    result = read_wheel(build_wheel(tmp_path, "demo", "1.0", files=files, record=False))
    assert result["import_names"] == ["demo", "hidden", "speed"]


def test_importable_code_missing_from_top_level_txt_is_reported(tmp_path):
    files = {"demo/__init__.py": "", "requests/__init__.py": "import os\n"}
    result = read_wheel(build_wheel(tmp_path, "demo", "1.0", files=files, top_level="demo\n"))
    assert outcome(result) == ("OK", "METADATA_READ")
    assert result["import_names"] == ["demo"]
    assert result["undeclared_import_names"] == ["requests"]


def test_native_and_pth_files_are_listed(tmp_path):
    files = {"demo/__init__.py": "", "demo/_speed.cpython-312-x86_64-linux-gnu.so": b"\x7fELF", "demo/win.pyd": b"MZ",
             "demo/libs/libz.so.1": b"\x7fELF", "demo/lib.dll": b"MZ", "demo/mac.dylib": b"\xcf\xfa", "demo-hook.pth": "import os\n",
             "demo/notes.so.txt": "not native"}
    result = read_wheel(build_wheel(tmp_path, "demo", "1.0", files=files))
    assert result["native_files"] == ["demo/_speed.cpython-312-x86_64-linux-gnu.so", "demo/lib.dll", "demo/libs/libz.so.1",
                                      "demo/mac.dylib", "demo/win.pyd"]
    assert result["pth_files"] == ["demo-hook.pth"]


def test_every_result_has_the_same_keys(tmp_path):
    good = read_wheel(PYPDF_WHEEL)
    bad = read_wheel(tmp_path / "nothing.whl")
    mismatch = read_wheel(PYPDF_WHEEL, "other", "1")
    assert set(good) == set(bad) == set(mismatch)
    assert good["path"] == str(PYPDF_WHEEL)
