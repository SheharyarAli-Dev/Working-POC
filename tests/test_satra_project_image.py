"""Per-project SATRA gate images: install plan (step 2), build/reuse (step 3).

Lockfile entries are real PyPI files: name, version, filename and sha256 were taken from
pypi.org (the Flask entries from the asent-target-flask lockfile, which CAVR wrote from PyPI).
The install plan reads only the base commit directory and the frozen base `.asent/` config.
"""
import hashlib
import json
from pathlib import Path

import pytest
from packaging import tags

from backend.project_config.loader import load
from backend.satra import project_image
from backend.satra.project_image import install_plan

FLASK = [
    {"name": "Flask", "version": "3.1.3", "ecosystem": "PyPI", "sha256": "f4bcbefc124291925f1a26446da31a5178f9483862233b23c0c96a20701f670c", "filename": "flask-3.1.3-py3-none-any.whl"},
    {"name": "Werkzeug", "version": "3.1.9", "ecosystem": "PyPI", "sha256": "6392e50c78460ba618e5b21f08a71f59c99ce99cdc6cf6e3dd7e6ccca8754fab", "filename": "werkzeug-3.1.9-py3-none-any.whl"},
    {"name": "Jinja2", "version": "3.1.6", "ecosystem": "PyPI", "sha256": "85ece4451f492d0c13c5dd7c13a64681a86afae63a5f347908daf103ce6d2f67", "filename": "jinja2-3.1.6-py3-none-any.whl"},
    {"name": "MarkupSafe", "version": "3.0.4", "ecosystem": "PyPI", "sha256": "8e124f974786f831d6043728e38296969d3579db8896fe004682f5758e613581", "filename": "markupsafe-3.0.4-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl"},
    {"name": "MarkupSafe", "version": "3.0.4", "ecosystem": "PyPI", "sha256": "a8e9f292fcda89b324f2f5c91d13f1424a153e40fc2756f38ee23b15835ff300", "filename": "markupsafe-3.0.4-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl"},
    {"name": "itsdangerous", "version": "2.2.0", "ecosystem": "PyPI", "sha256": "c6242fc49e35958c8b15141343aa660db5fc54d4f13a1db01a3f5891b98700ef", "filename": "itsdangerous-2.2.0-py3-none-any.whl"},
    {"name": "click", "version": "8.5.1", "ecosystem": "PyPI", "sha256": "8bb5376d2006950386f8c6427613334a2acadc5f559cb80e638d00b4df957e37", "filename": "click-8.5.1-py3-none-any.whl"},
    {"name": "blinker", "version": "1.9.0", "ecosystem": "PyPI", "sha256": "ba0efaa9080b619ff2f3459d1d500c57bddea4a6b424b60a91141db6fd2f08bc", "filename": "blinker-1.9.0-py3-none-any.whl"},
]
APPROVED = ["Flask==3.1.3", "Werkzeug==3.1.9", "Jinja2==3.1.6", "MarkupSafe==3.0.4", "itsdangerous==2.2.0", "click==8.5.1", "blinker==1.9.0"]
PACKAGING_26_3 = {"name": "packaging", "version": "26.3", "ecosystem": "PyPI", "sha256": "d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c", "filename": "packaging-26.3-py3-none-any.whl"}
PACKAGING_25_0 = {"name": "packaging", "version": "25.0", "ecosystem": "PyPI", "sha256": "29572ef2b1f17581046b3a2227d5c611fb25ec70ca1ba8554b24b0e69331a484", "filename": "packaging-25.0-py3-none-any.whl"}
PYTEST_8_4_2 = {"name": "pytest", "version": "8.4.2", "ecosystem": "PyPI", "sha256": "872f880de3fc3a5bdc88a11b39c9710c3497a547cfa9320bc3c5e62fbf272e79", "filename": "pytest-8.4.2-py3-none-any.whl"}
# The real sha256 of packaging-26.3.tar.gz: real bytes, but not the runner's wheel.
PACKAGING_26_3_SDIST_SHA = "94edc256424af38762eb31306eed28beb9f0efc50a8837492c9d6fd6004aed79"
NUMPY_CP314_ONLY = {"name": "numpy", "version": "2.5.4", "ecosystem": "PyPI", "sha256": "d549420b8858885cea8838a727842249218b9c1da24dd517e25c9c7a948310a3", "filename": "numpy-2.5.4-cp314-cp314-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl"}
CRYPTOGRAPHY_ABI3 = {"name": "cryptography", "version": "50.0.2", "ecosystem": "PyPI", "sha256": "9dab55f57c74c3cad24c323bacbbd04be4705ba6eb0d92e920b1fc4837ed5079", "filename": "cryptography-50.0.2-cp311-abi3-manylinux_2_34_x86_64.whl"}

_PLATFORMS = [f"manylinux_2_{minor}_x86_64" for minor in range(36, 4, -1)] + ["manylinux2014_x86_64", "linux_x86_64"]
# What `packaging.tags.sys_tags()` reports for CPython 3.12 on glibc 2.36 x86_64 (Debian bookworm).
CP312_LINUX = frozenset(str(t) for t in [*tags.cpython_tags((3, 12), ["cp312"], _PLATFORMS),
                                         *tags.compatible_tags((3, 12), "cp312", _PLATFORMS)])


def policy(approved=None, denied=None):
    return {"project_task_description": "Flask web service", "allowed_scopes": ["NETWORK_CONNECT:none", "PROCESS_EXEC:none"],
            "approved_requirements": list(APPROVED if approved is None else approved), "denied_packages": denied or []}


def base(tmp_path, requirements="Flask==3.1.3\n", lock=None, pol=None, cavr=None, extra=None, raw_lock=None):
    root = tmp_path / "base"
    files = {"requirements.txt": requirements,
             ".asent/config.json": json.dumps({"schema_version": 1, "project": {"name": "t"}, "modules": {
                 "CAVR": cavr or {"enabled": True}, "SATRA": {"enabled": False, "reason": "not in this test"},
                 "SABLE": {"enabled": False, "reason": "not in this test"}}}),
             ".asent/cavr/policy.json": json.dumps(pol or policy())}
    if raw_lock is not None:
        files["dependencies.lock.json"] = raw_lock
    elif lock is not False:
        files["dependencies.lock.json"] = json.dumps({"packages": FLASK if lock is None else lock}, indent=2)
    files.update(extra or {})
    for name, text in files.items():
        if text is None:
            continue
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    config = load(root / ".asent")
    assert config.valid, config.problems
    return root, config


def plan(tmp_path, supported=CP312_LINUX, **kwargs):
    root, config = base(tmp_path, **kwargs)
    return install_plan(root, config, supported_tags=supported)


def inconclusive(result, *words):
    assert result["status"] == "INCONCLUSIVE", result
    assert result["requirements_text"] is None
    for word in words:
        assert word in result["reason"], (word, result["reason"])


# --- step 2: install plan -------------------------------------------------------------------------

def test_plan_installs_every_approved_lock_entry_with_all_its_hashes(tmp_path):
    result = plan(tmp_path)
    assert result["status"] == "READY", result["reason"]
    lines = result["requirements_text"].splitlines()
    assert lines == sorted(lines) and len(lines) == 7
    assert ("markupsafe==3.0.4 --hash=sha256:8e124f974786f831d6043728e38296969d3579db8896fe004682f5758e613581"
            " --hash=sha256:a8e9f292fcda89b324f2f5c91d13f1424a153e40fc2756f38ee23b15835ff300") in lines
    assert "flask==3.1.3 --hash=sha256:f4bcbefc124291925f1a26446da31a5178f9483862233b23c0c96a20701f670c" in lines
    lock_bytes = (tmp_path / "base/dependencies.lock.json").read_bytes()
    assert result["lockfile_sha256"] == hashlib.sha256(lock_bytes).hexdigest()
    assert all(d["result"] == "PERMITTED" for d in result["decisions"]) and len(result["decisions"]) == 8


def test_plan_is_deterministic_and_ignores_lock_order(tmp_path):
    first = plan(tmp_path / "a")
    second = plan(tmp_path / "b", lock=list(reversed(FLASK)))
    assert first["requirements_text"] == second["requirements_text"]
    assert first["lockfile_sha256"] != second["lockfile_sha256"]  # the digest is of the real bytes


def test_missing_lockfile_is_inconclusive(tmp_path):
    inconclusive(plan(tmp_path, lock=False), "no dependencies.lock.json")


def test_requirements_with_an_empty_lockfile_is_inconclusive(tmp_path):
    inconclusive(plan(tmp_path, lock=[]), "flask", "NOT_IN_LOCKFILE")


def test_no_requirements_and_an_empty_lockfile_install_nothing(tmp_path):
    result = plan(tmp_path, requirements="# no third-party dependencies\n", lock=[])
    assert result["status"] == "READY", result["reason"]
    assert result["requirements_text"] == "" and result["packages"] == []


def test_unreadable_lockfile_is_inconclusive(tmp_path):
    inconclusive(plan(tmp_path, raw_lock="{not json"), "dependencies.lock.json")
    inconclusive(plan(tmp_path / "x", raw_lock=json.dumps({"lock_version": 1})), "dependencies.lock.json")


def test_transitive_entry_not_on_the_allowlist_is_inconclusive(tmp_path):
    result = plan(tmp_path, pol=policy([a for a in APPROVED if not a.startswith("Jinja2")]))
    inconclusive(result, "jinja2", "NOT_ON_ALLOWLIST")


def test_denied_lock_entry_is_inconclusive(tmp_path):
    result = plan(tmp_path, pol=policy(denied=[{"name": "blinker", "reason": "test"}]))
    inconclusive(result, "blinker", "DENYLIST")


@pytest.mark.parametrize("requirements, words", [
    ("Flask>=3\n", ("NOT_PINNED",)),
    ("Flask==3.1.3\nrequests==2.34.2\n", ("requests", "NOT_ON_ALLOWLIST")),
    ("--index-url https://example.invalid/simple\nFlask==3.1.3\n", ("requirements.txt", "option")),
    ("-e .\n", ("requirements.txt",)),
    ("./local-package\n", ("requirements.txt",)),
])
def test_requirements_file_must_be_fully_permitted(tmp_path, requirements, words):
    inconclusive(plan(tmp_path, requirements=requirements), *words)


def test_requirement_missing_from_the_lockfile_is_inconclusive(tmp_path):
    result = plan(tmp_path, requirements="Flask==3.1.3\nsix==1.17.0\n", pol=policy(APPROVED + ["six==1.17.0"]))
    inconclusive(result, "six", "NOT_IN_LOCKFILE")


def test_cavr_disabled_means_nothing_is_approved(tmp_path):
    inconclusive(plan(tmp_path, cavr={"enabled": False, "reason": "off"}), "CAVR")


def test_configured_requirements_file_missing_in_base_is_inconclusive(tmp_path):
    inconclusive(plan(tmp_path, requirements=None), "requirements.txt")


@pytest.mark.parametrize("name, text", [
    ("pyproject.toml", '[project]\nname = "x"\ndependencies = ["requests==2.34.2"]\n'),
    ("Pipfile", "[packages]\nrequests = '*'\n"),
])
def test_dependency_manifest_cavr_cannot_read_is_inconclusive(tmp_path, name, text):
    inconclusive(plan(tmp_path, extra={name: text}), name)


@pytest.mark.parametrize("field, value, words", [
    ("ecosystem", "LOCAL", ("not a PyPI",)),
    ("sha256", "F4BCBEFC124291925F1A26446DA31A5178F9483862233B23C0C96A20701F670C", ("sha256",)),
    ("sha256", "f4bcbefc", ("sha256",)),
    ("sha256", None, ("sha256",)),
    ("name", "flask\n--index-url http://example.invalid", ("name",)),
    ("version", "3.1.3 --hash=sha256:00", ("version",)),
    ("filename", "flask-3.1.3.tar.gz", ("wheel",)),
    ("filename", None, ("wheel",)),
    ("filename", "werkzeug-3.1.9-py3-none-any.whl", ("does not match",)),
])
def test_malformed_lock_entry_is_inconclusive(tmp_path, field, value, words):
    flask = {**FLASK[0], field: value}
    if value is None:
        del flask[field]
    inconclusive(plan(tmp_path, lock=[flask, *FLASK[1:]]), *words)


def test_artifact_path_names_the_wheel_when_filename_is_absent(tmp_path):
    flask = {k: v for k, v in FLASK[0].items() if k != "filename"}
    flask["artifact"] = "artifacts/flask-3.1.3-py3-none-any.whl"
    assert plan(tmp_path, lock=[flask, *FLASK[1:]])["status"] == "READY"


def test_two_versions_of_one_package_are_inconclusive(tmp_path):
    other = {**FLASK[7], "version": "1.8.2", "filename": "blinker-1.8.2-py3-none-any.whl",  # real PyPI wheel sha256
             "sha256": "1779309f71bf239144b9399d06ae925637cf6634cf6bd131104184531bf67c01"}
    inconclusive(plan(tmp_path, lock=[*FLASK, other], pol=policy(APPROVED + ["blinker==1.8.2"])), "blinker", "two versions")


def test_runner_package_at_the_same_version_and_bytes_comes_from_the_runner(tmp_path):
    result = plan(tmp_path, lock=[*FLASK, PACKAGING_26_3], pol=policy(APPROVED + ["packaging==26.3"]))
    assert result["status"] == "READY", result["reason"]
    assert "packaging" not in result["requirements_text"]
    assert result["provided_by_runner"] == [{"name": "packaging", "version": "26.3"}]


@pytest.mark.parametrize("entry, approved, words", [
    (PACKAGING_25_0, "packaging==25.0", ("packaging", "25.0", "26.3")),
    (PYTEST_8_4_2, "pytest==8.4.2", ("pytest", "8.4.2", "9.1.1")),
    ({**PACKAGING_26_3, "sha256": PACKAGING_26_3_SDIST_SHA}, "packaging==26.3", ("packaging", "different file")),
])
def test_runner_package_clash_is_inconclusive(tmp_path, entry, approved, words):
    inconclusive(plan(tmp_path, lock=[*FLASK, entry], pol=policy(APPROVED + [approved])), *words)


def test_package_without_a_compatible_wheel_is_inconclusive(tmp_path):
    result = plan(tmp_path, lock=[*FLASK, NUMPY_CP314_ONLY], pol=policy(APPROVED + ["numpy==2.5.4"]))
    inconclusive(result, "numpy", "no wheel")


def test_stable_abi_wheel_is_compatible(tmp_path):
    result = plan(tmp_path, lock=[*FLASK, CRYPTOGRAPHY_ABI3], pol=policy(APPROVED + ["cryptography==50.0.2"]))
    assert result["status"] == "READY", result["reason"]


def test_without_runner_tags_no_plan_is_ready(tmp_path):
    inconclusive(plan(tmp_path, supported=frozenset()), "tags")


def test_plan_reads_only_the_directory_it_is_given(tmp_path):
    root, config = base(tmp_path)
    head = tmp_path / "head"
    (head / ".asent").mkdir(parents=True)
    (head / "dependencies.lock.json").write_text(json.dumps({"packages": [*FLASK, CRYPTOGRAPHY_ABI3]}))
    result = install_plan(root, config, supported_tags=CP312_LINUX)
    assert "cryptography" not in result["requirements_text"]
