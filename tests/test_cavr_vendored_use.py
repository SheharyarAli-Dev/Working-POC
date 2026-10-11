"""Call-site authority of the older orchestrator contract when pypdf is used through a vendored LOCAL artifact.

`capability_contract.infer` gets its call sites from `ContextService.dependency_context`, which reads
`app/*.py` only. `use_through_local_artifacts` adds the pypdf call sites of a LOCAL lock artifact
that the application imports and calls. Every project here is real files (the InvoiceHub scenarios of
the orchestrator, or a tmp directory); hashes are computed from the files; nothing is imported or run.
"""
import hashlib
import json

import pytest

from backend.cavr.capability_contract import infer, use_through_local_artifacts
from backend.orchestrator.context_service import ContextService
from backend.orchestrator.scenarios import replace_lab

SRS = "FR-02 The service extracts invoice text from an uploaded PDF locally.\n"
VENDORED = '''from io import BytesIO
from pypdf import PdfReader, apply_configuration


def extract(content):
    with apply_configuration(jbig2dec_binary=None):
        return [page.extract_text() for page in PdfReader(BytesIO(content)).pages]
'''
ADAPTER = "from vendor.safe import extract\n"
MAIN = "from .pdf_adapter import extract\n\n\ndef upload(content):\n    return extract(content)\n"
PYPDF = {"name": "pypdf", "version": "6.19.0", "ecosystem": "PyPI", "artifact": "artifacts/pypdf-6.19.0-py3-none-any.whl",
         "sha256": "7e5d6e730e7dae87d560a2cee218b852f6498c8be61966f3cd02ead971e48d14"}
CHAIN = {"SRS.md": SRS, "vendor/__init__.py": "", "vendor/safe.py": VENDORED, "app/pdf_adapter.py": ADAPTER, "app/main.py": MAIN}


def local_package(files, artifact="vendor/safe.py", **changes):
    """The lock entry of a vendored file, with the SHA-256 of the bytes that are really in `files`."""
    return {"name": "invoice-pdf-safe", "version": "1.0.0", "ecosystem": "LOCAL", "artifact": artifact,
            "sha256": hashlib.sha256(files.get(artifact, "").encode()).hexdigest(), **changes}


def context_for(tmp_path, files, packages=None):
    root = tmp_path / "project"
    lock = {"packages": [PYPDF, local_package(files)] if packages is None else packages, "edges": []}
    for path, text in {**files, "dependencies.lock.json": json.dumps(lock)}.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    return ContextService(root, root)


def chain_of(record):
    through = record["through"]
    return (through["artifact"], (through["imported_at"]["file"], through["imported_at"]["line"]),
            (through["called_at"]["file"], through["called_at"]["line"]),
            (record["call_site"]["file"], record["call_site"]["line"], record["imported_name"]))


# --- the orchestrator's own scenarios (demo_project/InvoiceHub + scenarios/cavr_controlled) -------------

def test_cross_module_scenario_reaches_pypdf_through_the_vendored_lab_file(scenario):
    run, context = scenario("cross_module")
    assert not [a for a in context.dependency_context()["dependency_attributions"] if a["package"] == "pypdf"]
    found = use_through_local_artifacts(context)
    assert [chain_of(r) for r in found] == [
        ("vendor/invoice_pdf_lab.py", ("app/pdf_adapter.py", 1), ("app/main.py", 87), ("vendor/invoice_pdf_lab.py", 10, "apply_configuration")),
        ("vendor/invoice_pdf_lab.py", ("app/pdf_adapter.py", 1), ("app/main.py", 87), ("vendor/invoice_pdf_lab.py", 11, "PdfReader"))]
    assert {(r["package"], r["version"], r["purpose"], r["through"]["local_package"]) for r in found} == {
        ("pypdf", "6.19.0", "PDF text extraction", "invoice-pdf-lab")}
    assert found[0]["through"]["sha256"] == hashlib.sha256((context.path / "vendor/invoice_pdf_lab.py").read_bytes()).hexdigest()
    for name in ("pypdf", "invoice-pdf-lab"):
        contract = infer(context, {"name": name})
        assert contract["confidence"] == "rule-grounded" and contract["local_artifact_use"] == found
        # A contract is not a verdict: the lab file is still rejected by what the sandbox observes.
        assert {"SECRET_ACCESS", "NETWORK_CONNECT"} <= set(contract["denied"])


def test_repaired_cross_module_scenario_reaches_pypdf_through_the_safe_file(scenario, service):
    run, context = scenario("cross_module")
    replace_lab(run.candidate_workspace)
    repaired = ContextService(run.candidate_workspace, run.baseline_workspace, service.threats.snapshot())
    found = use_through_local_artifacts(repaired)
    assert {r["through"]["artifact"] for r in found} == {"vendor/invoice_pdf_safe.py"}
    assert sorted(r["imported_name"] for r in found) == ["PdfReader", "apply_configuration"]
    assert infer(repaired, {"name": "invoice-pdf-safe"})["confidence"] == "rule-grounded"


def test_safe_scenario_has_no_local_artifact_and_keeps_its_direct_call_sites(scenario):
    run, context = scenario("safe")
    contract = infer(context, {"name": "pypdf"})
    assert use_through_local_artifacts(context) == [] and contract["local_artifact_use"] == []
    assert contract["confidence"] == "rule-grounded"


# --- the chain, link by link ---------------------------------------------------------------------------

def test_reexported_name_called_in_another_app_file(tmp_path):
    found = use_through_local_artifacts(context_for(tmp_path, CHAIN))
    assert [chain_of(r) for r in found] == [
        ("vendor/safe.py", ("app/pdf_adapter.py", 1), ("app/main.py", 5), ("vendor/safe.py", 6, "apply_configuration")),
        ("vendor/safe.py", ("app/pdf_adapter.py", 1), ("app/main.py", 5), ("vendor/safe.py", 7, "PdfReader"))]
    assert infer(context_for(tmp_path, CHAIN), {"name": "pypdf"})["confidence"] == "rule-grounded"


@pytest.mark.parametrize("adapter, called_at", [
    ("from vendor.safe import extract\n\n\ndef upload(content):\n    return extract(content)\n", 5),
    ("from vendor.safe import extract as read_pdf\n\nTEXT = read_pdf(b'')\n", 3),
    ("import vendor.safe\n\n\ndef upload(content):\n    return vendor.safe.extract(content)\n", 5),
    ("import vendor.safe as pdf\n\n\ndef upload(content):\n    return pdf.extract(content)\n", 5),
])
def test_name_called_in_the_file_that_imports_it(tmp_path, adapter, called_at):
    files = {**CHAIN, "app/pdf_adapter.py": adapter, "app/main.py": "VERSION = 1\n"}
    found = use_through_local_artifacts(context_for(tmp_path, files))
    assert [r["through"]["called_at"] for r in found] == [{"file": "app/pdf_adapter.py", "line": called_at}] * 2


def test_renamed_reexport_is_followed_by_the_name_the_adapter_binds(tmp_path):
    files = {**CHAIN, "app/pdf_adapter.py": "from vendor.safe import extract as read_pdf\n",
             "app/main.py": "from .pdf_adapter import read_pdf as text_of\n\nTEXT = text_of(b'')\n"}
    assert [r["through"]["called_at"] for r in use_through_local_artifacts(context_for(tmp_path, files))] == [
        {"file": "app/main.py", "line": 3}] * 2


@pytest.mark.parametrize("changed", [
    {"app/main.py": "from .pdf_adapter import extract\n"},                                  # imported, never called
    {"app/main.py": "from .pdf_adapter import extract\n\nHANDLER = extract\n"},             # named, never called
    {"app/main.py": "from .other import extract\n\nTEXT = extract(b'')\n", "app/other.py": "def extract(content):\n    return ''\n"},
    {"app/main.py": "from .pdf_adapter import other\n\nTEXT = other(b'')\n"},               # a different name of the adapter
    {"app/main.py": "def extract(content):\n    return ''\n\n\nTEXT = extract(b'')\n"},      # a local function of the same name
    {"app/pdf_adapter.py": "VERSION = 1\n"},                                                # the app never imports the artifact
    {"app/pdf_adapter.py": "from vendor.other import extract\n", "vendor/other.py": VENDORED},  # imports a file that is not the artifact
    {"vendor/safe.py": "def extract(content):\n    return []\n"},                           # the artifact never calls pypdf
    {"vendor/safe.py": "from pypdf import PdfReader\n\n\ndef extract(content):\n    return []\n"},  # imports pypdf, never calls it
    {"vendor/safe.py": "def extract(content):\n    return []\n", "tools/convert.py": VENDORED},  # pypdf is called, but not by the artifact
])
def test_a_missing_link_gives_no_authority(tmp_path, changed):
    files = {**CHAIN, **changed}
    context = context_for(tmp_path, files)
    assert use_through_local_artifacts(context) == []
    contract = infer(context, {"name": "pypdf"})
    assert contract["confidence"] == "insufficient" and contract["required"] == [] and contract["local_artifact_use"] == []


def test_a_call_outside_app_is_not_the_applications_call(tmp_path):
    files = {**CHAIN, "app/main.py": "VERSION = 1\n",
             "tests/test_pdf.py": "from vendor.safe import extract\n\n\ndef test_pdf():\n    assert extract(b'') == []\n"}
    assert use_through_local_artifacts(context_for(tmp_path, files)) == []


def test_the_recorded_import_is_the_applications_not_another_directorys(tmp_path):
    files = {**CHAIN, "admin/tool.py": "from vendor.safe import extract\n\nTEXT = extract(b'')\n"}
    found = use_through_local_artifacts(context_for(tmp_path, files))
    assert {(r["through"]["imported_at"]["file"], r["through"]["called_at"]["file"]) for r in found} == {("app/pdf_adapter.py", "app/main.py")}


def test_artifact_whose_bytes_are_not_the_locked_ones_gives_no_authority(tmp_path):
    stale = local_package({"vendor/safe.py": VENDORED + "\n# edited after the lock was written\n"})
    assert use_through_local_artifacts(context_for(tmp_path, CHAIN, [PYPDF, stale])) == []
    assert use_through_local_artifacts(context_for(tmp_path / "ok", CHAIN, [PYPDF, local_package(CHAIN)])) != []


@pytest.mark.parametrize("packages", [
    lambda files: [local_package(files)],                                    # the lock does not pin pypdf
    lambda files: [PYPDF],                                                   # no LOCAL artifact
    lambda files: [PYPDF, local_package(files, ecosystem="PyPI")],           # a .py artifact that is not LOCAL
    lambda files: [PYPDF, local_package(files, artifact="vendor/gone.py")],  # the artifact is not in the project
    lambda files: [PYPDF, local_package(files, artifact="../vendor/safe.py")],
    lambda files: [],
])
def test_lock_entries_that_cannot_carry_the_chain(tmp_path, packages):
    assert use_through_local_artifacts(context_for(tmp_path, CHAIN, packages(CHAIN))) == []


def test_project_source_that_cannot_be_parsed_gives_no_authority(tmp_path):
    files = {**CHAIN, "app/broken.py": "def (:\n"}
    assert use_through_local_artifacts(context_for(tmp_path, files)) == []


def test_srs_without_a_pdf_task_is_still_insufficient(tmp_path):
    context = context_for(tmp_path, {**CHAIN, "SRS.md": "FR-02 The service stores invoices.\n"})
    assert use_through_local_artifacts(context) != []
    assert infer(context, {"name": "pypdf"})["confidence"] == "insufficient"


def test_contract_digest_follows_the_chain(tmp_path):
    whole = infer(context_for(tmp_path / "a", CHAIN), {"name": "pypdf"})
    again = infer(context_for(tmp_path / "b", CHAIN), {"name": "pypdf"})
    moved = infer(context_for(tmp_path / "c", {**CHAIN, "app/main.py": "\n" + MAIN}), {"name": "pypdf"})
    assert whole["digest"] == again["digest"] != moved["digest"]
