"""C4 capability contract from real imports and call sites (plan step 9).

Every project here is real files in a tmp directory (or the InvoiceHub demo project), and every
distribution is a real wheel read by `wheel_meta.read_wheel`. Nothing is imported or run.
"""
import copy
import os
import random

import pytest

from backend.cavr import context_extractor
from backend.cavr.capability_contract import infer_capability_contract
from backend.cavr.context_extractor import extract_project_context, usage_of
from backend.cavr.wheel_meta import read_wheel
from backend.threat_repo.repository import seeds
from test_cavr_support import PYPDF_WHEEL, REPO, build_wheel

INVOICEHUB = REPO / "demo_project" / "InvoiceHub"
POLICY = {
    "project_task_description": "Invoice PDF text extraction",
    "allowed_scopes": ["FILE_READ:invoice_documents", "FILE_WRITE:scratch_tmp", "PROCESS_EXEC:none", "NETWORK_CONNECT:none"],
    "approved_requirements": ["pypdf==6.19.0"],
    "denied_packages": [],
}
GUARDED = '''from io import BytesIO
from pypdf import PdfReader, apply_configuration


def extract(content):
    with apply_configuration(jbig2dec_binary=None):
        reader = PdfReader(BytesIO(content))
        return [page.extract_text() for page in reader.pages]
'''


def outcome(result):
    return result["result"], result["rule"]


def project(tmp_path, files):
    root = tmp_path / "project"
    for path, text in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text if isinstance(text, bytes) else text.encode())
    return root


def pypdf_distribution():
    return read_wheel(PYPDF_WHEEL, "pypdf", "6.19.0")


def contract_for(tmp_path, files, distribution=None, policy=POLICY, **args):
    context = extract_project_context(project(tmp_path, files))
    return infer_capability_contract(distribution or pypdf_distribution(), context, policy, **args)


def sites(items):
    return [(item["file"], item["line"], item["symbol"]) for item in items]


# --- context extractor: imports and call sites ------------------------------------------------------

def test_plain_import_and_call_site(tmp_path):
    context = extract_project_context(project(tmp_path, {"app/read.py": "import pypdf\n\nreader = pypdf.PdfReader('a.pdf')\n"}))
    assert outcome(context) == ("OK", "PROJECT_READ")
    assert context["imports"] == [{"file": "app/read.py", "line": 1, "module": "pypdf", "name": None, "bound_as": "pypdf"}]
    assert context["call_sites"] == [{"file": "app/read.py", "line": 3, "symbol": "pypdf.PdfReader",
                                      "expression": "pypdf.PdfReader", "kind": "call"}]
    assert context["references"] == [] and context["star_imports"] == [] and context["parse_errors"] == []
    assert [entry["path"] for entry in context["files"]] == ["app/read.py"]


def test_aliased_import_is_resolved_to_the_real_module(tmp_path):
    context = extract_project_context(project(tmp_path, {"a.py": "import pypdf as p\n\n\ndef f(x):\n    return p.PdfReader(x)\n"}))
    assert context["imports"][0]["bound_as"] == "p"
    assert context["call_sites"] == [{"file": "a.py", "line": 5, "symbol": "pypdf.PdfReader", "expression": "p.PdfReader",
                                      "kind": "call"}]


def test_from_x_import_y_as_z(tmp_path):
    context = extract_project_context(project(tmp_path, {"a.py": "from pypdf import PdfReader as R\nreader = R('a.pdf')\n"}))
    assert context["imports"] == [{"file": "a.py", "line": 1, "module": "pypdf", "name": "PdfReader", "bound_as": "R"}]
    assert sites(context["call_sites"]) == [("a.py", 2, "pypdf.PdfReader")]
    assert context["call_sites"][0]["expression"] == "R"


def test_submodule_imports(tmp_path):
    source = ("import pypdf.filters\nimport pypdf.generic as g\nfrom pypdf.errors import PdfReadError\n"
              "x = pypdf.filters.decode_stream_data(None)\ny = g.NameObject('/A')\n"
              "try:\n    pass\nexcept PdfReadError:\n    pass\n")
    context = extract_project_context(project(tmp_path, {"a.py": source}))
    assert [(i["module"], i["name"], i["bound_as"]) for i in context["imports"]] == [
        ("pypdf.filters", None, "pypdf"), ("pypdf.generic", None, "g"), ("pypdf.errors", "PdfReadError", "PdfReadError")]
    assert sites(context["call_sites"]) == [("a.py", 4, "pypdf.filters.decode_stream_data"), ("a.py", 5, "pypdf.generic.NameObject")]
    # A use that is not a call (here: an except clause) is a reference.
    assert sites(context["references"]) == [("a.py", 8, "pypdf.errors.PdfReadError")]


def test_decorator_and_base_class_uses(tmp_path):
    source = ("import functools\nimport abc\n\n\n@functools.cache\ndef f():\n    return 1\n\n\n"
              "@functools.lru_cache(maxsize=1)\ndef g():\n    return 2\n\n\nclass C(abc.ABC):\n    pass\n")
    context = extract_project_context(project(tmp_path, {"a.py": source}))
    assert [(c["line"], c["symbol"], c["kind"]) for c in context["call_sites"]] == [
        (5, "functools.cache", "decorator"), (10, "functools.lru_cache", "call")]
    assert sites(context["references"]) == [("a.py", 15, "abc.ABC")]


def test_a_chain_is_recorded_once_and_arguments_are_visited(tmp_path):
    source = "import os\nimport json\nprint(json.dumps(os.path.join(os.sep, 'a')))\n"
    context = extract_project_context(project(tmp_path, {"a.py": source}))
    assert [(c["symbol"], c["kind"]) for c in context["call_sites"]] == [("json.dumps", "call"), ("os.path.join", "call")]
    assert [r["symbol"] for r in context["references"]] == ["os.sep"]


def test_local_names_and_relative_imports_are_not_attributed(tmp_path):
    files = {"pkg/__init__.py": "", "pkg/helpers.py": "def PdfReader(x):\n    return x\n",
             "pkg/main.py": "from . import helpers\nfrom .helpers import PdfReader\n\n\ndef run(self):\n"
                            "    return PdfReader(1), helpers.PdfReader(2), self.reader.PdfReader(3)\n"}
    context = extract_project_context(project(tmp_path, files))
    assert outcome(context) == ("OK", "PROJECT_READ")
    assert context["call_sites"] == [] and context["references"] == []
    assert [(i["module"], i["name"]) for i in context["imports"]] == [(".", "helpers"), (".helpers", "PdfReader")]
    assert usage_of(context, ["pypdf", "helpers"])["imports"] == []


def test_star_import_is_recorded(tmp_path):
    context = extract_project_context(project(tmp_path, {"a.py": "from pypdf import *\nreader = PdfReader('a.pdf')\n"}))
    assert context["star_imports"] == [{"file": "a.py", "line": 1, "module": "pypdf"}]
    assert context["call_sites"] == []


def test_usage_of_filters_by_top_level_import_name(tmp_path):
    source = "import pypdf\nimport pypdfium2\nimport os\npypdf.PdfReader('a')\npypdfium2.PdfDocument('a')\nos.getcwd()\n"
    usage = usage_of(extract_project_context(project(tmp_path, {"a.py": source})), ["pypdf"])
    assert [i["module"] for i in usage["imports"]] == ["pypdf"]
    assert sites(usage["call_sites"]) == [("a.py", 4, "pypdf.PdfReader")]


# --- context extractor: which files are read ------------------------------------------------------------

def test_virtualenvs_caches_and_hidden_directories_are_not_project_code(tmp_path):
    files = {"app/a.py": "import pypdf\n", "build/b.py": "import pypdf\n",
             ".venv/lib/site.py": "import x\n", "venv/pyvenv.cfg": "home = /usr\n", "venv/lib/pkg.py": "import y\n",
             "node_modules/n/gyp.py": "import z\n", "app/__pycache__/a.py": "import w\n", ".git/hooks/h.py": "import v\n"}
    context = extract_project_context(project(tmp_path, files))
    assert [entry["path"] for entry in context["files"]] == ["app/a.py", "build/b.py"]
    assert sorted(context["skipped_directories"]) == [".git", ".venv", "app/__pycache__", "node_modules", "venv"]


def test_missing_project_directory_is_unresolved(tmp_path):
    assert outcome(extract_project_context(tmp_path / "nowhere")) == ("UNRESOLVED", "PROJECT_MISSING")
    file = tmp_path / "file.py"
    file.write_text("x = 1\n")
    assert outcome(extract_project_context(file)) == ("UNRESOLVED", "PROJECT_MISSING")


@pytest.mark.parametrize("data", [b"def broken(:\n    pass\n", b"x = 1\x00\n", b"# coding: no-such-codec\nx = 1\n",
                                  b"x = '\xff\xfe'\n", b"(" * 5000 + b")" * 5000])
def test_a_project_file_that_cannot_be_parsed_makes_the_context_unresolved(tmp_path, data):
    context = extract_project_context(project(tmp_path, {"good.py": "import pypdf\npypdf.PdfReader('a')\n", "bad.py": data}))
    assert outcome(context) == ("UNRESOLVED", "SOURCE_NOT_PARSED")
    assert [error["file"] for error in context["parse_errors"]] == ["bad.py"]
    # The files that do parse are still read.
    assert sites(context["call_sites"]) == [("good.py", 2, "pypdf.PdfReader")]


def test_symbolic_links_are_not_followed_and_make_the_context_unresolved(tmp_path):
    root = project(tmp_path, {"a.py": "import pypdf\n"})
    outside = tmp_path / "outside.py"
    outside.write_text("import secret_module\n")
    os.symlink(outside, root / "link.py")
    context = extract_project_context(root)
    assert outcome(context) == ("UNRESOLVED", "SOURCE_NOT_READ")
    assert [i["module"] for i in context["imports"]] == ["pypdf"]
    assert context["not_read"] == [{"file": "link.py", "reason": "symbolic link"}]


def test_symlinked_directory_is_not_followed(tmp_path):
    root = project(tmp_path, {"a.py": "x = 1\n"})
    other = tmp_path / "other"
    other.mkdir()
    (other / "b.py").write_text("import secret_module\n")
    os.symlink(other, root / "linked", target_is_directory=True)
    context = extract_project_context(root)
    assert outcome(context) == ("UNRESOLVED", "SOURCE_NOT_READ")
    assert context["imports"] == [] and context["not_read"] == [{"file": "linked", "reason": "symbolic link"}]


def test_directory_that_cannot_be_listed_makes_the_context_unresolved(tmp_path):
    """Review BLOCKER 6: `os.walk` skips a directory it may not read without saying so."""
    root = project(tmp_path, {"a.py": "import pypdf\n", "locked/b.py": "import pypdf\npypdf.PdfReader(1)\n"})
    if os.geteuid() == 0:
        pytest.skip("root can read every directory")
    os.chmod(root / "locked", 0)
    try:
        context = extract_project_context(root)
    finally:
        os.chmod(root / "locked", 0o755)
    assert outcome(context) == ("UNRESOLVED", "SOURCE_NOT_READ")
    assert [entry["file"] for entry in context["not_read"]] == ["locked"]
    assert outcome(extract_project_context(root)) == ("OK", "PROJECT_READ")


def test_budgets(tmp_path, monkeypatch):
    root = project(tmp_path, {"a.py": "x = 1\n", "b.py": "y = 2\n" * 10})
    monkeypatch.setattr(context_extractor, "MAX_FILE_BYTES", 20)
    assert outcome(extract_project_context(root)) == ("UNRESOLVED", "PROJECT_BUDGET")
    monkeypatch.undo()
    monkeypatch.setattr(context_extractor, "MAX_FILES", 1)
    assert outcome(extract_project_context(root)) == ("UNRESOLVED", "PROJECT_BUDGET")


def test_sources_digest_covers_every_python_file(tmp_path):
    root = project(tmp_path, {"a.py": "import pypdf\n", "b.py": "x = 1\n", "notes.txt": "hello"})
    first = extract_project_context(root)
    assert extract_project_context(root) == first and len(first["sources_digest"]) == 64
    (root / "notes.txt").write_text("changed")
    assert extract_project_context(root)["sources_digest"] == first["sources_digest"]
    (root / "b.py").write_text("x = 2\n")
    assert extract_project_context(root)["sources_digest"] != first["sources_digest"]


def test_reading_a_project_does_not_run_it(tmp_path):
    marker = tmp_path / "ran"
    root = project(tmp_path, {"a.py": f"open({str(marker)!r}, 'w').close()\n"})
    assert outcome(extract_project_context(root)) == ("OK", "PROJECT_READ")
    assert not marker.exists()
    # The same file does create the marker when it is really run, so the assertion above can fail.
    exec(compile((root / "a.py").read_text(), "a.py", "exec"), {})
    assert marker.exists()


def test_every_context_result_has_the_same_keys(tmp_path):
    good = extract_project_context(project(tmp_path, {"a.py": "x = 1\n"}))
    assert set(good) == set(extract_project_context(tmp_path / "nowhere"))


# --- contract: the InvoiceHub demo project and the real pypdf wheel ---------------------------------------

def test_invoicehub_contract_for_pypdf():
    contract = infer_capability_contract(pypdf_distribution(), extract_project_context(INVOICEHUB), POLICY)
    assert outcome(contract) == ("OK", "CONTRACT_INFERRED")
    assert contract["package"] == "pypdf" and contract["import_names"] == ["pypdf"]
    assert sites(contract["call_sites"]) == [("app/pdf_adapter.py", 7, "pypdf.apply_configuration"),
                                             ("app/pdf_adapter.py", 8, "pypdf.PdfReader")]
    assert [(i["file"], i["line"], i["name"]) for i in contract["imports"]] == [
        ("app/pdf_adapter.py", 2, "PdfReader"), ("app/pdf_adapter.py", 2, "apply_configuration")]
    assert contract["entry_modules"] == ["pypdf", "pypdf.PdfReader", "pypdf.apply_configuration"]
    assert [(a["capability"], a["scope"], a["status"]) for a in contract["allowed"]] == [
        ("FILE_READ", "invoice_documents", "REQUIRED"), ("FILE_WRITE", "scratch_tmp", "REQUIRED")]
    denied = {d["capability"]: d["source"] for d in contract["denied"]}
    assert denied["PROCESS_EXEC"] == "policy allowed_scopes: PROCESS_EXEC:none"
    assert denied["NETWORK_CONNECT"] == "policy allowed_scopes: NETWORK_CONNECT:none"
    assert denied["SECRET_READ"] == "rule CAP-PDF-001 denies it for the task 'pdf extraction'"
    assert denied["DYNAMIC_DOWNLOAD"] == "not granted by the policy (default deny)"
    assert contract["capability_rules"] == [{"id": "CAP-PDF-001", "version": 1, "task": "pdf extraction"}]
    assert len(contract["digest"]) == 64 and contract["sources_digest"] == extract_project_context(INVOICEHUB)["sources_digest"]


# --- contract: import names come from the wheel ---------------------------------------------------------

def test_import_name_comes_from_top_level_txt_not_from_the_distribution_name(tmp_path):
    wheel = build_wheel(tmp_path / "w", "invoice-tools", "1.0", files={"invtools/__init__.py": "def parse(x):\n    return x\n"},
                        top_level="invtools\n")
    distribution = read_wheel(wheel, "invoice-tools", "1.0")
    assert distribution["import_names"] == ["invtools"] and distribution["import_names_source"] == "top_level.txt"
    used = contract_for(tmp_path / "p1", {"a.py": "import invtools\ninvtools.parse(1)\n"}, distribution)
    assert outcome(used) == ("OK", "CONTRACT_INFERRED") and sites(used["call_sites"]) == [("a.py", 2, "invtools.parse")]
    # Guessing the import name from the distribution name would attribute this project instead.
    guessed = contract_for(tmp_path / "p2", {"a.py": "import invoice_tools\ninvoice_tools.parse(1)\n"}, distribution)
    assert outcome(guessed) == ("UNRESOLVED", "NO_CALL_SITE_AUTHORITY")


def test_undeclared_import_names_in_the_wheel_are_attributed_too(tmp_path):
    wheel = build_wheel(tmp_path / "w", "two-names", "1.0", top_level="two_names\n",
                        files={"two_names/__init__.py": "", "hidden/__init__.py": "def f():\n    return 1\n"})
    distribution = read_wheel(wheel, "two-names", "1.0")
    assert distribution["undeclared_import_names"] == ["hidden"]
    contract = contract_for(tmp_path, {"a.py": "import hidden\nhidden.f()\n"}, distribution)
    assert outcome(contract) == ("OK", "CONTRACT_INFERRED") and contract["import_names"] == ["hidden", "two_names"]


@pytest.mark.parametrize("distribution", ["pypdf", {"name": "pypdf", "version": "6.19.0"},
                                          {"name": "pypdf", "version": "6.19.0", "import_names": []},
                                          {"name": "pypdf", "version": "6.19.0", "import_names": "pypdf"},
                                          {"name": "pypdf", "version": "6.19.0", "import_names": ["not an identifier"]},
                                          {"import_names": ["pypdf"]}, None])
def test_distribution_without_usable_import_names_is_unresolved(tmp_path, distribution):
    context = extract_project_context(project(tmp_path, {"a.py": GUARDED}))
    contract = infer_capability_contract(distribution, context, POLICY)
    assert outcome(contract) == ("UNRESOLVED", "IMPORT_NAMES_UNKNOWN")
    assert contract["call_sites"] == []


# --- contract: no call-site authority -----------------------------------------------------------------------

def test_unused_package_has_no_call_site_authority(tmp_path):
    contract = contract_for(tmp_path, {"a.py": "import json\nprint(json.dumps({}))\n"})
    assert outcome(contract) == ("UNRESOLVED", "NO_CALL_SITE_AUTHORITY")
    assert "never imported" in contract["reason"]
    assert contract["imports"] == [] and contract["call_sites"] == []


def test_package_named_only_in_a_string_or_comment_is_not_imported(tmp_path):
    contract = contract_for(tmp_path, {"a.py": "# import pypdf\nTEXT = 'import pypdf; pypdf.PdfReader(1)'\n"})
    assert outcome(contract) == ("UNRESOLVED", "NO_CALL_SITE_AUTHORITY")


def test_imported_but_never_used_has_no_call_site_authority(tmp_path):
    contract = contract_for(tmp_path, {"a.py": "import pypdf\nfrom pypdf import PdfReader\n"})
    assert outcome(contract) == ("UNRESOLVED", "NO_CALL_SITE_AUTHORITY")
    assert "never used" in contract["reason"] and len(contract["imports"]) == 2


def test_a_reference_without_a_call_is_a_use(tmp_path):
    contract = contract_for(tmp_path, {"a.py": "from pypdf import PdfReader\n\n\nclass Reader(PdfReader):\n    pass\n"})
    assert outcome(contract) == ("OK", "CONTRACT_INFERRED")
    assert contract["call_sites"] == [] and sites(contract["references"]) == [("a.py", 4, "pypdf.PdfReader")]


def test_star_import_of_the_package_is_unresolved(tmp_path):
    contract = contract_for(tmp_path, {"a.py": "from pypdf import *\nreader = PdfReader('a.pdf')\n"})
    assert outcome(contract) == ("UNRESOLVED", "STAR_IMPORT")
    assert contract["star_imports"] == [{"file": "a.py", "line": 1, "module": "pypdf"}]
    # A star import of something else does not matter for this package.
    other = contract_for(tmp_path / "other", {"a.py": "from os.path import *\nimport pypdf\npypdf.PdfReader(1)\n"})
    assert outcome(other) == ("OK", "CONTRACT_INFERRED")


def test_unresolved_project_context_makes_the_contract_unresolved(tmp_path):
    broken = contract_for(tmp_path, {"a.py": GUARDED, "b.py": "def broken(:\n"})
    assert outcome(broken) == ("UNRESOLVED", "SOURCE_NOT_PARSED") and "b.py" in broken["reason"]
    missing = infer_capability_contract(pypdf_distribution(), extract_project_context(tmp_path / "nowhere"), POLICY)
    assert outcome(missing) == ("UNRESOLVED", "PROJECT_MISSING")
    for context in (None, {}, {"result": "OK"}, "text"):
        assert outcome(infer_capability_contract(pypdf_distribution(), context, POLICY)) == ("UNRESOLVED", "PROJECT_NOT_READ")


# --- contract: allowed capabilities from the policy and the capability rules --------------------------------

def test_policy_grants_and_task_rule_denies(tmp_path):
    policy = {**POLICY, "allowed_scopes": ["FILE_READ:invoices", "NETWORK_CONNECT:api.example.com", "DYNAMIC_DOWNLOAD:models"]}
    contract = contract_for(tmp_path, {"a.py": GUARDED}, policy=policy)
    assert outcome(contract) == ("OK", "CONTRACT_INFERRED")
    # CAP-PDF-001 denies NETWORK_CONNECT for a PDF extraction task: the stricter side wins and the conflict is recorded.
    assert [(a["capability"], a["scope"], a["status"]) for a in contract["allowed"]] == [
        ("DYNAMIC_DOWNLOAD", "models", "OPTIONAL"), ("FILE_READ", "invoices", "REQUIRED")]
    assert contract["conflicts"] == [{"capability": "NETWORK_CONNECT", "scope": "api.example.com", "denied_by": "CAP-PDF-001"}]
    assert "NETWORK_CONNECT" in {d["capability"] for d in contract["denied"]}


def test_without_a_matching_task_rule_only_the_policy_decides(tmp_path):
    policy = {**POLICY, "project_task_description": "Weather dashboard", "allowed_scopes": ["NETWORK_CONNECT:api.example.com"]}
    contract = contract_for(tmp_path, {"a.py": GUARDED}, policy=policy)
    assert contract["capability_rules"] == []
    assert [(a["capability"], a["status"]) for a in contract["allowed"]] == [("NETWORK_CONNECT", "OPTIONAL")]
    assert {d["source"] for d in contract["denied"]} == {"not granted by the policy (default deny)"}


def test_http_client_task_selects_the_http_rule(tmp_path):
    policy = {**POLICY, "project_task_description": "An HTTP client for the billing API",
              "allowed_scopes": ["NETWORK_CONNECT:billing.example.com", "PROCESS_EXEC:git"]}
    contract = contract_for(tmp_path, {"a.py": GUARDED}, policy=policy)
    assert [rule["id"] for rule in contract["capability_rules"]] == ["CAP-HTTP-001"]
    assert [(a["capability"], a["status"]) for a in contract["allowed"]] == [("NETWORK_CONNECT", "REQUIRED")]
    assert contract["conflicts"] == [{"capability": "PROCESS_EXEC", "scope": "git", "denied_by": "CAP-HTTP-001"}]


def test_policy_without_allowed_scopes_grants_nothing(tmp_path):
    policy = {key: value for key, value in POLICY.items() if key != "allowed_scopes"}
    contract = contract_for(tmp_path, {"a.py": GUARDED}, policy=policy)
    assert outcome(contract) == ("OK", "CONTRACT_INFERRED") and contract["allowed"] == []
    assert len(contract["denied"]) == len(contract["vocabulary"]) == 10


def test_capability_names_of_rules_and_policy_use_one_vocabulary(tmp_path):
    # The rules say PROCESS_CREATE / SECRET_ACCESS / EXECUTE_BINARY; the policy and the sinks say PROCESS_EXEC etc.
    policy = {**POLICY, "allowed_scopes": ["PROCESS_CREATE:none", "SECRET_ACCESS:none"]}
    contract = contract_for(tmp_path, {"a.py": GUARDED}, policy=policy)
    denied = {d["capability"]: d["source"] for d in contract["denied"]}
    assert denied["PROCESS_EXEC"] == "policy allowed_scopes: PROCESS_CREATE:none"
    assert denied["SECRET_READ"] == "policy allowed_scopes: SECRET_ACCESS:none"
    assert "NATIVE_EXEC" in denied and "EXECUTE_BINARY" not in denied


@pytest.mark.parametrize("scopes", ["FILE_READ:x", [1], ["FILE_READ"], ["FILE_READ:"], [":x"], ["TELEPORT:x"],
                                    ["FILE_READ:a", "FILE_READ:b"], ["FILE_READ:a", "FILE_READ:none"], {"FILE_READ": "x"}])
def test_malformed_allowed_scopes_is_unresolved(tmp_path, scopes):
    contract = contract_for(tmp_path, {"a.py": GUARDED}, policy={**POLICY, "allowed_scopes": scopes})
    assert outcome(contract) == ("UNRESOLVED", "CAPABILITY_POLICY_INVALID")
    assert contract["allowed"] == []


@pytest.mark.parametrize("policy", [None, [], "policy", {**POLICY, "project_task_description": 5}])
def test_unusable_policy_is_unresolved(tmp_path, policy):
    contract = contract_for(tmp_path, {"a.py": GUARDED}, policy=policy)
    assert outcome(contract) == ("UNRESOLVED", "CAPABILITY_POLICY_INVALID") and contract["allowed"] == []


def test_disabled_rule_is_not_applied(tmp_path):
    records = copy.deepcopy(seeds())
    next(r for r in records if r["id"] == "CAP-PDF-001")["enabled"] = False
    policy = {**POLICY, "allowed_scopes": ["NETWORK_CONNECT:api"]}
    contract = contract_for(tmp_path, {"a.py": GUARDED}, policy=policy, knowledge={"records": records})
    assert contract["capability_rules"] == [] and [a["capability"] for a in contract["allowed"]] == ["NETWORK_CONNECT"]


# --- contract: digest -------------------------------------------------------------------------------------------

FILES = {"app/a.py": GUARDED, "app/b.py": "import pypdf\n\n\ndef pages(path):\n    return len(pypdf.PdfReader(path).pages)\n",
         "app/c.py": "import json\n"}


def test_digest_is_stable_across_reordering(tmp_path):
    context = extract_project_context(project(tmp_path, FILES))
    first = infer_capability_contract(pypdf_distribution(), context, POLICY)
    assert outcome(first) == ("OK", "CONTRACT_INFERRED")
    shuffled = copy.deepcopy(context)
    generator = random.Random(7)
    for key in ("files", "imports", "call_sites", "references"):
        generator.shuffle(shuffled[key])
    assert shuffled["call_sites"] != context["call_sites"]
    policy = {**dict(reversed(list(POLICY.items()))), "allowed_scopes": list(reversed(POLICY["allowed_scopes"]))}
    distribution = {**pypdf_distribution(), "import_names": ["pypdf", "pypdf"]}
    second = infer_capability_contract(distribution, shuffled, policy)
    assert second["digest"] == first["digest"]
    assert second["call_sites"] == first["call_sites"] and second["allowed"] == first["allowed"]
    # The same project in another directory gives the same contract.
    moved = infer_capability_contract(pypdf_distribution(), extract_project_context(project(tmp_path / "elsewhere", FILES)), POLICY)
    assert moved["digest"] == first["digest"]


def test_digest_changes_when_a_new_call_site_appears(tmp_path):
    first = contract_for(tmp_path / "one", FILES)
    more = {**FILES, "app/c.py": "import json\nimport pypdf\n\nwriter = pypdf.PdfWriter()\n"}
    second = contract_for(tmp_path / "two", more)
    assert second["digest"] != first["digest"]
    assert set(sites(second["call_sites"])) - set(sites(first["call_sites"])) == {("app/c.py", 4, "pypdf.PdfWriter")}


def test_digest_changes_when_a_call_site_moves_or_is_removed(tmp_path):
    first = contract_for(tmp_path / "one", FILES)
    moved = contract_for(tmp_path / "two", {**FILES, "app/b.py": "\n" + FILES["app/b.py"]})
    removed = contract_for(tmp_path / "three", {key: value for key, value in FILES.items() if key != "app/b.py"})
    assert len({first["digest"], moved["digest"], removed["digest"]}) == 3


def test_digest_changes_when_the_guard_changes_but_the_call_sites_do_not(tmp_path):
    """The verdict depends on the code around a call site (the pypdf guard), so the digest covers the sources."""
    first = contract_for(tmp_path / "one", FILES)
    unguarded = {**FILES, "app/a.py": GUARDED.replace("jbig2dec_binary=None", "jbig2dec_binary='x'")}
    second = contract_for(tmp_path / "two", unguarded)
    assert sites(second["call_sites"]) == sites(first["call_sites"])
    assert second["digest"] != first["digest"]


def test_digest_changes_with_the_policy_the_rules_and_the_import_names(tmp_path):
    root = project(tmp_path, FILES)
    context = extract_project_context(root)
    first = infer_capability_contract(pypdf_distribution(), context, POLICY)
    granted = infer_capability_contract(pypdf_distribution(), context, {**POLICY, "allowed_scopes": ["FILE_READ:invoice_documents"]})
    records = copy.deepcopy(seeds())
    next(r for r in records if r["id"] == "CAP-PDF-001")["data"]["denied"].remove("SECRET_ACCESS")
    other_rules = infer_capability_contract(pypdf_distribution(), context, POLICY, knowledge={"records": records})
    more_names = infer_capability_contract({**pypdf_distribution(), "import_names": ["pypdf", "extra"]}, context, POLICY)
    assert len({first["digest"], granted["digest"], other_rules["digest"], more_names["digest"]}) == 4
    # Policy keys that the contract does not read do not change it (they change `policy_version` instead).
    same = infer_capability_contract(pypdf_distribution(), context, {**POLICY, "approved_requirements": []})
    assert same["digest"] == first["digest"]


# --- shape ---------------------------------------------------------------------------------------------------------

def test_every_contract_has_the_same_keys_and_dashboard_rows(tmp_path):
    good = contract_for(tmp_path / "one", FILES)
    bad = infer_capability_contract("pypdf", None, None)
    assert set(good) == set(bad)
    for contract in (good, bad):
        counts = contract["summary"]
        assert counts["required_count"] + counts["optional_count"] + counts["denied_count"] == len(contract["contract_rows"])
        assert all(set(row) == {"capability", "status", "evidence", "justification"} for row in contract["contract_rows"])
    assert [row["capability"] for row in good["contract_rows"] if row["status"] == "REQUIRED"] == [
        "FILE_READ(invoice_documents)", "FILE_WRITE(scratch_tmp)"]
    assert good["summary"] == {"required_count": 2, "optional_count": 0, "denied_count": 8}


def test_dashboard_call_without_a_wheel_is_unresolved_not_a_guess():
    """A caller that gives only a name and no wheel: the rows come from the policy, the authority is unknown."""
    contract = infer_capability_contract("pypdf", extract_project_context(), POLICY)
    assert outcome(contract) == ("UNRESOLVED", "IMPORT_NAMES_UNKNOWN")
    assert contract["summary"]["denied_count"] == 8 and contract["package"] == "pypdf"
