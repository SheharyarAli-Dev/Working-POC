"""Which sinks can the project's call sites reach? (plan step 11, "Sink reachability and escalation").

Wheels are real zips built in tmp directories (or the real pypdf wheel); projects are real files.
Nothing is imported or run.
"""
import functools

import pytest

from backend.cavr.ast_scan import scan_wheel
from backend.cavr.capability_contract import infer_capability_contract
from backend.cavr.context_extractor import extract_project_context
from backend.cavr.fast_gate import disabled_jbig2_sinks
from backend.cavr.reachability import ProjectSources, import_graph, judge_sinks, module_name
from backend.cavr.wheel_meta import read_wheel
from test_cavr_support import PYPDF_WHEEL, build_wheel

POLICY = {"project_task_description": "Invoice PDF text extraction",
          "allowed_scopes": ["FILE_READ:invoice_documents", "PROCESS_EXEC:none", "NETWORK_CONNECT:none"]}
NETWORK = "import socket\n\n\ndef send(data):\n    socket.create_connection(('example.invalid', 443))\n"
GUARDED = '''from io import BytesIO
from pypdf import PdfReader, apply_configuration


def extract(content):
    with apply_configuration(jbig2dec_binary=None):
        reader = PdfReader(BytesIO(content))
        return [page.extract_text() for page in reader.pages]
'''


def project(tmp_path, files):
    root = tmp_path / "project"
    for path, text in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    return root


def node(wheel, name, version):
    metadata = read_wheel(wheel, name, version)
    assert metadata["result"] == "OK", metadata["reason"]
    return {"name": metadata["name"], "version": version, "path": str(wheel), "import_names": metadata["import_names"],
            "metadata": metadata}


def judge(tmp_path, wheels, project_files, policy=POLICY):
    """`wheels` is [(name, version, files)]; the first one is the root the project asks for."""
    nodes = [node(build_wheel(tmp_path / f"w{i}", name, version, files=files), name, version)
             for i, (name, version, files) in enumerate(wheels)]
    context = extract_project_context(project(tmp_path, project_files))
    contract = infer_capability_contract(nodes[0]["metadata"], context, policy)
    assert contract["result"] == "OK", contract["reason"]
    return judge_sinks(nodes, [scan_wheel(n["path"]) for n in nodes], contract, context)


def outcome(result):
    return result["result"], result["rule"]


def verdicts(result):
    return [(sink["file"], sink["line"], sink["verdict"]) for sink in result["sinks"]]


# --- module names and the import graph -----------------------------------------------------------

@pytest.mark.parametrize("path, expected", [
    ("pkg/__init__.py", "pkg"), ("pkg/sub/mod.py", "pkg.sub.mod"), ("single.py", "single"), ("pkg/sub/__init__.py", "pkg.sub"),
    ("pkg-1.0.data/purelib/pkg/a.py", "pkg.a"), ("pkg-1.0.data/platlib/pkg/__init__.py", "pkg"),
    ("pkg-1.0.data/scripts/tool.py", None), ("pkg-1.0.dist-info/x.py", None), ("pkg/not-a-module.py", None),
    ("pkg/data.txt", None), ("__init__.py", None)])
def test_module_name(path, expected):
    assert module_name(path) == expected


def test_import_graph_resolves_absolute_relative_and_star_imports(tmp_path):
    files = {"pkg/__init__.py": "from . import a\nfrom .sub import b as renamed\n", "pkg/a.py": "import pkg.sub.c\nfrom .. import outside\n",
             "pkg/sub/__init__.py": "", "pkg/sub/b.py": "from ..a import thing\nfrom . import c\n", "pkg/sub/c.py": "from pkg.star import *\n",
             "pkg/star/__init__.py": "", "pkg/star/one.py": "", "pkg/lonely.py": "import os\n"}
    wheel = build_wheel(tmp_path, "pkg", "1.0", files=files)
    graph = import_graph([{"name": "pkg", "version": "1.0", "path": str(wheel)}])
    assert graph["complete"] and sorted(graph["modules"]) == ["pkg", "pkg.a", "pkg.lonely", "pkg.star", "pkg.star.one", "pkg.sub",
                                                             "pkg.sub.b", "pkg.sub.c"]
    imports = graph["imports"]
    assert imports["pkg"] == {"pkg.a", "pkg.sub", "pkg.sub.b"}
    assert imports["pkg.a"] == {"pkg", "pkg.sub", "pkg.sub.c"}
    assert imports["pkg.sub.b"] == {"pkg", "pkg.a", "pkg.sub", "pkg.sub.c"}
    # A star import may bind every submodule of the package.
    assert imports["pkg.sub.c"] == {"pkg", "pkg.star", "pkg.star.one"}
    assert imports["pkg.lonely"] == set()


# --- reachable, unreachable, allowed -----------------------------------------------------------------

def test_sink_in_a_module_the_project_never_reaches_is_unreachable_evidence(tmp_path):
    files = {"demo/__init__.py": "from .core import run\n", "demo/core.py": "def run():\n    return 1\n", "demo/cli.py": NETWORK}
    result = judge(tmp_path, [("demo", "1.0", files)], {"app.py": "import demo\ndemo.run()\n"})
    assert outcome(result) == ("OK", "NO_DENIED_SINK_REACHABLE")
    assert verdicts(result) == [("demo/cli.py", 5, "UNREACHABLE")]
    assert result["reachable_modules"] == ["demo", "demo.core"] and result["entry_modules"] == ["demo"]
    assert "demo.cli" in result["sinks"][0]["why"]


def test_sink_in_a_module_imported_by_the_entry_module_is_reachable(tmp_path):
    files = {"demo/__init__.py": "from .core import run\n", "demo/core.py": "from . import net\n\n\ndef run():\n    return 1\n",
             "demo/net.py": NETWORK}
    result = judge(tmp_path, [("demo", "1.0", files)], {"app.py": "import demo\ndemo.run()\n"})
    assert outcome(result) == ("UNRESOLVED", "SINK_REACHABLE")
    assert verdicts(result) == [("demo/net.py", 5, "REACHABLE")]
    assert "demo/net.py:5" in result["reason"] and "NETWORK_CONNECT" in result["reason"]


def test_importing_a_submodule_directly_is_an_entry(tmp_path):
    files = {"demo/__init__.py": "", "demo/core.py": "", "demo/net.py": NETWORK}
    quiet = judge(tmp_path / "a", [("demo", "1.0", files)], {"app.py": "import demo.core\ndemo.core.x()\n"})
    assert outcome(quiet) == ("OK", "NO_DENIED_SINK_REACHABLE")
    for number, source in enumerate(("import demo.net\ndemo.net.send(b'')\n", "from demo import net\nnet.send(b'')\n",
                                     "from demo.net import send\nsend(b'')\n", "import demo\ndemo.net.send(b'')\n")):
        direct = judge(tmp_path / f"direct{number}", [("demo", "1.0", files)], {"app.py": source})
        assert outcome(direct) == ("UNRESOLVED", "SINK_REACHABLE"), source


def test_a_sink_whose_capability_is_granted_without_a_scope_limit_is_evidence(tmp_path):
    files = {"demo/__init__.py": NETWORK}
    policy = {"project_task_description": "Billing dashboard", "allowed_scopes": ["NETWORK_CONNECT:*"]}
    result = judge(tmp_path, [("demo", "1.0", files)], {"app.py": "import demo\ndemo.send(b'')\n"}, policy)
    assert outcome(result) == ("OK", "NO_DENIED_SINK_REACHABLE")
    assert verdicts(result) == [("demo/__init__.py", 5, "ALLOWED")]
    # The same wheel and project under a policy that does not grant it.
    denied = judge(tmp_path / "denied", [("demo", "1.0", files)], {"app.py": "import demo\ndemo.send(b'')\n"})
    assert outcome(denied) == ("UNRESOLVED", "SINK_REACHABLE")


def test_a_grant_limited_to_a_scope_does_not_clear_a_sink(tmp_path):
    """Review BLOCKER 1: the scan cannot tell where a call connects to, so a scoped grant proves nothing about it."""
    files = {"demo/__init__.py": NETWORK}  # connects to example.invalid
    policy = {"project_task_description": "Billing dashboard", "allowed_scopes": ["NETWORK_CONNECT:billing.example.com"]}
    result = judge(tmp_path, [("demo", "1.0", files)], {"app.py": "import demo\ndemo.send(b'')\n"}, policy)
    assert outcome(result) == ("UNRESOLVED", "SINK_REACHABLE")
    assert verdicts(result) == [("demo/__init__.py", 5, "REACHABLE")]
    assert "billing.example.com" in result["sinks"][0]["why"]
    # A sink the project cannot reach is still only evidence.
    files = {"demo/__init__.py": "def run():\n    return 1\n", "demo/cli.py": NETWORK}
    quiet = judge(tmp_path / "quiet", [("demo", "1.0", files)], {"app.py": "import demo\ndemo.run()\n"}, policy)
    assert outcome(quiet) == ("OK", "NO_DENIED_SINK_REACHABLE")


def test_no_sinks_at_all(tmp_path):
    result = judge(tmp_path, [("demo", "1.0", {"demo/__init__.py": "def run():\n    return 1\n"})], {"app.py": "import demo\ndemo.run()\n"})
    assert outcome(result) == ("OK", "NO_DENIED_SINK_REACHABLE") and result["sinks"] == []


def test_sink_in_a_dependency_is_reached_through_the_root(tmp_path):
    root = {"top/__init__.py": "import helper\n\n\ndef run():\n    return helper.work()\n"}
    used = {"helper/__init__.py": "import os\n\n\ndef work():\n    os.system('id')\n"}
    result = judge(tmp_path, [("top", "1.0", root), ("helper", "2.0", used)], {"app.py": "import top\ntop.run()\n"})
    assert outcome(result) == ("UNRESOLVED", "SINK_REACHABLE")
    assert [(s["package"], s["verdict"]) for s in result["sinks"]] == [("helper", "REACHABLE")]
    # The same dependency when the root never imports it.
    unused = judge(tmp_path / "b", [("top", "1.0", {"top/__init__.py": "def run():\n    return 1\n"}), ("helper", "2.0", used)],
                   {"app.py": "import top\ntop.run()\n"})
    assert outcome(unused) == ("OK", "NO_DENIED_SINK_REACHABLE")
    assert [(s["package"], s["verdict"]) for s in unused["sinks"]] == [("helper", "UNREACHABLE")]


def test_dependency_that_the_project_imports_directly_is_an_entry(tmp_path):
    """Review BLOCKER 2: the root never imports `helper`, but the project does."""
    root = {"top/__init__.py": "def run():\n    return 1\n"}
    used = {"helper/__init__.py": "import os\n\n\ndef work():\n    os.system('id')\n"}
    for number, source in enumerate(("import top\nimport helper\ntop.run()\nhelper.work()\n",
                                     "import top\nfrom helper import work\ntop.run()\nwork()\n",
                                     "import top\nfrom helper import *\ntop.run()\n")):
        result = judge(tmp_path / f"p{number}", [("top", "1.0", root), ("helper", "2.0", used)], {"app.py": source})
        assert outcome(result) == ("UNRESOLVED", "SINK_REACHABLE"), source
        assert [(s["package"], s["verdict"]) for s in result["sinks"]] == [("helper", "REACHABLE")]
        assert "helper" in result["entry_modules"]


def test_no_entry_module_in_the_wheels_means_nothing_can_be_called_unreachable(tmp_path):
    """Review BLOCKER 3: top_level.txt says `nice`, the code is at `_src/nice/`, and a .pth line adds `_src` to the path."""
    files = {"_src/nice/__init__.py": NETWORK, "x.pth": "_src\n"}
    wheel = build_wheel(tmp_path / "w", "nice", "1.0", files=files, top_level="nice\n")
    nodes = [node(wheel, "nice", "1.0")]
    context = extract_project_context(project(tmp_path, {"app.py": "import nice\nnice.send(b'')\n"}))
    contract = infer_capability_contract(nodes[0]["metadata"], context, POLICY)
    assert contract["result"] == "OK" and contract["entry_modules"] == ["nice", "nice.send"]
    scans = [scan_wheel(wheel)]
    assert scans[0]["rule"] == "SCAN_COMPLETE"
    result = judge_sinks(nodes, scans, contract, context)
    assert outcome(result) == ("UNRESOLVED", "SINK_REACHABLE") and verdicts(result) == [("_src/nice/__init__.py", 5, "REACHABLE")]
    # The same without the .pth file: still no module the project imports is a module of the wheel.
    files = {"_src/nice/__init__.py": NETWORK}
    wheel = build_wheel(tmp_path / "w2", "nice", "1.0", files=files, top_level="nice\n")
    nodes = [node(wheel, "nice", "1.0")]
    result = judge_sinks(nodes, [scan_wheel(wheel)], contract, context)
    assert outcome(result) == ("UNRESOLVED", "SINK_REACHABLE") and result["entry_modules"] == []
    assert "none of the modules the project imports" in result["sinks"][0]["why"]


def test_a_pth_path_line_makes_every_sink_reachable(tmp_path):
    """With a path added by a .pth file, a module's name in the archive is not the name it is imported by."""
    files = {"demo/__init__.py": "import extra\n\n\ndef run():\n    return 1\n", "_vendor/extra.py": NETWORK, "demo.pth": "_vendor\n"}
    result = judge(tmp_path, [("demo", "1.0", files)], {"app.py": "import demo\ndemo.run()\n"})
    assert outcome(result) == ("UNRESOLVED", "SINK_REACHABLE")
    assert verdicts(result) == [("_vendor/extra.py", 5, "REACHABLE")]
    assert [(w["file"], w["call"]) for w in result["widened_by"]] == [("demo.pth", "import path added by a .pth file")]
    # Without the .pth line `extra` is not importable from the wheel, and the file is not reached.
    del files["demo.pth"]
    quiet = judge(tmp_path / "quiet", [("demo", "1.0", files)], {"app.py": "import demo\ndemo.run()\n"})
    assert outcome(quiet) == ("OK", "NO_DENIED_SINK_REACHABLE")


@pytest.mark.parametrize("name", ["sitecustomize", "usercustomize"])
def test_modules_python_runs_at_start_up_are_always_reached(tmp_path, name):
    files = {"demo/__init__.py": "def run():\n    return 1\n", f"{name}.py": "import os\nos.system('id')\n"}
    result = judge(tmp_path, [("demo", "1.0", files)], {"app.py": "import demo\ndemo.run()\n"})
    assert outcome(result) == ("UNRESOLVED", "SINK_REACHABLE")
    assert verdicts(result) == [(f"{name}.py", 2, "REACHABLE")] and name in result["entry_modules"]


def test_a_dynamic_import_in_reached_code_makes_every_sink_reachable(tmp_path):
    files = {"demo/__init__.py": "import importlib\n\n\ndef run(name):\n    return importlib.import_module('demo.' + name)\n",
             "demo/cli.py": NETWORK}
    result = judge(tmp_path, [("demo", "1.0", files)], {"app.py": "import demo\ndemo.run('x')\n"})
    assert outcome(result) == ("UNRESOLVED", "SINK_REACHABLE")
    assert verdicts(result) == [("demo/cli.py", 5, "REACHABLE")]
    assert [(w["file"], w["line"], w["call"]) for w in result["widened_by"]] == [("demo/__init__.py", 5, "importlib.import_module")]
    # A dynamic import in code the project never reaches changes nothing.
    files = {"demo/__init__.py": "def run():\n    return 1\n", "demo/plugins.py": "x = __import__('demo.cli')\n", "demo/cli.py": NETWORK}
    quiet = judge(tmp_path / "b", [("demo", "1.0", files)], {"app.py": "import demo\ndemo.run()\n"})
    assert outcome(quiet) == ("OK", "NO_DENIED_SINK_REACHABLE") and quiet["widened_by"] == []


def test_a_sink_outside_any_importable_module_counts_as_reachable(tmp_path):
    files = {"demo/__init__.py": "def run():\n    return 1\n", "demo-1.0.data/scripts/tool.py": "import os\nos.system('id')\n"}
    nodes = [node(build_wheel(tmp_path / "w", "demo", "1.0", files=files), "demo", "1.0")]
    context = extract_project_context(project(tmp_path, {"app.py": "import demo\ndemo.run()\n"}))
    contract = infer_capability_contract(nodes[0]["metadata"], context, POLICY)
    result = judge_sinks(nodes, [scan_wheel(n["path"]) for n in nodes], contract, context)
    assert outcome(result) == ("UNRESOLVED", "SINK_REACHABLE")
    assert result["sinks"][0]["module"] is None and result["sinks"][0]["verdict"] == "REACHABLE"


def test_unreadable_wheel_means_no_sink_can_be_called_unreachable(tmp_path):
    files = {"demo/__init__.py": "def run():\n    return 1\n", "demo/cli.py": NETWORK}
    wheel = build_wheel(tmp_path / "w", "demo", "1.0", files=files)
    nodes = [node(wheel, "demo", "1.0")]
    context = extract_project_context(project(tmp_path, {"app.py": "import demo\ndemo.run()\n"}))
    contract = infer_capability_contract(nodes[0]["metadata"], context, POLICY)
    scans = [scan_wheel(wheel)]
    wheel.write_bytes(b"not a zip any more")
    result = judge_sinks(nodes, scans, contract, context)
    assert outcome(result) == ("UNRESOLVED", "SINK_REACHABLE") and verdicts(result) == [("demo/cli.py", 5, "REACHABLE")]
    assert import_graph(nodes)["complete"] is False


def test_nodes_and_scans_must_match(tmp_path):
    with pytest.raises(ValueError):
        judge_sinks([{"name": "a", "version": "1", "path": "x"}], [], {"allowed": [], "entry_modules": []}, {})


# --- the pypdf guard: the one reachability proof ------------------------------------------------------------

@functools.lru_cache(maxsize=1)
def pypdf_scan():
    """The scan of the real wheel takes about a second and does not depend on the project, so it is done once."""
    return scan_wheel(PYPDF_WHEEL)


def pypdf_judgement(tmp_path, project_files):
    nodes = [node(PYPDF_WHEEL, "pypdf", "6.19.0")]
    context = extract_project_context(project(tmp_path, project_files))
    contract = infer_capability_contract(nodes[0]["metadata"], context, POLICY)
    assert contract["result"] == "OK", contract["reason"]
    return judge_sinks(nodes, [pypdf_scan()], contract, context), context


def reused_guard_alone(context):
    """What `fast_gate.disabled_jbig2_sinks` says on its own, given the same project files."""
    import zipfile
    with zipfile.ZipFile(PYPDF_WHEEL) as archive:
        source = archive.read("pypdf/filters.py").decode()
    return disabled_jbig2_sinks({"sources": {"pypdf/filters.py": source}}, ProjectSources(context))


def test_pypdf_sinks_are_disabled_when_every_reader_is_inside_the_guard(tmp_path):
    result, context = pypdf_judgement(tmp_path, {"app/pdf.py": GUARDED, "app/other.py": "import json\n"})
    assert outcome(result) == ("OK", "NO_DENIED_SINK_REACHABLE")
    assert verdicts(result) == [("pypdf/filters.py", 774, "GUARD_DISABLED"), ("pypdf/filters.py", 804, "GUARD_DISABLED")]
    proof = result["proofs"][0]
    assert proof["id"] == "pypdf-jbig2dec-disabled" and proof["accepted"] is True and proof["lines"] == [774, 804]
    assert proof["guard_result"] == reused_guard_alone(context) == [774, 804]
    # Without the proof the two calls are reachable: pypdf/__init__ imports the reader, which imports the filters.
    assert "pypdf.filters" in result["reachable_modules"]


UNGUARDED_CASES = {
    "reader outside the with block": GUARDED + "\n\ndef quick(path):\n    return PdfReader(path)\n",
    "guard with another value": GUARDED.replace("jbig2dec_binary=None", "jbig2dec_binary='/usr/bin/jbig2dec'"),
    "no guard at all": "from pypdf import PdfReader\n\n\ndef extract(path):\n    return PdfReader(path)\n",
    "guard overridden inside": GUARDED.replace(
        "        reader = PdfReader(BytesIO(content))",
        "        with apply_configuration(jbig2dec_binary='x'):\n            reader = PdfReader(BytesIO(content))"),
    "guard with an extra argument": GUARDED.replace("jbig2dec_binary=None", "jbig2dec_binary=None, **options"),
}


@pytest.mark.parametrize("label", sorted(UNGUARDED_CASES))
def test_pypdf_sinks_are_reachable_without_the_guard(tmp_path, label):
    result, _ = pypdf_judgement(tmp_path, {"app/pdf.py": UNGUARDED_CASES[label]})
    assert outcome(result) == ("UNRESOLVED", "SINK_REACHABLE"), label
    assert verdicts(result) == [("pypdf/filters.py", 774, "REACHABLE"), ("pypdf/filters.py", 804, "REACHABLE")]
    assert result["proofs"][0]["accepted"] is False and result["proofs"][0]["lines"] == []


# Entries into pypdf that `disabled_jbig2_sinks` does not see, because it only looks for the text `PdfReader(`.
UNSEEN_BY_THE_REUSED_GUARD = {
    "attribute call in another file": {"app/pdf.py": GUARDED, "app/quick.py": "import pypdf\n\n\ndef quick(p):\n    return pypdf.PdfReader(p)\n"},
    "aliased reader": {"app/pdf.py": GUARDED, "app/quick.py": "from pypdf import PdfReader as R\n\n\ndef quick(p):\n    return R(p)\n"},
    "another pypdf entry point": {"app/pdf.py": GUARDED, "app/w.py": "from pypdf import PdfWriter\n\n\ndef copy(p):\n    return PdfWriter(clone_from=p)\n"},
    "reader passed around uncalled": {"app/pdf.py": GUARDED + "\n\nFACTORY = PdfReader\n"},
    "reader counted twice by nested guards": {"app/pdf.py": GUARDED.replace(
        "        reader = PdfReader(BytesIO(content))",
        "        with apply_configuration(jbig2dec_binary=None):\n            reader = PdfReader(BytesIO(content))")
        + "\n\ndef quick(path):\n    return PdfReader(path)\n"},
}


@pytest.mark.parametrize("label", sorted(UNSEEN_BY_THE_REUSED_GUARD))
def test_the_proof_is_refused_when_the_project_enters_pypdf_in_a_way_the_guard_does_not_see(tmp_path, label):
    result, context = pypdf_judgement(tmp_path, UNSEEN_BY_THE_REUSED_GUARD[label])
    # The reused guard on its own still answers "disabled" for these projects ...
    assert reused_guard_alone(context) == [774, 804], label
    # ... so the pipeline adds its own conditions and does not accept the proof.
    assert result["proofs"][0]["accepted"] is False and result["proofs"][0]["guard_result"] == [774, 804]
    assert outcome(result) == ("UNRESOLVED", "SINK_REACHABLE")


def test_the_proof_covers_only_the_lines_the_guard_returns(tmp_path):
    """A sink anywhere else in a wheel named pypdf is judged like any other sink."""
    files = {"pypdf/__init__.py": "from . import extra\n\n\ndef PdfReader(x):\n    return x\n\n\ndef apply_configuration(**k):\n    return k\n",
             "pypdf/extra.py": NETWORK}
    nodes = [node(build_wheel(tmp_path / "w", "pypdf", "9.9", files=files), "pypdf", "9.9")]
    context = extract_project_context(project(tmp_path, {"app/pdf.py": GUARDED}))
    contract = infer_capability_contract(nodes[0]["metadata"], context, POLICY)
    result = judge_sinks(nodes, [scan_wheel(n["path"]) for n in nodes], contract, context)
    assert verdicts(result) == [("pypdf/extra.py", 5, "REACHABLE")]
    # This wheel has no pypdf/filters.py with the guarded decoder, so there is nothing to prove.
    assert result["proofs"][0]["accepted"] is False


def test_project_sources_adapter_serves_every_file_and_checks_its_hash(tmp_path):
    root = project(tmp_path, {"app/pdf.py": GUARDED, "tools/x.py": "x = 1\n"})
    context = extract_project_context(root)
    sources = ProjectSources(context)
    assert sorted(sources.manifest) == ["app/app/pdf.py", "app/tools/x.py"]
    assert sources.read("app/app/pdf.py") == GUARDED.encode()
    (root / "app" / "pdf.py").write_text(GUARDED + "# changed after it was hashed\n")
    with pytest.raises(ValueError):
        sources.read("app/app/pdf.py")
    with pytest.raises(KeyError):
        sources.read("app/elsewhere.py")


def test_file_changed_after_the_context_was_read_refuses_the_proof(tmp_path):
    root = project(tmp_path, {"app/pdf.py": GUARDED})
    context = extract_project_context(root)
    nodes = [node(PYPDF_WHEEL, "pypdf", "6.19.0")]
    contract = infer_capability_contract(nodes[0]["metadata"], context, POLICY)
    (root / "app" / "pdf.py").write_text(GUARDED + "\n\ndef quick(path):\n    return PdfReader(path)\n")
    result = judge_sinks(nodes, [pypdf_scan()], contract, context)
    assert result["proofs"][0]["accepted"] is False and outcome(result) == ("UNRESOLVED", "SINK_REACHABLE")


# --- review of steps 9-11: project shapes for which the proof was accepted and must not be ------------------------

READER_AFTER_THE_BLOCK = '''from pypdf import PdfReader, apply_configuration


def extract(path):
    with apply_configuration(jbig2dec_binary=None):
        reader = PdfReader(path)
    return [page.extract_text() for page in reader.pages]
'''
HELPER = "from pypdf import PdfReader, apply_configuration\n"
STILL_REFUSED = {
    # BLOCKER 4a: a guard that is not pypdf's.
    "local do-nothing apply_configuration": {"app/pdf.py": "from contextlib import contextmanager\nfrom pypdf import PdfReader\n\n\n"
        "@contextmanager\ndef apply_configuration(**settings):\n    yield\n\n\ndef extract(p):\n"
        "    with apply_configuration(jbig2dec_binary=None):\n        reader = PdfReader(p)\n        return len(reader.pages)\n"},
    "apply_configuration from another package": {"app/pdf.py": "from other import apply_configuration\nfrom pypdf import PdfReader\n\n\n"
        "def extract(p):\n    with apply_configuration(jbig2dec_binary=None):\n        reader = PdfReader(p)\n        return len(reader.pages)\n"},
    "pypdf guard hidden by a local function of the same name": {"app/pdf.py": GUARDED + "\n\ndef apply_configuration(**settings):\n    return open('x')\n"},
    # BLOCKER 4b: the reader re-exported by a project module.
    "reader re-exported, attribute call": {"app/pdf.py": GUARDED, "app/main.py": "from app import pdf\n\n\ndef quick(p):\n    return pdf.PdfReader(p)\n"},
    "reader re-exported, aliased": {"app/pdf.py": GUARDED, "app/main.py": "from app.pdf import PdfReader as R\n\n\ndef quick(p):\n    return R(p)\n"},
    "reader re-exported, star import": {"app/pdf.py": GUARDED, "app/main.py": "from app.pdf import *\n\n\ndef quick(p):\n    return PdfReader(p)\n"},
    "names that cannot be traced to pypdf": {"app/pdf.py": GUARDED, "app/main.py": "from app.pdf import *\n\n\ndef count(p):\n"
        "    with apply_configuration(jbig2dec_binary=None):\n        reader = PdfReader(p)\n        return len(reader.pages)\n"},
    # BLOCKER 4d: written inside the block, run after it.
    "reader in a lambda": {"app/pdf.py": HELPER + "\n\ndef later(p):\n    with apply_configuration(jbig2dec_binary=None):\n        return lambda: PdfReader(p)\n"},
    "reader in a nested function": {"app/pdf.py": HELPER + "\n\ndef later(p):\n    with apply_configuration(jbig2dec_binary=None):\n"
        "        def make():\n            reader = PdfReader(p)\n            return len(reader.pages)\n        return make\n"},
    "reader in a generator expression": {"app/pdf.py": HELPER + "\n\ndef later(paths):\n    with apply_configuration(jbig2dec_binary=None):\n"
        "        return (PdfReader(p) for p in paths)\n"},
    # BLOCKER 5: the reader object leaves the block; pypdf decodes pages when they are read.
    "pages read after the block": {"app/pdf.py": READER_AFTER_THE_BLOCK},
    "reader returned": {"app/pdf.py": HELPER + "\n\ndef load(p):\n    with apply_configuration(jbig2dec_binary=None):\n        reader = PdfReader(p)\n        return reader\n"},
    "reader stored on an object": {"app/pdf.py": HELPER + "\n\nclass Doc:\n    def load(self, p):\n        with apply_configuration(jbig2dec_binary=None):\n"
        "            reader = PdfReader(p)\n            self.reader = reader\n"},
    "reader passed to other code": {"app/pdf.py": HELPER + "\n\ndef load(p, keep):\n    with apply_configuration(jbig2dec_binary=None):\n"
        "        reader = PdfReader(p)\n        keep(reader)\n"},
    "reader not bound to a name": {"app/pdf.py": HELPER + "\n\ndef pages(p):\n    with apply_configuration(jbig2dec_binary=None):\n        return PdfReader(p).pages\n"},
    "reader used lazily in a generator expression": {"app/pdf.py": HELPER + "\n\ndef pages(p):\n    with apply_configuration(jbig2dec_binary=None):\n"
        "        reader = PdfReader(p)\n        return (reader.pages[i] for i in range(3))\n"},
    "reader captured by a closure": {"app/pdf.py": HELPER + "\n\ndef pages(p):\n    with apply_configuration(jbig2dec_binary=None):\n"
        "        reader = PdfReader(p)\n        return lambda: reader.pages\n"},
    "reader made global": {"app/pdf.py": HELPER + "\n\ndef load(p):\n    global reader\n    with apply_configuration(jbig2dec_binary=None):\n"
        "        reader = PdfReader(p)\n"},
}


@pytest.mark.parametrize("label", sorted(STILL_REFUSED))
def test_project_shapes_the_first_version_of_the_proof_accepted(tmp_path, label):
    result, _ = pypdf_judgement(tmp_path, STILL_REFUSED[label])
    proof = result["proofs"][0]
    assert proof["accepted"] is False and proof["lines"] == [], (label, proof["reason"])
    assert outcome(result) == ("UNRESOLVED", "SINK_REACHABLE")


ACCEPTED_SHAPES = {
    "the InvoiceHub adapter": None,  # read from demo_project/InvoiceHub/app/pdf_adapter.py in the test
    "reader used in two guard blocks": HELPER + "\n\ndef extract(p):\n    with apply_configuration(jbig2dec_binary=None):\n        reader = PdfReader(p)\n"
        "        first = reader.pages[0].extract_text()\n    with apply_configuration(jbig2dec_binary=None):\n        return first + str(len(reader.pages))\n",
    "two readers in two functions": GUARDED + "\n\ndef count(path):\n    with apply_configuration(jbig2dec_binary=None):\n"
        "        reader = PdfReader(path)\n        return len(reader.pages)\n",
}


@pytest.mark.parametrize("label", sorted(ACCEPTED_SHAPES))
def test_project_shapes_for_which_the_proof_holds(tmp_path, label):
    from test_cavr_support import REPO
    source = ACCEPTED_SHAPES[label] or (REPO / "demo_project" / "InvoiceHub" / "app" / "pdf_adapter.py").read_text()
    result, _ = pypdf_judgement(tmp_path, {"app/pdf.py": source})
    proof = result["proofs"][0]
    assert proof["accepted"] is True and proof["lines"] == [774, 804], proof["reason"]
    assert "used after the block" in proof["limit"]
    assert outcome(result) == ("OK", "NO_DENIED_SINK_REACHABLE")


def test_pypdf_as_a_dependency_is_not_covered_by_the_projects_own_guard(tmp_path):
    """Review BLOCKER 4c: the wheel that was asked for calls PdfReader itself, outside any guard of the project."""
    root = build_wheel(tmp_path / "w", "top", "1.0", files={"top/__init__.py": "from pypdf import PdfReader\n\n\ndef run(p):\n    return PdfReader(p).pages\n"})
    nodes = [node(root, "top", "1.0"), node(PYPDF_WHEEL, "pypdf", "6.19.0")]
    context = extract_project_context(project(tmp_path, {"app/pdf.py": GUARDED, "app/main.py": "import top\n\ntop.run('a.pdf')\n"}))
    contract = infer_capability_contract(nodes[0]["metadata"], context, POLICY)
    assert contract["result"] == "OK", contract["reason"]
    result = judge_sinks(nodes, [scan_wheel(root), pypdf_scan()], contract, context)
    assert result["proofs"][0]["accepted"] is False and "dependency" in result["proofs"][0]["reason"]
    assert outcome(result) == ("UNRESOLVED", "SINK_REACHABLE")
