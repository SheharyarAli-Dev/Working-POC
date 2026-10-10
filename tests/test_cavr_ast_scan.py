"""C3 light AST risk scan of wheel sources (plan step 8). Every wheel is a real zip; nothing is executed."""
import zipfile

import pytest

from backend.cavr import ast_scan
from backend.cavr.ast_scan import scan_wheel
from test_cavr_support import PYPDF_WHEEL, build_wheel

CLEAN = '''"""A module with nothing sensitive."""
import json


def load(text):
    return json.loads(text)
'''

ENV_GATED_SOCKET = '''import os
import socket


def ping():
    if os.getenv("DEPLOY_ENV") == "prod":
        socket.create_connection(("example.invalid", 443))
    return True
'''


def outcome(result):
    return result["result"], result["rule"]


def wheel(tmp_path, files, **args):
    return build_wheel(tmp_path, "demo", "1.0", files=files, **args)


def kinds(result):
    return sorted(finding["kind"] for finding in result["findings"])


# --- clean module ---------------------------------------------------------------------------------

def test_clean_module_has_no_findings(tmp_path):
    result = scan_wheel(wheel(tmp_path, {"demo/__init__.py": CLEAN, "demo/data.json": "{}"}))
    assert outcome(result) == ("OK", "SCAN_COMPLETE")
    assert result["findings"] == [] and result["sinks"] == [] and result["triggers"] == []
    assert result["python_files"] == 1 and result["files_scanned"] == ["demo/__init__.py"]
    assert result["bytes_scanned"] == len(CLEAN)
    assert result["analyzer_version"] == ast_scan.ANALYZER_VERSION and len(result["rules_digest"]) == 64


def test_wheel_without_python_files_is_complete_and_empty(tmp_path):
    result = scan_wheel(wheel(tmp_path, {"demo/data.txt": "hello"}))
    assert outcome(result) == ("OK", "SCAN_COMPLETE") and result["python_files"] == 0


# --- env-gated socket -------------------------------------------------------------------------------

def test_env_gated_socket_is_a_trigger_and_a_sink(tmp_path):
    result = scan_wheel(wheel(tmp_path, {"demo/__init__.py": "", "demo/net.py": ENV_GATED_SOCKET}))
    assert outcome(result) == ("OK", "SCAN_COMPLETE")
    assert result["sinks"] == [{"file": "demo/net.py", "line": 7, "sink": "socket.create_connection",
                                "capability": "NETWORK_CONNECT", "rule_id": "BEH-NETWORK_CONNECT", "via_alias": False}]
    assert len(result["triggers"]) == 1
    trigger = result["triggers"][0]
    assert (trigger["file"], trigger["line"]) == ("demo/net.py", 6)
    assert trigger["inputs"] == ["DEPLOY_ENV"] and trigger["trigger_type"] == ["environment-variable"]
    assert trigger["reachable_sinks"] == [{"sink": "socket.create_connection", "capability": "NETWORK_CONNECT", "line": 7}]
    assert kinds(result) == ["SINK", "TRIGGER"]


def test_ungated_sinks_are_listed_with_their_capability(tmp_path):
    source = "import os, subprocess\nos.system('id')\nsubprocess.run(['id'])\neval('1')\n"
    result = scan_wheel(wheel(tmp_path, {"demo/__init__.py": source}))
    assert [(sink["line"], sink["sink"], sink["capability"]) for sink in result["sinks"]] == [
        (2, "os.system", "PROCESS_CREATE"), (3, "subprocess.run", "PROCESS_CREATE"), (4, "eval", "NATIVE_EXEC")]
    assert result["triggers"] == []


@pytest.mark.parametrize("source, sink, line", [
    ("import socket as s\ns.create_connection(('h', 1))\n", "socket.create_connection", 2),
    ("from subprocess import run\nrun(['id'])\n", "subprocess.run", 2),
    ("from os import system as sh\n\n\nsh('id')\n", "os.system", 4),
    ("import urllib.request as r\nr.urlopen('http://h')\n", "urllib.request.urlopen", 2),
    ("from urllib import request\nrequest.urlopen('http://h')\n", "urllib.request.urlopen", 2),
    ("def f():\n    import subprocess as sp\n    sp.Popen('id')\n", "subprocess.Popen", 3),
    ("import builtins\nbuiltins.exec('1')\n", "exec", 2),
])
def test_sink_called_through_an_import_alias_is_still_found(tmp_path, source, sink, line):
    result = scan_wheel(wheel(tmp_path, {"demo/__init__.py": source}))
    assert outcome(result) == ("OK", "SCAN_COMPLETE")
    assert [(s["sink"], s["line"], s["via_alias"]) for s in result["sinks"]] == [(sink, line, True)]


def test_a_local_function_with_a_sink_like_name_is_not_a_sink(tmp_path):
    source = "def run(x):\n    return x\n\n\nclass system:\n    pass\n\n\nrun(1)\nsystem()\n"
    assert scan_wheel(wheel(tmp_path, {"demo/__init__.py": source}))["sinks"] == []


def test_dynamic_import_and_compile_are_reported(tmp_path):
    source = "import importlib\nm = importlib.import_module('o' + 's')\n__import__('subprocess')\ncompile('1', 'x', 'eval')\n"
    result = scan_wheel(wheel(tmp_path, {"demo/__init__.py": source}))
    assert outcome(result) == ("OK", "SCAN_COMPLETE")
    assert [(f["line"], f["call"]) for f in result["dynamic_code"]] == [
        (2, "importlib.import_module"), (3, "__import__"), (4, "compile")]
    assert kinds(result) == ["DYNAMIC_CODE"] * 3


# --- the real pypdf wheel ---------------------------------------------------------------------------------

def test_pypdf_wheel_scan():
    result = scan_wheel(PYPDF_WHEEL)
    assert outcome(result) == ("OK", "SCAN_COMPLETE")
    assert result["python_files"] == 59
    # The two calls to the optional jbig2dec binary; `fast_gate.disabled_jbig2_sinks` is about these lines.
    assert [(s["file"], s["line"], s["sink"]) for s in result["sinks"]] == [
        ("pypdf/filters.py", 774, "subprocess.run"), ("pypdf/filters.py", 804, "subprocess.run")]
    assert result["triggers"] == [] and result["parse_errors"] == []
    assert result["native_files"] == [] and result["pth_files"] == []


# --- syntax error and other unparseable sources -> UNRESOLVED ------------------------------------------------

def test_syntax_error_is_an_explicit_finding_and_unresolved(tmp_path):
    files = {"demo/__init__.py": CLEAN, "demo/broken.py": "def broken(:\n    pass\n", "demo/net.py": ENV_GATED_SOCKET}
    result = scan_wheel(wheel(tmp_path, files))
    assert outcome(result) == ("UNRESOLVED", "SOURCE_NOT_PARSED")
    assert [error["file"] for error in result["parse_errors"]] == ["demo/broken.py"]
    assert "demo/broken.py" in result["reason"]
    # The files that do parse are still scanned.
    assert [sink["file"] for sink in result["sinks"]] == ["demo/net.py"]
    assert "PARSE_ERROR" in kinds(result)


@pytest.mark.parametrize("data", [
    b"x = 1\n\x00\n",                                  # NUL byte
    b"# -*- coding: utf-8 -*-\nname = '\xff\xfe'\n",    # not valid UTF-8
    b"# -*- coding: no-such-codec -*-\nx = 1\n",
    b"print 'python 2 only'\n",
    ("x = " + "(" * 5000 + "1" + ")" * 5000 + "\n").encode(),
])
def test_source_that_cannot_be_parsed_is_unresolved(tmp_path, data):
    result = scan_wheel(wheel(tmp_path, {"demo/__init__.py": "", "demo/odd.py": data}))
    assert outcome(result) == ("UNRESOLVED", "SOURCE_NOT_PARSED")
    assert [error["file"] for error in result["parse_errors"]] == ["demo/odd.py"]


def test_source_with_a_declared_encoding_is_decoded_with_it(tmp_path):
    data = "# -*- coding: latin-1 -*-\nname = 'café'\nimport os\nos.system(name)\n".encode("latin-1")
    result = scan_wheel(wheel(tmp_path, {"demo/__init__.py": data}))
    assert outcome(result) == ("OK", "SCAN_COMPLETE") and [s["line"] for s in result["sinks"]] == [4]


# --- native code and .pth -> UNRESOLVED ---------------------------------------------------------------------

def test_so_present_is_an_explicit_finding_and_unresolved(tmp_path):
    files = {"demo/__init__.py": CLEAN, "demo/_speed.cpython-312-x86_64-linux-gnu.so": b"\x7fELF\x02\x01\x01"}
    result = scan_wheel(wheel(tmp_path, files))
    assert outcome(result) == ("UNRESOLVED", "COMPILED_CODE_NOT_SCANNED")
    assert result["native_files"] == ["demo/_speed.cpython-312-x86_64-linux-gnu.so"]
    assert kinds(result) == ["NATIVE_EXTENSION"]
    assert result["files_scanned"] == ["demo/__init__.py"]


@pytest.mark.parametrize("name", ["demo/win.pyd", "demo/lib.dll", "demo/mac.dylib", "demo/libz.so.1", "demo/only.pyc",
                                  "demo/__pycache__/x.cpython-312.pyc"])
def test_other_compiled_files_are_unresolved_too(tmp_path, name):
    result = scan_wheel(wheel(tmp_path, {"demo/__init__.py": CLEAN, name: b"\x00\x01"}))
    assert outcome(result) == ("UNRESOLVED", "COMPILED_CODE_NOT_SCANNED")


def test_pth_file_that_executes_code_is_unresolved_and_its_code_is_scanned(tmp_path):
    pth = "# a comment\n./src\nimport os; os.system('id')\n"
    result = scan_wheel(wheel(tmp_path, {"demo/__init__.py": CLEAN, "demo-hook.pth": pth}))
    assert outcome(result) == ("UNRESOLVED", "PTH_EXECUTES_CODE")
    assert result["pth_files"] == [{"file": "demo-hook.pth", "executable_lines": [3], "path_lines": 1}]
    assert [(s["file"], s["line"], s["sink"]) for s in result["sinks"]] == [("demo-hook.pth", 3, "os.system")]
    assert "PTH_EXECUTABLE" in kinds(result)


def test_pth_file_with_only_paths_is_a_finding_but_the_scan_is_complete(tmp_path):
    result = scan_wheel(wheel(tmp_path, {"demo/__init__.py": CLEAN, "demo.pth": "src\nimportant_dir\n"}))
    assert outcome(result) == ("OK", "SCAN_COMPLETE")
    assert result["pth_files"] == [{"file": "demo.pth", "executable_lines": [], "path_lines": 2}]
    assert kinds(result) == ["PTH_FILE"]


def test_pth_import_line_that_does_not_parse_is_unresolved(tmp_path):
    result = scan_wheel(wheel(tmp_path, {"demo/__init__.py": "", "x.pth": "import os; (\n"}))
    assert outcome(result) == ("UNRESOLVED", "SOURCE_NOT_PARSED")


def test_several_problems_are_all_listed_and_the_rule_is_the_first_in_order(tmp_path):
    files = {"demo/__init__.py": "def broken(:\n", "demo/x.so": b"\x7fELF", "y.pth": "import sys\n"}
    result = scan_wheel(wheel(tmp_path, files))
    assert outcome(result) == ("UNRESOLVED", "SOURCE_NOT_PARSED")
    assert kinds(result) == ["NATIVE_EXTENSION", "PARSE_ERROR", "PTH_EXECUTABLE"]


# --- budgets and bad archives ------------------------------------------------------------------------------------

def test_source_file_over_the_size_budget_is_unresolved(tmp_path, monkeypatch):
    monkeypatch.setattr(ast_scan, "MAX_SOURCE_BYTES", 50)
    result = scan_wheel(wheel(tmp_path, {"demo/__init__.py": "x = 1\n", "demo/big.py": "y = 2\n" * 20}))
    assert outcome(result) == ("UNRESOLVED", "SCAN_BUDGET")
    assert result["files_scanned"] == ["demo/__init__.py"]


def test_total_source_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(ast_scan, "MAX_TOTAL_SOURCE_BYTES", 30)
    files = {f"demo/m{i}.py": "value = 12345\n" for i in range(4)}
    result = scan_wheel(wheel(tmp_path, files))
    assert outcome(result) == ("UNRESOLVED", "SCAN_BUDGET")
    assert len(result["files_scanned"]) == 2


def test_not_a_wheel_is_unresolved(tmp_path):
    path = tmp_path / "demo-1.0-py3-none-any.whl"
    path.write_bytes(b"not a zip")
    assert outcome(scan_wheel(path)) == ("UNRESOLVED", "NOT_A_WHEEL")
    assert outcome(scan_wheel(tmp_path / "missing.whl")) == ("UNRESOLVED", "NOT_A_WHEEL")
    assert outcome(scan_wheel(None)) == ("UNRESOLVED", "NOT_A_WHEEL")


def test_archive_checks_of_step_5_apply(tmp_path):
    built = wheel(tmp_path, {"demo/__init__.py": CLEAN})
    with zipfile.ZipFile(built, "a") as archive:
        archive.writestr("../evil.py", "import os\n")
    assert outcome(scan_wheel(built)) == ("REJECTED", "UNSAFE_PATH")


def test_zip_bomb_is_not_decompressed(tmp_path):
    bomb = wheel(tmp_path, {"demo/__init__.py": b"#" * (30 * 1024 * 1024)}, record=False)
    result = scan_wheel(bomb)
    assert outcome(result) == ("UNRESOLVED", "ZIP_BUDGET") and result["bytes_scanned"] == 0


def test_scanner_crash_on_one_file_is_unresolved_not_an_exception(tmp_path, monkeypatch):
    real = ast_scan.scan

    def flaky(sources, knowledge=None):
        if "demo/bad.py" in sources:
            raise RuntimeError("rule engine failure")
        return real(sources, knowledge)

    monkeypatch.setattr(ast_scan, "scan", flaky)
    result = scan_wheel(wheel(tmp_path, {"demo/__init__.py": ENV_GATED_SOCKET, "demo/bad.py": "x = 1\n"}))
    assert outcome(result) == ("UNRESOLVED", "SOURCE_NOT_PARSED")
    assert result["parse_errors"] == [{"file": "demo/bad.py", "error": "scanner failed: RuntimeError: rule engine failure"}]
    assert len(result["sinks"]) == 1


# --- shape, determinism, no execution --------------------------------------------------------------------------------

def test_scanning_does_not_execute_the_package(tmp_path):
    marker = tmp_path / "executed"
    source = f"open({str(marker)!r}, 'w').write('x')\n"
    result = scan_wheel(wheel(tmp_path, {"demo/__init__.py": source, "boot.pth": f"import demo\n"}))
    assert result["python_files"] == 1 and not marker.exists()


def test_same_wheel_gives_the_same_result(tmp_path):
    files = {"demo/b.py": ENV_GATED_SOCKET, "demo/a.py": "import os\nos.system('x')\n", "demo/__init__.py": ""}
    built = wheel(tmp_path, files)
    assert scan_wheel(built) == scan_wheel(built)
    assert [sink["file"] for sink in scan_wheel(built)["sinks"]] == ["demo/a.py", "demo/b.py"]


def test_rules_digest_changes_with_the_rules(tmp_path):
    built = wheel(tmp_path, {"demo/__init__.py": "import os\nos.system('x')\n"})
    default = scan_wheel(built)
    no_rules = scan_wheel(built, knowledge={"records": []})
    assert default["rules_digest"] != no_rules["rules_digest"]
    assert default["sinks"] and no_rules["sinks"] == []


def test_every_result_has_the_same_keys(tmp_path):
    good = scan_wheel(PYPDF_WHEEL)
    bad = scan_wheel(tmp_path / "missing.whl")
    assert set(good) == set(bad) and "coverage" in good
