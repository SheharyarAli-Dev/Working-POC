"""PR 12 of docs/cavr-m2-plan.md: which of the project's call sites the deep stage drives, and why not the others.

Every project here is real files in tmp_path; the hashes are computed from those files, as the project context does.
"""
import hashlib
import json

import pytest

from backend.cavr import call_drive


def project(tmp_path, files):
    root = tmp_path / "project"
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in files}
    return {"project_dir": str(root), "files": hashes}


def site(file, line, expression, symbol=None, kind="call"):
    return {"file": file, "line": line, "expression": expression, "symbol": symbol or expression, "kind": kind}


def package(proj, *sites):
    return {"contract": {"call_sites": list(sites)}, "project": proj}


def test_a_call_with_only_literals_is_driven_with_those_literals(tmp_path):
    proj = project(tmp_path, {"app/a.py": "import demo\n\n\ndef go():\n    return demo.send('x', 2, flag=True, n=(1, b'z'))\n"})
    got = call_drive.plan(package(proj, site("app/a.py", 5, "demo.send")))
    (drive,) = got["drives"]
    assert (drive["step"], drive["symbol"], drive["args"], drive["kwargs"]) == (
        "drive_1", "demo.send", ["'x'", "2"], {"flag": "True", "n": "(1, b'z')"})
    assert got["not_driven"] == [] and call_drive.describe(drive) == "demo.send('x', 2, flag=True, n=(1, b'z')) at app/a.py:5"
    job = json.loads(call_drive.drive_job(drive, ["demo"], ["-c"]))
    assert job == {"modules": ["demo"], "argv": ["-c"], "symbol": "demo.send", "args": ["'x'", "2"],
                   "kwargs": {"flag": "True", "n": "(1, b'z')"}}


def test_a_call_with_no_arguments_is_driven(tmp_path):
    proj = project(tmp_path, {"app/uses_demo.py": "import demo\n\n\ndef go():\n    return demo.run()\n"})
    (drive,) = call_drive.plan(package(proj, site("app/uses_demo.py", 5, "demo.run")))["drives"]
    assert (drive["args"], drive["kwargs"], drive["call"]) == ([], {}, "demo.run()")


def test_an_imported_name_keeps_the_real_symbol(tmp_path):
    proj = project(tmp_path, {"app/a.py": "from demo.net import send as s\n\ns('x')\n"})
    (drive,) = call_drive.plan(package(proj, site("app/a.py", 3, "s", "demo.net.send")))["drives"]
    assert drive["symbol"] == "demo.net.send" and drive["call"] == "s('x')"


@pytest.mark.parametrize("call, why", [
    ("demo.send(data)", "argument 1 `data` is not a literal"),
    ("demo.send(*items)", "argument 1 is `*items`"),
    ("demo.send(**options)", "`**options`"),
    ("demo.send(f'{x}')", "is not a literal"),
    ("demo.send(open('f'))", "is not a literal"),
    ("demo.send(x=compute())", "keyword `x` `compute()` is not a literal"),
])
def test_a_call_whose_arguments_are_not_literals_is_not_driven(tmp_path, call, why):
    proj = project(tmp_path, {"app/a.py": f"import demo\ndata = items = options = x = 1\n{call}\n"})
    got = call_drive.plan(package(proj, site("app/a.py", 3, "demo.send")))
    assert got["drives"] == []
    (refused,) = got["not_driven"]
    assert why in refused["why"] and refused["file"] == "app/a.py" and refused["line"] == 3


@pytest.mark.parametrize("call", [
    "demo.login('AKIAIOSFODNN7EXAMPLE')",
    "demo.login('ghp_0123456789abcdefghijklmnopqrstuvwxyz')",
    "demo.login(['ok', 'sk-proj-abcdef'])",
    "demo.login('-----BEGIN OPENSSH PRIVATE KEY-----')",
    "demo.login('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b')",
    "demo.login(user='me', password='hunter2')",
    "demo.login(api_key='short')",
])
def test_a_credential_is_never_passed_into_a_run(tmp_path, call):
    proj = project(tmp_path, {"app/a.py": f"import demo\n{call}\n"})
    got = call_drive.plan(package(proj, site("app/a.py", 2, "demo.login")))
    assert got["drives"] == [] and "NFR-5" in got["not_driven"][0]["why"]


@pytest.mark.parametrize("value", ["fixtures/invoice.pdf", "/tmp/out.txt", "https://example.invalid/api", "hello world",
                                   "build-prod-7", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"])
def test_ordinary_strings_are_not_taken_for_credentials(value):
    assert call_drive.looks_like_credential(value) is False


def test_a_decorator_is_not_driven(tmp_path):
    proj = project(tmp_path, {"app/a.py": "import demo\n\n\n@demo.register\ndef f():\n    pass\n"})
    got = call_drive.plan(package(proj, site("app/a.py", 4, "demo.register", kind="decorator")))
    assert got["drives"] == [] and "a decorator, not a call" in got["not_driven"][0]["why"]


def test_a_project_file_that_changed_is_not_driven(tmp_path):
    proj = project(tmp_path, {"app/a.py": "import demo\ndemo.run()\n"})
    (tmp_path / "project/app/a.py").write_text("import demo\ndemo.run('changed')\n")
    got = call_drive.plan(package(proj, site("app/a.py", 2, "demo.run")))
    assert got["drives"] == [] and "SHA-256 differs" in got["not_driven"][0]["why"]


@pytest.mark.parametrize("files, call_site, why", [
    ({"app/a.py": "import demo\ndemo.run()\n"}, site("app/a.py", 1, "demo.run"), "no call written `demo.run(...)` at line 1"),
    ({"app/a.py": "import demo\ndemo.run()\n"}, site("app/b.py", 2, "demo.run"), "cannot be read again"),
    ({"app/a.py": "import demo\ndemo.run()\n"}, site("app/a.py", None, "demo.run"), "no file, line or expression"),
    ({"app/a.py": "import demo\ndemo.run()\n"}, site("app/a.py", 2, "demo.run", "demo.ru n"), "cannot be resolved by name"),
])
def test_a_call_site_that_cannot_be_found_is_not_driven(tmp_path, files, call_site, why):
    got = call_drive.plan(package(project(tmp_path, files), call_site))
    assert got["drives"] == [] and why in got["not_driven"][0]["why"]


def test_two_calls_on_one_line_are_both_driven_and_repeats_are_dropped(tmp_path):
    proj = project(tmp_path, {"app/a.py": "import demo\ndemo.run(1); demo.run(2)\n", "app/b.py": "import demo\ndemo.run(1)\n"})
    got = call_drive.plan(package(proj, site("app/a.py", 2, "demo.run"), site("app/b.py", 2, "demo.run")))
    assert [d["args"] for d in got["drives"]] == [["1"], ["2"]] and got["not_driven"] == []


def test_at_most_four_calls_are_driven_in_file_and_line_order(tmp_path):
    source = "import demo\n" + "".join(f"demo.run({i})\n" for i in range(6))
    proj = project(tmp_path, {"app/a.py": source})
    sites = [site("app/a.py", line, "demo.run") for line in range(7, 1, -1)]  # given in reverse order
    got = call_drive.plan(package(proj, *sites))
    assert [d["args"] for d in got["drives"]] == [["0"], ["1"], ["2"], ["3"]]
    assert [d["step"] for d in got["drives"]] == ["drive_1", "drive_2", "drive_3", "drive_4"]
    assert [r["line"] for r in got["not_driven"]] == [6, 7] and all("limit of 4" in r["why"] for r in got["not_driven"])


def test_arguments_over_the_size_limit_are_not_driven(tmp_path):
    proj = project(tmp_path, {"app/a.py": f"import demo\ndemo.run('{'a b ' * 2000}')\n"})
    got = call_drive.plan(package(proj, site("app/a.py", 2, "demo.run")))
    assert got["drives"] == [] and "over 4096 bytes" in got["not_driven"][0]["why"]


def test_no_project_or_no_call_sites_drives_nothing_and_never_raises():
    assert call_drive.plan({})["drives"] == []
    assert call_drive.plan({"contract": {"call_sites": [site("a.py", 1, "x")]}, "project": None})["drives"] == []
    broken = call_drive.plan({"contract": {"call_sites": 5}})
    assert broken["drives"] == [] and "failed" in broken["not_driven"][0]["why"]


def test_the_driver_catches_everything_and_ends_with_os_exit():
    code = call_drive.DRIVE_CODE
    compile(code, "<drive>", "exec")
    assert "except BaseException" in code and code.rstrip().endswith("os._exit(0)")
    assert call_drive.DRIVE_ARGV[:5] == ["/usr/local/bin/python", "-I", "-S", "-B", "-c"]
