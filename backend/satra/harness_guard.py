"""Tripwire for head changes that could steer SATRA's trusted pytest run (docs/satra/harness-isolation.md, step 3).

`suspicious(base_dir, head_dir)` compares the two snapshots (`hashing.manifest`, so `.asent/` and generated
folders are left out) and lists every file the head ADDS or CHANGES that:

- is a native extension module: the name ends (any letter case) with a suffix in
  importlib.machinery.EXTENSION_SUFFIXES or with .so, .pyd or .dylib, in any folder. Python's import system
  prefers an extension module over the .py file of the same name, so one can replace any module;
- is named conftest.py, or is the module pytest / _pytest / sitecustomize / usercustomize (any extension), or
  lies inside a pytest/ or _pytest/ folder;
- is a .pth file;
- is a pytest settings file (pytest.ini, .pytest.ini, pytest.toml, .pytest.toml), or changes the pytest section
  of pyproject.toml ([tool.pytest] / [tool.pytest.ini_options]), tox.ini ([pytest]) or setup.cfg ([tool:pytest]);
- is Python code that imports _pytest (import, from-import, __import__/import_module with a literal name), binds
  `sys.modules` by name, or writes it (assignment, deletion, or a mutating method call) — checked in EVERY .py file,
  test-named ones included, because a file under tests/ can still be imported by code under test;
- is non-test Python code that imports pytest itself. Test files (under tests/ or test/, test_*.py, *_test.py) are
  exempt from this one check only, since test code normally imports pytest.

A head file that cannot be read or parsed is listed too: it cannot be shown harmless. Deleted files are not
listed (a head file is never loaded into the trusted run). This is a heuristic tripwire for human review, not
a proof: code can reach the same effect in ways a static check cannot see (see the stated limit in
docs/satra/threat-model.md). Step 1's isolation is the control; this only makes attempts visible.
"""
from __future__ import annotations

import ast
import configparser
import tomllib
from importlib.machinery import EXTENSION_SUFFIXES
from pathlib import Path, PurePosixPath

from backend.orchestrator.hashing import manifest

REASON = "test-harness tampering suspected"
HARNESS_MODULES = {"pytest", "_pytest", "sitecustomize", "usercustomize"}
HARNESS_DIRS = {"pytest", "_pytest"}
PUBLIC_PYTEST = "pytest"
SETTINGS_FILES = {"pytest.ini", ".pytest.ini", "pytest.toml", ".pytest.toml"}
SECTION_FILES = {"pyproject.toml", "tox.ini", "setup.cfg"}
TEST_DIRS = {"tests", "test"}
NATIVE_SUFFIXES = tuple(sorted({suffix.lower() for suffix in EXTENSION_SUFFIXES} | {".so", ".pyd", ".dylib"}))
MUTATORS = {"__setitem__", "__delitem__", "update", "setdefault", "pop", "popitem", "clear"}


def suspicious(base_dir, head_dir) -> list[dict]:
    """[{path, why, label}] for each added or changed head file that touches the test harness.

    `label` is what the gate reason lists: "native module <path>" for a native module, else the path."""
    base_dir, head_dir = Path(base_dir), Path(head_dir)
    try:
        old, new = manifest(base_dir), manifest(head_dir)
    except (OSError, ValueError) as error:
        return [{"path": ".", "why": "base and head could not be compared: " + str(error), "label": "."}]
    found = []
    for path in sorted(name for name, sha in new.items() if old.get(name) != sha):
        if path.lower().endswith(NATIVE_SUFFIXES):
            found.append({"path": path, "why": "native module " + path, "label": "native module " + path})
            continue
        why = _why(path, base_dir if path in old else None, head_dir)
        if why:
            found.append({"path": path, "why": why, "label": path})
    return found


def _why(path, base_dir, head_dir):
    parts = PurePosixPath(path).parts
    name = parts[-1]
    if name == "conftest.py":
        return "adds or changes a conftest.py"
    if name.split(".")[0] in HARNESS_MODULES and name not in SETTINGS_FILES:
        return "adds or changes a module named " + name.split(".")[0]
    if HARNESS_DIRS & set(parts[:-1]):
        return "adds or changes a file inside a pytest/ or _pytest/ folder"
    if name.endswith(".pth"):
        return "adds or changes a .pth file"
    if name in SETTINGS_FILES:
        return "adds or changes a pytest settings file"
    if name in SECTION_FILES:
        try:
            before = _section(base_dir / path, name) if base_dir is not None else None
            after = _section(head_dir / path, name)
        except ValueError as error:
            return "pytest settings in %s cannot be read: %s" % (name, error)
        return "changes the pytest settings in " + name if before != after else None
    if name.endswith(".py"):
        return _code(head_dir / path, test_file=_is_test(parts))
    return None


def _section(path, name):
    """The pytest settings of one file, normalised for comparison; None when it has none."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ValueError(str(error)) from None
    if name == "pyproject.toml":
        try:
            table = tomllib.loads(text).get("tool", {}).get("pytest")
        except tomllib.TOMLDecodeError as error:
            raise ValueError(str(error)) from None
        return table if table else None
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error as error:
        raise ValueError(str(error).splitlines()[0]) from None
    section = "pytest" if name == "tox.ini" else "tool:pytest"
    return dict(parser.items(section)) if parser.has_section(section) else None


def _is_test(parts):
    name = parts[-1]
    return bool(TEST_DIRS & set(parts[:-1])) or name.startswith("test_") or name.endswith("_test.py")


def _root(module):
    return (module or "").split(".")[0]


def _imports_harness(module, test_file):
    """True for _pytest anywhere, and for pytest itself outside test files."""
    root = _root(module)
    return root in HARNESS_DIRS and not (test_file and root == PUBLIC_PYTEST)


def _code(path, test_file=False):
    try:
        tree = ast.parse(path.read_bytes())
    except (OSError, SyntaxError, ValueError) as error:
        return "Python file cannot be parsed, so it cannot be checked: " + type(error).__name__
    sys_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _imports_harness(alias.name, test_file):
                    return "code imports " + alias.name
                if alias.name == "sys":
                    sys_names.add(alias.asname or "sys")
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            if _imports_harness(node.module, test_file):
                return "code imports from " + node.module
            if node.module == "sys" and any(alias.name in ("modules", "*") for alias in node.names):
                return "code binds sys.modules by name"
        elif isinstance(node, ast.Call) and _call_name(node.func) in ("__import__", "import_module"):
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str) \
                    and _imports_harness(node.args[0].value, test_file):
                return "code imports " + node.args[0].value
    for node in ast.walk(tree):
        if _writes_modules(node, sys_names):
            return "code writes sys.modules"
    return None


def _call_name(func):
    return func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None


def _is_modules(node, sys_names):
    return isinstance(node, ast.Attribute) and node.attr == "modules" and isinstance(node.value, ast.Name) \
        and node.value.id in sys_names


def _writes_modules(node, sys_names):
    targets = []
    if isinstance(node, ast.Assign):
        targets = node.targets
    elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
        targets = [node.target]
    elif isinstance(node, ast.Delete):
        targets = node.targets
    for target in targets:
        for part in ast.walk(target):
            if _is_modules(part, sys_names) or (isinstance(part, ast.Subscript) and _is_modules(part.value, sys_names)):
                return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in MUTATORS \
            and _is_modules(node.func.value, sys_names):
        return True
    return False
