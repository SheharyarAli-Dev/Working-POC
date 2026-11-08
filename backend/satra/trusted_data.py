"""Base data files that the trusted tests read (`SATRA.trusted_data`, docs/satra/trusted-suite.md).

In a gate run the trusted suite is mounted read-only at /trusted/asent_assurance/, outside the head, so
a trusted test that finds a fixture next to itself (`Path(__file__).parents[1] / "fixtures"`) looks in
/trusted/fixtures. Each `trusted_data` path is copied from the BASE commit to /trusted/<path>, so that
lookup finds the base's bytes; the head's copy of the same files is never used by a trusted run.

`collect(base_dir, paths)` reads every declared file into memory once. The trusted runs write exactly
those bytes, so what was checked is what the tests see. It accepts regular data files only and refuses,
with a reason (SATRA then reports INCONCLUSIVE):
  - a path that is missing in the base, is a symbolic link (or has one on the way), or is neither a
    regular file nor a folder; a folder with no files in it; anything in a folder that is not a regular
    file or a folder;
  - a path whose first part is `asent_assurance` or `pytest.ini` (it would replace the trusted suite or ini);
  - Python code, native modules, `.pth` files and pytest settings files, so nothing in /trusted besides
    the suite can be imported or change pytest's configuration;
  - more than MAX_FILES files or MAX_BYTES bytes in total.
"""
from __future__ import annotations

import hashlib
import os
import stat
from importlib.machinery import EXTENSION_SUFFIXES
from pathlib import Path, PurePosixPath

MAX_FILES = 1000
MAX_BYTES = 20 * 1024 * 1024  # 20 MiB in total
RESERVED = ("asent_assurance", "pytest.ini")
CODE_SUFFIXES = tuple(sorted({".py", ".pyc", ".pyo", ".pyw", ".pyi", ".pth", ".so", ".pyd", ".dylib", ".dll",
                              *(s.lower() for s in EXTENSION_SUFFIXES)}))
SETTINGS_NAMES = ("conftest.py", "pytest.ini", ".pytest.ini", "pytest.toml", ".pytest.toml", "pyproject.toml",
                  "tox.ini", "setup.cfg", "sitecustomize.py", "usercustomize.py")


def _kind(mode):
    return "symbolic link" if stat.S_ISLNK(mode) else "folder" if stat.S_ISDIR(mode) else \
        "regular file" if stat.S_ISREG(mode) else "special file"


def _refused_name(rel):
    name = PurePosixPath(rel).name.lower()
    if name in SETTINGS_NAMES:
        return "is a pytest or Python settings file"
    if name.endswith(CODE_SUFFIXES):
        return "is Python code or a native module, not data"
    return None


def _read(path, budget):
    """Bytes of a regular file, opened without following a link, or (None, reason)."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as error:
        return None, "cannot be opened (%s)" % (error.strerror or error)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None, "is not a regular file"
        with os.fdopen(fd, "rb", closefd=False) as handle:
            return handle.read(budget + 1), None
    finally:
        os.close(fd)


def collect(base_dir, paths):
    """-> ({relative posix path: bytes}, None) for the declared base paths, or (None, reason)."""
    base = Path(base_dir)
    found, total = {}, 0
    for declared in dict.fromkeys(paths):
        parts = PurePosixPath(declared).parts
        label = "trusted_data %r" % declared
        if not parts or parts[0] in RESERVED:
            return None, "%s would replace /trusted/%s" % (label, parts[0] if parts else "")
        current = base
        for part in parts:  # no link anywhere on the way, so the path stays inside the base
            current = current / part
            try:
                mode = os.lstat(current).st_mode
            except FileNotFoundError:
                return None, "%s is not in the base commit" % label
            if stat.S_ISLNK(mode):
                return None, "%s: %s is a symbolic link" % (label, current.relative_to(base).as_posix())
        if stat.S_ISREG(mode):
            members = [current]
        elif stat.S_ISDIR(mode):
            members = []
            for folder, dirs, names in os.walk(current, followlinks=False):
                for name in sorted(dirs + names):
                    entry = Path(folder, name)
                    kind = _kind(os.lstat(entry).st_mode)
                    if kind not in ("regular file", "folder"):
                        return None, "%s: %s is a %s" % (label, entry.relative_to(base).as_posix(), kind)
                    if kind == "regular file":
                        members.append(entry)
                dirs.sort()
            if not members:
                return None, "%s has no files in the base commit" % label
        else:
            return None, "%s is a %s, not a regular file or folder" % (label, _kind(mode))
        for member in sorted(members):
            rel = member.relative_to(base).as_posix()
            if rel in found:
                continue
            why = _refused_name(rel)
            if why:
                return None, "%s: %s %s" % (label, rel, why)
            if len(found) + 1 > MAX_FILES:
                return None, "trusted_data has more than %d files (cap %d)" % (MAX_FILES, MAX_FILES)
            data, why = _read(member, MAX_BYTES - total)
            if why:
                return None, "%s: %s %s" % (label, rel, why)
            total += len(data)
            if total > MAX_BYTES:
                return None, "trusted_data is larger than %d bytes (cap %d MiB)" % (MAX_BYTES, MAX_BYTES // (1024 * 1024))
            found[rel] = data
    return found, None


def summary(files):
    """Evidence: each copied file with its size and SHA-256, and the totals."""
    entries = [{"path": rel, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for rel, data in sorted(files.items())]
    return {"files": entries, "file_count": len(entries), "total_bytes": sum(e["bytes"] for e in entries)}
