"""pytest plugin for SATRA's trusted gate runs: the head becomes importable only as code under test.

`pytest_runner.run_pytest` copies this file to a read-only directory, puts that directory on PYTHONPATH and
loads it with `-p asent_satra_trusted_run`; nothing else in that directory exists. The interpreter starts
with `-P -s`, so neither the working directory (/work, the head) nor a user site directory is on sys.path,
and pytest, pluggy and the standard library are imported from the image before any head file can be.

Before the initial conftests are loaded, this plugin removes any sys.path entry inside the head and appends
the head (ASENT_SATRA_HEAD) at the END of sys.path, after the standard library and site-packages, so a head
module can never shadow pytest, _pytest or an installed package. Each `pythonpath` entry of the trusted
pytest.ini that lies inside ASENT_SATRA_TRUSTED is mapped to the same relative path inside the head
(`pythonpath = src` -> /work/src), in ini order, before the head root itself.
"""
import os
import sys
from pathlib import Path

import pytest


def _inside(path, root):
    return path == root or root in path.parents


@pytest.hookimpl(tryfirst=True)
def pytest_load_initial_conftests(early_config, parser, args):
    trusted = os.environ.get("ASENT_SATRA_TRUSTED")
    head = os.environ.get("ASENT_SATRA_HEAD")
    if not trusted or not head:
        raise pytest.UsageError("asent_satra_trusted_run needs ASENT_SATRA_TRUSTED and ASENT_SATRA_HEAD")
    trusted, head = Path(trusted), Path(head)
    wanted = []
    for entry in early_config.getini("pythonpath"):
        entry = Path(entry)
        if _inside(entry, trusted):
            wanted.append(str(head / entry.relative_to(trusted)))
    wanted.append(str(head))
    sys.path[:] = [p for p in sys.path if not _inside(Path(p or os.curdir).absolute(), head)]
    for path in dict.fromkeys(wanted):
        sys.path.append(path)
