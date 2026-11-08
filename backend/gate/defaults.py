"""Defaults for `asent gate` run with no arguments: which repository, and which base commit.

`top_level(path)`: the top level of the git work tree containing `path`, or None.
`default_base(repository)`: `(ref, how)` for the repository's default branch, or `(None, None)`:

1. `refs/remotes/origin/HEAD` when it points at an existing remote-tracking branch (`git clone` sets
   it to the remote's default branch, whatever its name);
2. otherwise the local branch `main`, then the local branch `master`.

Only branches count (full `refs/...` names are returned, so a tag called `main` can never be picked).
With no default branch the gate gets base None and decides REVIEW (`runner.NO_BASE`).
Git runs like `integrations.git_adapter`: no hooks, no system or global config, no prompts.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

ORIGIN_HEAD = "refs/remotes/origin/HEAD"
FALLBACK_BRANCHES = ("main", "master")


def _git(cwd, *args):
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0"}
    try:
        p = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *args], cwd=cwd, env=env,
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return p.stdout.strip() if p.returncode == 0 else None


def top_level(path) -> Path | None:
    top = _git(Path(path), "rev-parse", "--show-toplevel")
    return Path(top) if top else None


def _is_commit(repository, ref) -> bool:
    return bool(_git(repository, "rev-parse", "--verify", "--quiet", "--end-of-options", ref + "^{commit}"))


def default_base(repository):
    target = _git(repository, "symbolic-ref", "--quiet", ORIGIN_HEAD)
    if target and target.startswith("refs/remotes/origin/") and target != ORIGIN_HEAD and _is_commit(repository, target):
        return target, "origin/HEAD"
    for branch in FALLBACK_BRANCHES:
        if _is_commit(repository, "refs/heads/" + branch):
            return "refs/heads/" + branch, "branch " + branch
    return None, None
