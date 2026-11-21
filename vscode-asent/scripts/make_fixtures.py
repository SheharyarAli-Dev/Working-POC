"""Write the extension's test fixtures from real `asent` runs (nothing here is hand-written JSON).

    .venv/bin/python vscode-asent/scripts/make_fixtures.py [--out DIR] [--only NAME ...]

Each scenario builds a throwaway git repository with real base and head commits (the
`tests/gate_support.py` helpers) and runs the real CLI (`backend.cli.main`) on it, exactly as the
extension does: `gate --json`, `init --json`, `doctor --json`, and the line `dashboard --json` prints.

| Scenario       | What happens                                               | Needs        |
|----------------|------------------------------------------------------------|--------------|
| accept         | CAVR-only config, head changes README.md -> ACCEPT          | -            |
| cavr-block     | head adds the denied typosquat `reqeusts==2.31.0` -> BLOCK  | -            |
| review         | head edits `.asent/` (config changed in head) -> REVIEW     | -            |
| sable-block    | head replaces infra/ with scenarios/sable/regressed -> SABLE REGRESSED | - |
| satra-block    | head turns `can_access` into `return True` -> SATRA REJECT  | Docker and the images of scripts/satra_build_sandbox.sh |
| doctor         | `asent doctor --json` on this machine                       | -            |
| init           | `asent init --json` on a fresh repository                   | -            |
| dashboard      | the line `asent dashboard --json` prints (the server is not started) | -   |

CAVR's PyPI and OSV answers are the recorded real answers the gate tests use (real pypdf 6.19.0 wheel
and registry response, `tests/test_cavr_support.py`), so these runs need no network. SATRA runs the
trusted tests in real containers. A scenario whose result is not the expected one is an error and
writes nothing, so a fixture can never carry a decision its name does not say.

Machine paths are replaced by neutral placeholders before writing (`neutral`), and nothing else is
changed. The paths are read from the environment of the run (`machine_paths`), not hard-coded: the
scenario's repository -> /workspace/project, its temp folder -> /workspace, the ASENT checkout (and
$GITHUB_WORKSPACE when set) -> /opt/asent, $RUNNER_TEMP when set -> /tmp/runner-temp, the temp folder
(tempfile.gettempdir(), $TMPDIR/$TEMP/$TMP) -> /tmp, the home folder -> /home/user, and asent's own
mkdtemp folders inside a temp folder (`/tmp/asent-gate-<random>`) -> `<that folder's placeholder>/asent-gate-run`.
Unset, empty, relative or root (`/`) values are ignored. Only JSON string values (and keys) are edited, in one
pass; a path must end on a segment boundary but may be glued to other text (`-I/home/runner/include`). Numbers,
booleans, structure, digests and SHAs stay exactly as asent wrote them. A file in which one of those machine
paths, or the user name ($USER, $LOGNAME, $USERNAME, the home folder's name) as a path segment (`/runner/`), is
still found afterwards is not written; nor is one with two keys that become the same, or a value that is not
JSON. The user name as a plain word is not a path: SATRA's report has a `runner` key, and a GitHub runner's
user is called `runner`.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

import pytest  # noqa: E402  (MonkeyPatch, the same injection the gate tests use)

from backend import cli  # noqa: E402
from gate_support import DISABLED, GateRepo, cavr_files, config, recorded_pypi, run_cli  # noqa: E402

DEFAULT_OUT = ROOT / "vscode-asent" / "test" / "fixtures"


class ScenarioError(Exception):
    pass


def _expect(report, decision, module=None, result=None):
    if report is None:
        raise ScenarioError("no asent-report.json was written")
    if report["decision"] != decision:
        raise ScenarioError(f"decision {report['decision']}, expected {decision}: {report['reasons']}")
    if module and report["modules"][module]["result"] != result:
        raise ScenarioError(f"{module} result {report['modules'][module]['result']!r}, expected {result!r}: "
                            f"{report['modules'][module]['reason']}")
    return report


def _cavr_repo(work: Path, monkeypatch):
    recorded_pypi(monkeypatch, work)
    repo = GateRepo(work / "repo")
    return repo, repo.commit(cavr_files(), message="project with reviewed .asent/")


def accept(work, monkeypatch):
    repo, base = _cavr_repo(work, monkeypatch)
    head = repo.commit({"README.md": "docs\n"}, message="docs only")
    return _expect(run_cli(repo, base, head, work / "out")[1], "ACCEPT", "CAVR", "pass")


def cavr_block(work, monkeypatch):
    repo, base = _cavr_repo(work, monkeypatch)
    head = repo.commit({"requirements.txt": "pypdf==6.19.0\nreqeusts==2.31.0\n"}, message="typosquat")
    return _expect(run_cli(repo, base, head, work / "out")[1], "BLOCK", "CAVR", "block")


def review(work, monkeypatch):
    repo, base = _cavr_repo(work, monkeypatch)
    head = repo.commit({".asent/README.md": "relaxed\n"}, message="edit .asent/ in the change")
    report = _expect(run_cli(repo, base, head, work / "out")[1], "REVIEW")
    if report["config"]["changed_in_head"] is not True:
        raise ScenarioError("expected config.changed_in_head true")
    return report


def sable_block(work, monkeypatch):
    from test_gate_cli import OBLIGATIONS, infra_files
    repo = GateRepo(work / "repo")
    base = repo.commit({**infra_files(), ".asent/config.json": config(SABLE={"enabled": True}, CAVR=DISABLED, SATRA=DISABLED),
                        ".asent/sable/obligations.json": OBLIGATIONS}, message="infrastructure with its obligation")
    for tf in (repo.root / "infra").rglob("*.tf"):
        tf.unlink()
    head = repo.commit(infra_files(ROOT / "scenarios/sable/regressed"), message="regressed infrastructure")
    return _expect(run_cli(repo, base, head, work / "out")[1], "BLOCK", "SABLE", "block")


# The head only edits app/security.py, so CAVR is asked to verify the base -> head edit of requirements.txt
# (nothing added or changed: VERIFIED NOTHING_TO_VERIFY, no network). With the default "all", the empty
# requirements file is `pip install -r requirements.txt` naming nothing, which CAVR fails closed on
# (UNRESOLVED CAPTURE_INCOMPLETE) and the gate would REVIEW instead of BLOCK on SATRA alone.
SATRA_SCENARIO_CAVR = {"enabled": True, "verify": "changed"}


def satra_files():
    """Base commit of the SATRA scenario: a project with no third-party dependencies and a trusted contract."""
    from test_satra_config import CONTRACT, NO_DEPENDENCIES, SECURE, TRUSTED
    return {**NO_DEPENDENCIES, "app/__init__.py": "", "app/security.py": SECURE,
            "app/main.py": "from app.security import can_access\n",
            ".asent/config.json": config(SATRA={"enabled": True, "pytest_ini": "satra/pytest.ini", "source_dirs": ["app"]},
                                         CAVR=SATRA_SCENARIO_CAVR, SABLE=DISABLED),
            ".asent/satra/contract.json": json.dumps(CONTRACT),
            ".asent/satra/pytest.ini": "[pytest]\npythonpath = .\n",
            ".asent/satra/trusted_tests/test_contract.py": TRUSTED}


def satra_block(work, monkeypatch):
    if shutil.which("docker") is None:
        raise ScenarioError("Docker is not installed; SATRA cannot run the trusted tests (see the manual fixtures workflow)")
    from test_satra_config import BROKEN
    repo = GateRepo(work / "repo")
    base = repo.commit(satra_files(), message="secure access check")
    head = repo.commit({"app/security.py": BROKEN}, message="access check always allows")
    return _expect(run_cli(repo, base, head, work / "out")[1], "BLOCK", "SATRA", "block")


def _json_stdout(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = cli.main(argv)
    return code, json.loads(out.getvalue())


def doctor(work, monkeypatch):
    return _json_stdout(["doctor", "--json"])[1]


def init(work, monkeypatch):
    repo = GateRepo(work / "repo")
    repo.commit({"requirements.txt": "pypdf==6.19.0\n"}, message="project")
    code, result = _json_stdout(["init", "--json", "--repository", str(repo.root)])
    if code != 0:
        raise ScenarioError(f"init exited {code}: {result}")
    return result


def dashboard(work, monkeypatch):
    from backend.commands import dashboard as dash
    return json.loads(json.dumps(dash.info(dash.DEFAULT_PORT)))  # cli.dashboard_command prints json.dumps(info(port))


# A machine path ends on a separator or a character no file name segment has (so /home/runner2 is not
# /home/runner). There is no start boundary on purpose: a path glued to other text (`-I/home/runner/include`,
# `--root=/srv/asent`) is still replaced, and still found by the check.
SEGMENT_END = r"(?=[/\\]|$|[^\w.-])"
# tempfile.mkdtemp folder name: a prefix that ends in "-" plus 8 random characters, e.g. asent-gate-ab12cd_3
MKDTEMP = r"[/\\](?P<prefix>[A-Za-z][\w.]*(?:-[A-Za-z][\w.]*)*-)[a-z0-9_]{8}"
TEMP_VARS = ("TMPDIR", "TEMP", "TMP")
USER_VARS = ("USER", "LOGNAME", "USERNAME")


def _usable(raw):
    """`raw` as an absolute path with at least one segment, else None: "" or "/" would match every path."""
    if not raw:
        return None
    path = Path(raw)
    return path if path.is_absolute() and path != Path(path.anchor) else None


def machine_paths(work: Path, env=None) -> dict:
    """{machine path: placeholder} of this run, read from the real environment (both the given and the resolved
    form of each path). The first entry wins when two sources name the same folder (GITHUB_WORKSPACE is the checkout)."""
    env = os.environ if env is None else env
    entries = [(work / "repo", "/workspace/project"), (work, "/workspace"),
               (ROOT, "/opt/asent"), (env.get("GITHUB_WORKSPACE"), "/opt/asent"),
               (env.get("RUNNER_TEMP"), "/tmp/runner-temp"),
               (tempfile.gettempdir(), "/tmp"), *((env.get(name), "/tmp") for name in TEMP_VARS),
               (env.get("HOME") or Path.home(), "/home/user")]
    table = {}
    for raw, placeholder in entries:
        path = _usable(str(raw) if raw else None)
        if path is not None:
            for form in (str(path), str(path.resolve())):
                table.setdefault(form, placeholder)
    return table


def _temp_roots(table: dict, env) -> set:
    """The table's folders that asent's own mkdtemp folders can sit in (the temp folder and RUNNER_TEMP)."""
    roots = {tempfile.gettempdir(), env.get("RUNNER_TEMP"), *(env.get(name) for name in TEMP_VARS)}
    paths = {p for p in (_usable(r) for r in roots) if p is not None}
    return {form for p in paths for form in (str(p), str(p.resolve()))} & set(table)


def _replacer(work: Path, env):
    """One regex over all machine paths, applied in a single pass so a placeholder is never replaced again.

    At a position the longest machine path wins (alternatives are tried in order); a temp folder's mkdtemp
    pattern is tried just before the temp folder itself, so /tmp/asent-gate-ab12cd_3 -> /tmp/asent-gate-run
    while a longer known path under it (the scenario folder) still wins."""
    table = machine_paths(work, env)
    temps = _temp_roots(table, env)
    alternatives, replacement = [], {}
    for path in sorted(table, key=len, reverse=True):
        if path in temps:
            name = f"m{len(alternatives)}"
            alternatives.append(f"(?P<{name}>{re.escape(path)}{MKDTEMP.replace('?P<prefix>', f'?P<{name}p>')})")
            replacement[name] = lambda m, name=name, new=table[path]: f"{new}/{m.group(name + 'p')}run"
        name = f"a{len(alternatives)}"
        alternatives.append(f"(?P<{name}>{re.escape(path)})")
        replacement[name] = lambda m, new=table[path]: new
    pattern = re.compile("(?:" + "|".join(alternatives) + ")" + SEGMENT_END)
    return table, lambda s: pattern.sub(lambda m: replacement[m.lastgroup](m), s)


def _user_names(env) -> set:
    """$USER, $LOGNAME, $USERNAME and the home folder's name (so the check works when no user variable is set)."""
    home = _usable(env.get("HOME") or str(Path.home()))
    return ({env.get(name) for name in USER_VARS} | {home.name if home else None}) - {None, ""}


def leftovers(strings, table: dict, env) -> list:
    r"""Machine paths, and the user name as a path segment, still present in `strings` (sorted).

    A match that lies wholly inside a placeholder is not counted (e.g. /home/user when the user is `user`, or
    /opt/asent when the home folder is /opt); a placeholder that only starts the match does not hide it
    (/tmp/asent-fixture-<random>/repo is still found). The user name only counts inside a path (/runner/,
    \runner): as a plain word it is also an ordinary key of asent's own reports (SATRA's sandbox_image.runner),
    and the user of a GitHub runner is called `runner`."""
    machine = {path: re.compile(re.escape(path) + SEGMENT_END) for path, placeholder in table.items() if path != placeholder}
    users = {u: re.compile(r"(?<=[/\\])" + re.escape(u) + SEGMENT_END) for u in _user_names(env)}
    placeholders = [re.compile(re.escape(p) + SEGMENT_END) for p in set(table.values())]
    found = set()
    for s in strings:
        covers = [m.span() for q in placeholders for m in q.finditer(s)]
        for name, pattern in (*machine.items(), *users.items()):
            if any(not any(a <= m.start() and m.end() <= b for a, b in covers) for m in pattern.finditer(s)):
                found.add(name)
    return sorted(found)


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for x in value:
            yield from _strings(x)
    elif isinstance(value, dict):
        for k, x in value.items():
            yield k
            yield from _strings(x)


def neutral(value, work: Path, env=None):
    """The same JSON value with machine paths replaced by placeholders (see the module docstring)."""
    env = os.environ if env is None else env
    table, text = _replacer(work, env)

    def walk(v):
        if isinstance(v, str):
            return text(v)
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, dict):
            keys = {}
            for k, x in v.items():
                new = text(k)
                if new in keys:  # two machine paths became the same placeholder: the file would lose an entry
                    raise ScenarioError(f"keys {keys[new][0]!r} and {k!r} both become {new!r} after neutral()")
                keys[new] = (k, walk(x))
            return {new: x for new, (_, x) in keys.items()}
        if v is None or isinstance(v, (bool, int, float)):
            return v
        raise ScenarioError(f"not a JSON value, so it would be neither neutralised nor checked: {type(v).__name__}")

    result = walk(value)
    left = leftovers(_strings(result), table, env)
    if left:
        raise ScenarioError(f"machine paths still present after neutral(): {left}")
    return result


SCENARIOS = {"accept": accept, "cavr-block": cavr_block, "review": review, "sable-block": sable_block, "satra-block": satra_block,
             "doctor": doctor, "init": init, "dashboard": dashboard}
FOLDER = {"doctor": "doctor", "init": "init", "dashboard": "dashboard"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--only", nargs="+", choices=sorted(SCENARIOS))
    args = parser.parse_args(argv)
    failed = False
    for name in args.only or [n for n in SCENARIOS if n != "satra-block"]:
        with tempfile.TemporaryDirectory(prefix=f"asent-fixture-{name}-") as work, pytest.MonkeyPatch.context() as mp:
            try:
                value = neutral(SCENARIOS[name](Path(work), mp), Path(work))
            except ScenarioError as exc:
                print(f"{name}: NOT WRITTEN: {exc}", file=sys.stderr)
                failed = True
                continue
        folder = args.out / FOLDER.get(name, "reports")
        folder.mkdir(parents=True, exist_ok=True)
        target = folder / f"{name}.json"
        target.write_text(json.dumps(value, indent=2, default=str) + "\n", encoding="utf-8")
        print(f"{name}: {target}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
