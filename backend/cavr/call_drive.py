"""Driving the project's call sites in the sandbox (PR 12 of docs/cavr-m2-plan.md, FR-4). Pure on the host; fail closed.

An install + import run cannot show a sink that only runs when the project calls the package (PR 9: UNRESOLVED
DEEP_SINK_NOT_EXERCISED). `plan(package)` proposes a bounded way to run that code: call the package function the
project calls, with the arguments the project's own call site writes, if and only if every one of them is a literal.

For each call site of the contract (`capability_contract`: file, line, symbol, expression, kind) of kind "call":

    1. the project file is read again and must have the SHA-256 the project context recorded (that context, through
       `sources_digest`, is in the contract digest and so in the cache key: a drive never uses source the key does
       not cover);
    2. every `ast.Call` at that line whose callee, written out, is the recorded expression is a candidate;
    3. every positional and keyword argument must be accepted by `ast.literal_eval` (numbers, strings, bytes, None,
       booleans, tuples, lists, sets, dicts of those); no `*args`, no `**kwargs`; at most MAX_ARG_BYTES of source;
    4. no string in an argument may look like a credential, and no keyword may be named like one (NFR-5: no real
       credential ever enters a run; decision D2, Maryam 2026-11-24). This is a heuristic guard, stated as one:
       known token prefixes, a PEM block, a long letters-and-digits token, keyword names such as password / token.

Anything else is listed in `not_driven` with the reason, and stays undriven: the deep verdict cannot count a sink
that only such a call reaches as exercised. Decorators (`@demo.register`) are never driven: their argument is a
function. At most LIMIT distinct calls (symbol and arguments) are driven per run, ordered by file, line and column.

In the sandbox each drive is one harness step (`drive_1` ... `drive_4`), a fresh Python with the imports step's
environment: DRIVE_CODE imports the modules (as the imports step does), resolves the symbol (attribute by attribute,
importing a submodule when the attribute is not there yet), calls it with the literals and catches every exception
(BaseException: SystemExit and KeyboardInterrupt too), then ends with os._exit(0) so that a thread the call left
running cannot hold the run until its deadline. What the call printed goes to the untrusted output and is never
read for a verdict; only the trace (strace, which the package cannot write) is evidence.

Not driven, by construction: a call whose arguments the project computes, methods on objects the package returned
(`reader.pages`), async functions and generators (the coroutine or generator is returned, never run), code the call
leaves for later (threads killed by os._exit, atexit hooks). Not mounted: the project itself, so a literal path in
the project (`"fixtures/invoice.pdf"`) does not exist in the sandbox.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path

from backend.cavr.sandbox_observe import SITE_LIB

VERSION = "cavr-call-drive/1"
LIMIT = 4
MAX_ARG_BYTES = 4096
STEP_PREFIX = "drive_"
TOKEN_PREFIXES = ("AKIA", "ASIA", "ghp_", "gho_", "ghs_", "github_pat_", "pypi-", "sk-", "xoxb-", "xoxp-", "glpat-",
                  "AIza", "-----BEGIN")
TOKEN = re.compile(r"^[A-Za-z0-9+/=_-]{24,}$")
SECRET_NAME = re.compile(r"(?i)(pass|secret|token|cred|auth|api_?key|private_?key|^key$)")

DRIVE_CODE = (f"import ast, importlib, json, os, site, sys\njob = json.loads(sys.argv[1])\n"
              f"site.addsitedir({SITE_LIB!r})\nsys.argv = job['argv']\n"
              "for name in job['modules']:\n    importlib.import_module(name)\n"
              "parts = job['symbol'].split('.')\n"
              "try:\n"
              "    target = importlib.import_module(parts[0])\n"
              "    for i in range(1, len(parts)):\n"
              "        try:\n            target = getattr(target, parts[i])\n"
              "        except AttributeError:\n            target = importlib.import_module('.'.join(parts[:i + 1]))\n"
              "    target(*[ast.literal_eval(a) for a in job['args']],\n"
              "           **{k: ast.literal_eval(v) for k, v in job['kwargs'].items()})\n"
              "except BaseException as exc:\n    print('cavr-drive:', type(exc).__name__, flush=True)\n"
              "sys.stdout.flush()\nos._exit(0)\n")
DRIVE_ARGV = ["/usr/local/bin/python", "-I", "-S", "-B", "-c", DRIVE_CODE]


def plan(package: dict) -> dict:
    """{version, drives: [...], not_driven: [...], limit}. Never raises."""
    try:
        return _plan(package)
    except Exception as exc:  # a fault here drives nothing; the reasons stay not exercised
        return {"version": VERSION, "drives": [], "limit": LIMIT,
                "not_driven": [{"file": None, "line": None, "expression": None, "why": f"the drive plan failed: "
                                f"{type(exc).__name__}: {exc}"}]}


def _plan(package):
    contract = package.get("contract") or {}
    project = package.get("project") or {}
    root = project.get("project_dir")
    hashes = project.get("files") or {}
    candidates, not_driven, seen = [], [], set()
    for site in sorted(contract.get("call_sites") or [], key=lambda s: (str(s.get("file")), s.get("line") or 0,
                                                                        str(s.get("expression")))):
        where = {"file": site.get("file"), "line": site.get("line"), "symbol": site.get("symbol"),
                 "expression": site.get("expression")}
        if site.get("kind") != "call":
            not_driven.append({**where, "why": f"a {site.get('kind')}, not a call: its argument is code, not a literal"})
            continue
        calls, problem = _calls(root, hashes, site)
        if problem:
            not_driven.append({**where, "why": problem})
            continue
        for call in calls:
            drive, why = _drive(call, site)
            text = ast.unparse(call)
            if why:
                not_driven.append({**where, "call": text, "why": why})
                continue
            key = json.dumps([drive["symbol"], drive["args"], drive["kwargs"]])
            if key in seen:
                continue
            seen.add(key)
            candidates.append({**where, "call": text, "column": call.col_offset, **drive})
    drives = []
    for item in candidates:
        if len(drives) == LIMIT:
            not_driven.append({key: item[key] for key in ("file", "line", "symbol", "expression", "call")}
                              | {"why": f"over the limit of {LIMIT} driven calls per run"})
            continue
        drives.append({**item, "step": f"{STEP_PREFIX}{len(drives) + 1}"})
    return {"version": VERSION, "drives": drives, "not_driven": not_driven, "limit": LIMIT}


def _calls(root, hashes, site):
    """The ast.Call nodes at the site's line written as its expression, or (None, why)."""
    file, line, expression = site.get("file"), site.get("line"), site.get("expression")
    if not root or not isinstance(file, str) or not isinstance(line, int) or not expression:
        return None, "the call site has no file, line or expression"
    recorded = hashes.get(file)
    try:
        data = (Path(root) / file).read_bytes()
    except OSError as exc:
        return None, f"the project file cannot be read again: {exc}"
    if recorded is None or hashlib.sha256(data).hexdigest() != recorded:
        return None, "the project file is not the one the contract was inferred from (its SHA-256 differs)"
    try:
        tree = ast.parse(data)
    except (SyntaxError, ValueError) as exc:
        return None, f"the project file cannot be parsed: {exc}"
    found = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and node.lineno == line
             and _dotted(node.func) == expression]
    if not found:
        return None, f"no call written `{expression}(...)` at line {line}"
    return sorted(found, key=lambda n: n.col_offset), None


def _drive(call, site):
    """({symbol, args, kwargs}, None) or (None, why not)."""
    symbol = site.get("symbol")
    if not (isinstance(symbol, str) and all(part.isidentifier() for part in symbol.split("."))):
        return None, f"the symbol {symbol!r} cannot be resolved by name"
    args, kwargs = [], {}
    for index, node in enumerate(call.args, 1):
        if isinstance(node, ast.Starred):
            return None, f"argument {index} is `*{ast.unparse(node.value)}`: its values are not literals"
        text, why = _literal(node, f"argument {index}")
        if why:
            return None, why
        args.append(text)
    for keyword in call.keywords:
        if keyword.arg is None:
            return None, f"`**{ast.unparse(keyword.value)}`: its values are not literals"
        if SECRET_NAME.search(keyword.arg):
            return None, f"keyword `{keyword.arg}` is named like a credential; it is never passed into a run (NFR-5)"
        text, why = _literal(keyword.value, f"keyword `{keyword.arg}`")
        if why:
            return None, why
        kwargs[keyword.arg] = text
    if len(json.dumps([args, kwargs])) > MAX_ARG_BYTES:
        return None, f"the arguments are over {MAX_ARG_BYTES} bytes"
    return {"symbol": symbol, "args": args, "kwargs": dict(sorted(kwargs.items()))}, None


def _literal(node, label):
    text = ast.unparse(node)
    try:
        value = ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None, f"{label} `{text}` is not a literal"
    secret = next((s for s in _strings(value) if looks_like_credential(s)), None)
    if secret is not None:
        return None, f"{label} looks like a credential; it is never passed into a run (NFR-5)"
    return text, None


def _strings(value):
    if isinstance(value, (str, bytes)):
        yield value.decode("latin-1") if isinstance(value, bytes) else value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(key)
            yield from _strings(item)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _strings(item)


def looks_like_credential(text: str) -> bool:
    """A heuristic (D2): a known token prefix or PEM block, or a 24+ character token of letters and digits."""
    stripped = text.strip()
    if any(stripped.startswith(prefix) for prefix in TOKEN_PREFIXES) or "PRIVATE KEY" in stripped:
        return True
    return bool(TOKEN.match(stripped) and re.search(r"[A-Za-z]", stripped) and re.search(r"[0-9]", stripped))


def drive_job(drive: dict, modules, argv) -> str:
    """The JSON the drive step's DRIVE_CODE reads (its last argv entry)."""
    return json.dumps({"modules": list(modules), "argv": list(argv), "symbol": drive["symbol"], "args": drive["args"],
                       "kwargs": drive["kwargs"]})


def describe(drive: dict) -> str:
    """`demo.send('x')` at app/uses_demo.py:5, for reasons and the report."""
    return f"{drive.get('call') or drive.get('expression')} at {drive.get('file')}:{drive.get('line')}"


def _dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    return ".".join([node.id, *reversed(parts)])
