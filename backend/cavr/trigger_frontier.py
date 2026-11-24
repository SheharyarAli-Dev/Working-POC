"""The trigger frontier: conditions in the verified wheel that guard a sink (PR 10 of docs/cavr-m2-plan.md, FR-12).

`frontier(nodes, contract, now=...)` re-hashes every wheel of the verified tree, parses its `.py` files (nothing is
imported or run) and finds each sink that runs only when a condition holds. A condition is a *trigger* when it reads
one of these families (through import aliases, and through a name assigned exactly once in its scope):

    env       os.getenv, os.environ.get / [...] / in
    time      time.time, datetime.datetime.now / utcnow / today, datetime.date.today
    file      os.path.exists / isfile / isdir, pathlib.Path(...).exists() / is_file() / is_dir()
    host      socket.gethostname, platform.node, os.uname().nodename
    user      getpass.getuser (set through LOGNAME / USER), os.getuid / geteuid (fixed: 10001), os.getlogin
    argv      sys.argv
    platform  sys.platform, os.name, platform.system()
    obfuscated  getattr, __import__, importlib, eval, exec, compile, globals, vars, locals in the condition

Guards: `if` bodies and `else` branches, `while` bodies, early exits (`if not X: return` covers what follows in the
block), nested guards (combined with "and"), and calls to functions defined at module level in the same file (followed
up to CALL_DEPTH). Sinks: the threat repository's Python sinks (import aliases resolved) and reads of a secret path
named by a string constant (`open`, `read_text`, `read_bytes` on .aws, .ssh, .netrc, .kube, .env, ...). A guard that
reads none of the families is not a trigger; it is counted in `other_guards`.

Activation. A small evaluator (an AST walk, never `eval`) computes the condition in candidate environments built
from the condition's own constants: env values (unset, "1", "true", every string constant), a clock (the analysis
time `now`, every date / datetime / timestamp constant +- 1 day, constant dates plus constant day counts), files under
the sandbox HOME (absent, a file, a directory), hostnames, login names and argv lists from the constants. At most
MAX_COMBINATIONS are tried; a clock is accepted only if the condition holds at t and at t + 60 s. Unknown values
(Kleene logic: `X or True` is True whatever X is) keep a reason. The smallest change from the baseline run that makes
the condition true is the entry's `activation`; `baseline_takes_it` when the baseline run (canaries only, see PR 11)
already does. Otherwise the entry is `simulable: False` with the reason (per Q8 that is UNRESOLVED in PR 12):
a non-Linux platform, UID 0, os.getlogin, a file outside the sandbox HOME, an invalid hostname, a computed or
obfuscated value, or no candidate that makes it true.

Risk, from the worst sink of the entry against the contract: high (denied, not granted, or the contract cannot be
read), medium (granted for a scope only), low (granted with "*"). Priority (design §6.3):
sink_risk x reachability_confidence x novelty / run_cost, every factor in the entry. The list is ordered by risk,
then score (descending), then package, file, line, id, and cut at `limit`; `dropped` counts the rest per risk.

`frontier_residual(frontier, explored)` is the check PR 12 calls: an incomplete, truncated or missing frontier, an
unsimulable entry, or a simulable entry that no run explored (and the baseline does not take) can never give VERIFIED.
PR 12 adds the rule for `other_guards` in front of a sink not granted with "*" (high or medium risk; medium added by
Maryam on 2026-11-24): unexplored unless a completed run showed the sink.
"""
from __future__ import annotations

import ast
import calendar
import datetime as dt
import hashlib
import io
import itertools
import json
import posixpath
import re
import tokenize
import zipfile
from pathlib import Path

from backend.cavr.ast_scan import MAX_SOURCE_BYTES, MAX_TOTAL_SOURCE_BYTES, SOURCE_SUFFIXES
from backend.cavr.contract_check import read_contract
from backend.cavr.sandbox_harness import CHILD_ENV
from backend.cavr.sandbox_exec import HOSTNAME
from backend.cavr.wheel_meta import NATIVE, ZIP_ERRORS, WheelProblem, check_entries
from backend.threat_repo.behavior_rules import normalize_name, python_sinks
from backend.threat_repo.repository import seeds

VERSION = "cavr-trigger-frontier/1"
LIMIT = 32
MAX_COMBINATIONS = 512
MAX_TIMES = 64
CALL_DEPTH = 5
RESOLVE_DEPTH = 8
HOME = "/tmp/home"  # the sandbox HOME (sandbox_harness.CHILD_ENV); PR 11 mounts the spec's files there
WORKDIR = "/tmp"  # the image's WORKDIR: where a relative path points
# Files every PR 11 run has (the canaries): the baseline run already finds them.
CANARY_FILES = ("/tmp/home/.aws/credentials", "/tmp/home/.env", "/tmp/home/.netrc", "/tmp/home/.ssh/id_ed25519")
# The variables every PR 11 run's imports step has: the harness's own (CHILD_ENV) and the four canary variables, in
# their shapes (the values are random per run; a condition can see that they are set, and their prefix, not more).
CANARY_ENV_SHAPES = {"AWS_ACCESS_KEY_ID": "AKIA" + "0" * 16, "AWS_SECRET_ACCESS_KEY": "0" * 40,
                     "GITHUB_TOKEN": "ghp_" + "0" * 36, "PYPI_TOKEN": "pypi-" + "0" * 32}
BASELINE_ENV = {**CHILD_ENV, **CANARY_ENV_SHAPES}
# Variables the sandbox fixes: a spec cannot change them (env_synthesis refuses), so no candidate does either.
RESERVED_ENV = re.compile(r"^(?:PATH|HOME|LANG|TMPDIR|PWD|PYTHON.*|LD_.*|FAKETIME.*|PIP_.*|CAVR_.*)$")
SANDBOX = {"platform": "linux", "os_name": "posix", "system": "Linux", "uid": 10001, "hostname": "cavr-sandbox",
           "user": "cavr", "argv": ("-c",)}
OTHER_PLATFORMS = ({"platform": "win32", "os_name": "nt", "system": "Windows"},
                   {"platform": "darwin", "os_name": "posix", "system": "Darwin"})
SECRET_MARKERS = (".aws", ".ssh", ".netrc", ".kube", ".env", ".git-credentials", ".pypirc", ".docker/config.json",
                  ".gnupg", ".azure", "gcloud", "id_rsa", "id_ed25519")
READ_CALLS = ("open", "io.open", "builtins.open", "codecs.open")
READ_METHODS = ("read_text", "read_bytes", "open")
SINK_RISK = {"PROCESS_EXEC": 10.0, "NATIVE_EXEC": 9.5, "SECRET_READ": 9.5, "NETWORK_CONNECT": 9.0}
DEFAULT_SINK_RISK = 5.0
RISK_RANK = {"high": 0, "medium": 1, "low": 2}
CONFIDENCE = {"body": 1.0, "else": 1.0, "after": 0.9}
VIA_CALL_CONFIDENCE = 0.8
OPAQUE_FACTOR = 0.5
FORMULA = "sink_risk x reachability_confidence x novelty / run_cost"
EXITS = ("sys.exit", "os._exit", "exit", "quit")

FAMILY_OF = {"os.getenv": "env", "os.environ": "env", "time.time": "time", "time.time_ns": "time",
             "datetime.datetime.now": "time", "datetime.datetime.utcnow": "time", "datetime.datetime.today": "time",
             "datetime.date.today": "time", "os.path.exists": "file", "os.path.isfile": "file", "os.path.isdir": "file",
             "os.path.lexists": "file", "socket.gethostname": "host", "platform.node": "host", "os.uname": "host",
             "getpass.getuser": "user", "os.getuid": "user", "os.geteuid": "user", "os.getlogin": "user",
             "sys.argv": "argv", "sys.platform": "platform", "os.name": "platform", "platform.system": "platform"}
FILE_METHODS = ("exists", "is_file", "is_dir")
OBFUSCATION = ("getattr", "__import__", "importlib", "eval", "exec", "compile", "globals", "vars", "locals")


# --- values of the evaluator ------------------------------------------------------------------------------------------

class Unknown:
    """A value the evaluator cannot know; it carries why."""
    def __init__(self, why: str):
        self.why = why


class Raised:
    """The expression would raise (KeyError, IndexError, TypeError, ...): the branch is not taken."""
    def __init__(self, why: str):
        self.why = why


class Ref:
    """A module, class or function, by its dotted name."""
    def __init__(self, dotted: str):
        self.dotted = dotted


class Environ:
    pass


class PathValue:
    def __init__(self, path: str):
        self.path = path


class Uname:
    def __init__(self, nodename: str):
        self.nodename, self.sysname = nodename, "Linux"


class Bound:
    """A method of a value: `value.name`."""
    def __init__(self, value, name: str):
        self.value, self.name = value, name


class World:
    """One candidate environment of the sandbox run."""
    def __init__(self, env=None, now=None, files=None, hostname=None, user=None, argv=None, fixed=None):
        self.env = dict(BASELINE_ENV if env is None else env)
        self.now = now
        self.files = dict(files or {})
        self.hostname = hostname or SANDBOX["hostname"]
        self.user = user
        self.argv = list(argv or SANDBOX["argv"])
        self.fixed = {**SANDBOX, **(fixed or {})}
        self.reads = set()  # (family, key)


def _special(value) -> bool:
    return isinstance(value, (Unknown, Raised))


def truth(value):
    if _special(value):
        return value
    if isinstance(value, (Ref, Bound)):
        return Unknown("a function reference is used as a condition")
    if isinstance(value, (Environ, PathValue, Uname)):
        return True
    return bool(value)


# --- scopes: import aliases and names assigned once -----------------------------------------------------------------

class Scope:
    def __init__(self, parent=None, name="module"):
        self.parent, self.name = parent, name
        self.aliases = {}  # local name -> dotted
        self.assigned = {}  # name -> [value node or None]

    def alias(self, name):
        scope = self
        while scope is not None:
            if name in scope.aliases:
                return scope.aliases[name]
            if name in scope.assigned:
                return None
            scope = scope.parent
        return None

    def assignment(self, name):
        """(scope, [value nodes]) of the nearest scope that binds `name`, or (None, None)."""
        scope = self
        while scope is not None:
            if name in scope.assigned:
                return scope, scope.assigned[name]
            if name in scope.aliases:
                return None, None
            scope = scope.parent
        return None, None


def build_scope(body, parent=None, name="module", args=()) -> Scope:
    """The bindings of one scope (module, function or class body); nested functions and classes are not entered."""
    scope = Scope(parent, name)
    for arg in args:
        scope.assigned.setdefault(arg, []).append(None)

    def bind(target, value):
        if isinstance(target, ast.Name):
            scope.assigned.setdefault(target.id, []).append(value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                bind(item, None)
        elif isinstance(target, ast.Starred):
            bind(target.value, None)

    def visit(node):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            scope.assigned.setdefault(node.name, []).append(None)
            return
        if isinstance(node, ast.Lambda):
            return
        if isinstance(node, ast.Import):
            for item in node.names:
                if item.asname:
                    scope.aliases[item.asname] = item.name
                else:
                    head = item.name.split(".")[0]
                    scope.aliases[head] = head
        elif isinstance(node, ast.ImportFrom):
            for item in node.names:
                if item.name != "*" and node.module and node.level == 0:
                    scope.aliases[item.asname or item.name] = f"{node.module}.{item.name}"
                elif item.name != "*":
                    scope.assigned.setdefault(item.asname or item.name, []).append(None)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                bind(target, node.value if len(node.targets) == 1 else None)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            bind(node.target, node.value)
        elif isinstance(node, ast.AugAssign):
            bind(node.target, None)
            bind(node.target, None)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            bind(node.target, None)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    bind(item.optional_vars, None)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            scope.assigned.setdefault(node.name, []).append(None)
        elif isinstance(node, ast.NamedExpr):
            bind(node.target, None)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for item in node.names:
                scope.assigned.setdefault(item, []).extend([None, None])
        for child in ast.iter_child_nodes(node):
            visit(child)

    for statement in body:
        visit(statement)
    return scope


def dotted(node, scope: Scope):
    """The canonical dotted name of a Name / Attribute chain through the import aliases, or None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    head = scope.alias(node.id)
    if head is None:
        if node.id in OBFUSCATION or node.id in ("open", "len", "int", "str", "float", "bool"):
            head = node.id
        else:
            return None
    return ".".join([head, *reversed(parts)])


# --- the evaluator --------------------------------------------------------------------------------------------------

DATE_CTORS = {"datetime.date": dt.date, "datetime.datetime": dt.datetime, "datetime.timedelta": dt.timedelta}
STR_METHODS = ("lower", "upper", "strip", "lstrip", "rstrip", "casefold", "startswith", "endswith", "isdigit")


class Evaluator:
    def __init__(self, scope: Scope, world: World | None, constant_only=False):
        self.scope, self.world, self.constant_only = scope, world, constant_only
        self.depth = 0

    def read(self, family, key=None):
        if self.constant_only:
            raise _NotConstant()
        self.world.reads.add((family, key))

    def env_written(self, key):
        """Unknown when the package itself sets `key` (or any variable) somewhere in the tree (review of PRs 10-11)."""
        written = self.world.fixed.get("env_written") or ()
        if "*" in written or key in written:
            return Unknown(f"the package sets the variable {key} itself, so its value at the condition is not known")
        return None

    def ev(self, node):
        method = getattr(self, "e_" + type(node).__name__, None)
        if method is None:
            return Unknown(f"`{_text(node)}` is computed ({type(node).__name__} is not evaluated)")
        try:
            return method(node)
        except _NotConstant:
            raise
        except RecursionError:
            return Unknown("too deeply nested")

    def e_Constant(self, node):
        return node.value

    def e_Tuple(self, node):
        return self._seq(node, tuple)

    def e_List(self, node):
        return self._seq(node, list)

    def e_Set(self, node):
        return self._seq(node, lambda items: tuple(items))

    def _seq(self, node, kind):
        items = [self.ev(item) for item in node.elts]
        bad = next((item for item in items if _special(item)), None)
        return bad if bad is not None else kind(items)

    def e_Name(self, node):
        name = node.id
        canonical = self.scope.alias(name)
        if canonical is not None:
            return self.ref(canonical)
        if name in OBFUSCATION:
            return Unknown(f"obfuscated: `{name}` hides what is read")
        if name in ("len", "int", "str", "float", "bool"):
            return Ref("builtins." + name)
        if name == "__file__":
            return Unknown("`__file__` depends on where the wheel is installed")
        scope, values = self.scope.assignment(name)
        if values is None:
            return Unknown(f"`{name}` is not bound in this file")
        if len(values) != 1:
            return Unknown(f"`{name}` is assigned more than once, so its value is computed")
        if values[0] is None:
            return Unknown(f"`{name}` is not a simple assignment (a parameter, loop or import), so its value is computed")
        if self.depth >= RESOLVE_DEPTH:
            return Unknown(f"`{name}` is defined through too many names")
        self.depth += 1
        try:
            saved, self.scope = self.scope, scope
            return self.ev(values[0])
        finally:
            self.scope = saved
            self.depth -= 1

    def ref(self, name):
        if name == "os.environ":
            self.read("env")
            return Environ()
        if name == "sys.argv":
            self.read("argv")
            return list(self.world.argv)
        if name == "sys.platform":
            self.read("platform")
            return self.world.fixed["platform"]
        if name == "os.name":
            self.read("platform")
            return self.world.fixed["os_name"]
        if name == "datetime.timezone.utc":
            return dt.timezone.utc
        if name.split(".")[0] in ("importlib",):
            return Unknown(f"obfuscated: `{name}` hides what is read")
        return Ref(name)

    def e_Attribute(self, node):
        base = self.ev(node.value)
        if _special(base):
            return base
        name = node.attr
        if isinstance(base, Ref):
            return self.ref(f"{base.dotted}.{name}")
        if isinstance(base, (dt.date, dt.timedelta)) and name in ("year", "month", "day", "hour", "minute", "second",
                                                                    "days", "seconds"):
            return getattr(base, name) if hasattr(base, name) else Raised(f"no attribute {name}")
        if isinstance(base, Uname) and name in ("nodename", "sysname"):
            return getattr(base, name)
        return Bound(base, name)

    def e_Subscript(self, node):
        base, key = self.ev(node.value), self.ev(node.slice)
        for value in (base, key):
            if _special(value):
                return value
        if isinstance(base, Environ):
            if not isinstance(key, str):
                return Unknown("the variable name is computed")
            self.read("env", key)
            return self.env_written(key) or (self.world.env[key] if key in self.world.env else Raised(f"KeyError {key}"))
        if isinstance(base, (list, tuple, str)) and (isinstance(key, (int, slice)) and not isinstance(key, bool)):
            try:
                return base[key]
            except IndexError:
                return Raised("IndexError")
        return Unknown(f"`{_text(node)}` is computed")

    def e_Slice(self, node):
        parts = [self.ev(part) if part is not None else None for part in (node.lower, node.upper, node.step)]
        bad = next((part for part in parts if _special(part)), None)
        if bad is not None:
            return bad
        if not all(part is None or (isinstance(part, int) and not isinstance(part, bool)) for part in parts):
            return Unknown("a slice bound is computed")
        return slice(*parts)

    def test(self, node):
        """The truth of `node` used as a condition: Kleene logic through and / or / not (an unknown operand does not
        stop a decisive one). Used for an if / while test and for the operands of and / or / not."""
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            value = self.test(node.operand)
            return value if _special(value) else not value
        if not isinstance(node, ast.BoolOp):
            return truth(self.ev(node))
        is_and = isinstance(node.op, ast.And)
        unknown = None
        for operand in node.values:
            flag = self.test(operand)
            if isinstance(flag, Raised):
                return unknown or flag
            if isinstance(flag, Unknown):
                unknown = unknown or flag
                continue
            if flag is (not is_and):  # True for or, False for and: decisive whatever the unknown operands were
                return flag
        return unknown if unknown is not None else is_and

    def e_UnaryOp(self, node):
        if isinstance(node.op, ast.Not):
            return self.test(node)
        value = self.ev(node.operand)
        if _special(value):
            return value
        if isinstance(node.op, ast.USub) and isinstance(value, (int, float)) and not isinstance(value, bool):
            return -value
        return Unknown(f"`{_text(node)}` is computed")

    def e_BoolOp(self, node):
        """`a or b` / `a and b` as a value (Python: the deciding operand itself). An unknown operand before the
        decision makes the value unknown (review of PRs 10-11); a condition's truth goes through `test`."""
        is_and = isinstance(node.op, ast.And)
        value = None
        for operand in node.values:
            value = self.ev(operand)
            flag = truth(value)
            if _special(flag):
                return flag
            if flag is (not is_and):
                return value
        return value

    def e_Compare(self, node):
        left = self.ev(node.left)
        for op, right_node in zip(node.ops, node.comparators):
            right = self.ev(right_node)
            for value in (left, right):
                if _special(value):
                    return value
            result = self.compare(op, left, right)
            if _special(result) or not result:
                return result
            left = right
        return True

    def compare(self, op, left, right):
        if isinstance(op, (ast.In, ast.NotIn)):
            if isinstance(right, Environ):
                if not isinstance(left, str):
                    return Unknown("the variable name is computed")
                self.read("env", left)
                if self.env_written(left):
                    return self.env_written(left)
                found = left in self.world.env
            elif isinstance(right, (list, tuple, str)):
                if isinstance(right, str) and not isinstance(left, str):
                    return Raised("TypeError")
                if any(isinstance(item, (Ref, Bound, Environ, PathValue)) for item in [left, *([] if isinstance(right, str) else right)]):
                    return Unknown("a comparison with a reference")
                found = left in right
            else:
                return Unknown("`in` on a computed value")
            return found if isinstance(op, ast.In) else not found
        if any(isinstance(value, (Ref, Bound, Environ, PathValue, Uname)) for value in (left, right)):
            return Unknown("a comparison with a reference")
        operations = {ast.Eq: lambda a, b: a == b, ast.NotEq: lambda a, b: a != b, ast.Lt: lambda a, b: a < b,
                      ast.LtE: lambda a, b: a <= b, ast.Gt: lambda a, b: a > b, ast.GtE: lambda a, b: a >= b,
                      ast.Is: lambda a, b: a is b, ast.IsNot: lambda a, b: a is not b}
        if isinstance(op, (ast.Is, ast.IsNot)) and not (left is None or right is None
                                                         or (isinstance(left, bool) and isinstance(right, bool))):
            return Unknown("`is` between values that are not None or booleans depends on object identity")
        try:
            return operations[type(op)](left, right)
        except TypeError:
            return Raised("TypeError")

    def e_BinOp(self, node):
        left, right = self.ev(node.left), self.ev(node.right)
        for value in (left, right):
            if _special(value):
                return value
        if isinstance(node.op, ast.Div) and isinstance(left, PathValue) and isinstance(right, str):
            return PathValue(_join(left.path, right))
        if any(isinstance(value, (Ref, Bound, Environ, PathValue, Uname)) for value in (left, right)):
            return Unknown(f"`{_text(node)}` is computed")
        operations = {ast.Add: lambda a, b: a + b, ast.Sub: lambda a, b: a - b, ast.Mult: lambda a, b: a * b,
                      ast.Div: lambda a, b: a / b, ast.FloorDiv: lambda a, b: a // b}
        if type(node.op) not in operations:
            return Unknown(f"`{_text(node)}` is computed")
        if isinstance(node.op, ast.Mult) and (isinstance(left, (str, list, tuple)) or isinstance(right, (str, list, tuple))):
            return Unknown(f"`{_text(node)}` is computed")
        try:
            return operations[type(node.op)](left, right)
        except (TypeError, ZeroDivisionError, OverflowError):
            return Raised("TypeError")

    def e_Call(self, node):
        if any(isinstance(arg, ast.Starred) for arg in node.args) or any(k.arg is None for k in node.keywords):
            return Unknown(f"`{_text(node)}` passes computed arguments")
        func = self.ev(node.func)
        if _special(func):
            return func
        args = [self.ev(arg) for arg in node.args]
        kwargs = {k.arg: self.ev(k.value) for k in node.keywords}
        bad = next((value for value in [*args, *kwargs.values()] if _special(value)), None)
        if isinstance(func, Ref):
            return self.call(func.dotted, args, kwargs, bad, node)
        if isinstance(func, Bound):
            return self.method(func.value, func.name, args, kwargs, bad, node)
        return Unknown(f"`{_text(node)}` is computed")

    def call(self, name, args, kwargs, bad, node):
        world = self.world
        if name in ("os.getenv", "os.environ.get"):
            if not args or not isinstance(args[0], str):
                return bad or Unknown("the variable name is computed")
            self.read("env", args[0])
            default = args[1] if len(args) > 1 else kwargs.get("default")
            if self.env_written(args[0]):
                return self.env_written(args[0])
            return world.env[args[0]] if args[0] in world.env else default  # an unknown default stays unknown
        if bad is not None:
            return bad
        if name in DATE_CTORS:
            try:
                return DATE_CTORS[name](*args, **kwargs)
            except (TypeError, ValueError, OverflowError):
                return Raised("bad date")
        if name in ("datetime.date.fromisoformat", "datetime.datetime.fromisoformat"):
            kind = dt.date if name.startswith("datetime.date.") else dt.datetime
            try:
                return kind.fromisoformat(args[0])
            except (TypeError, ValueError, IndexError):
                return Raised("bad ISO date")
        if name == "datetime.datetime.fromtimestamp" and args and isinstance(args[0], (int, float)):
            return dt.datetime(1970, 1, 1) + dt.timedelta(seconds=args[0])
        if name in ("time.time", "time.time_ns", "datetime.datetime.now", "datetime.datetime.utcnow",
                    "datetime.datetime.today", "datetime.date.today"):
            self.read("time")
            now = world.now
            if name == "time.time":
                return calendar.timegm(now.timetuple()) + now.microsecond / 1e6
            if name == "time.time_ns":
                return calendar.timegm(now.timetuple()) * 10 ** 9
            if name == "datetime.date.today":
                return now.date()
            if name == "datetime.datetime.now" and (args or kwargs):
                zone = args[0] if args else kwargs.get("tz")
                return now.replace(tzinfo=zone) if zone is dt.timezone.utc else Unknown("a time zone CAVR does not set")
            return now
        if name in ("os.path.exists", "os.path.isfile", "os.path.isdir", "os.path.lexists"):
            if not args or not isinstance(args[0], (str, PathValue)):
                return Unknown("the path is computed")
            return self.exists(_path(args[0]), {"os.path.isfile": "file", "os.path.isdir": "dir"}.get(name))
        if name == "os.path.expanduser":
            return _expand(args[0]) if args and isinstance(args[0], str) else Unknown("the path is computed")
        if name == "os.path.join":
            if not args or not all(isinstance(a, (str, PathValue)) for a in args):
                return Unknown("the path is computed")
            out = _path(args[0])
            for part in args[1:]:
                out = _join(out, _path(part))
            return out
        if name in ("pathlib.Path", "pathlib.PosixPath"):
            if not all(isinstance(a, (str, PathValue)) for a in args):
                return Unknown("the path is computed")
            out = "." if not args else _path(args[0])
            for part in args[1:]:
                out = _join(out, _path(part))
            return PathValue(out)
        if name in ("pathlib.Path.home", "pathlib.PosixPath.home"):
            return PathValue(HOME)
        if name in ("socket.gethostname", "platform.node"):
            self.read("host")
            return world.hostname
        if name == "os.uname":
            self.read("host")
            return Uname(world.hostname)
        if name == "getpass.getuser":
            self.read("user")
            return world.user if world.user is not None else world.fixed["user"]
        if name in ("os.getuid", "os.geteuid"):
            self.read("user")
            return world.fixed["uid"]
        if name == "os.getlogin":
            self.read("user")
            return Unknown("os.getlogin reads the login terminal, and the sandbox has none")
        if name == "platform.system":
            self.read("platform")
            return world.fixed["system"]
        if name == "builtins.len":
            try:
                return len(args[0])
            except (TypeError, IndexError):
                return Raised("TypeError")
        if name in ("builtins.int", "builtins.str", "builtins.float", "builtins.bool"):
            if len(args) == 1 and isinstance(args[0], (int, float, str, bool, type(None))):
                try:
                    return {"builtins.int": int, "builtins.str": str, "builtins.float": float,
                            "builtins.bool": bool}[name](args[0])
                except (TypeError, ValueError):
                    return Raised("ValueError")
        return Unknown(f"`{_text(node)}` is computed (a call CAVR does not model)")

    def method(self, value, name, args, kwargs, bad, node):
        if isinstance(value, Environ) and name == "get":
            if not args or not isinstance(args[0], str):
                return bad or Unknown("the variable name is computed")
            self.read("env", args[0])
            if self.env_written(args[0]):
                return self.env_written(args[0])
            if args[0] in self.world.env:
                return self.world.env[args[0]]
            return args[1] if len(args) > 1 else kwargs.get("default")
        if bad is not None:
            return bad
        if isinstance(value, str) and name in STR_METHODS:
            if any(not isinstance(a, (str, tuple)) for a in args) or kwargs:
                return Unknown(f"`{_text(node)}` is computed")
            try:
                return getattr(value, name)(*args)
            except TypeError:
                return Raised("TypeError")
        if value is None and name in STR_METHODS:
            return Raised("AttributeError on None")
        if isinstance(value, dt.date) and name in ("weekday", "isoweekday", "date", "timestamp") and not args:
            if name == "timestamp":
                if not isinstance(value, dt.datetime):
                    return Raised("AttributeError")
                return calendar.timegm(value.timetuple())
            if name == "date" and not isinstance(value, dt.datetime):
                return Raised("AttributeError")
            return getattr(value, name)()
        if isinstance(value, dt.timedelta) and name == "total_seconds" and not args:
            return value.total_seconds()
        if isinstance(value, PathValue):
            if name in FILE_METHODS and not args:
                return self.exists(value.path, {"is_file": "file", "is_dir": "dir"}.get(name))
            if name == "expanduser" and not args:
                return PathValue(_expand(value.path))
            if name == "joinpath" and all(isinstance(a, (str, PathValue)) for a in args):
                out = value.path
                for part in args:
                    out = _join(out, _path(part))
                return PathValue(out)
        return Unknown(f"`{_text(node)}` is computed (a method CAVR does not model)")

    def exists(self, path, kind=None):
        absolute = posixpath.normpath(path if path.startswith("/") else posixpath.join(WORKDIR, path))
        if not (absolute == HOME or absolute.startswith(HOME + "/")):
            return Unknown(f"{absolute} is outside the sandbox HOME ({HOME}): CAVR cannot create it, and whether the "
                           "image has it is not known statically")
        self.read("file", absolute)
        present = _present(self.world.files, absolute)
        if present is None:
            return False
        return kind is None or present == kind


class _NotConstant(Exception):
    pass


def _path(value) -> str:
    return value.path if isinstance(value, PathValue) else value


def _join(base: str, part: str) -> str:
    return part if part.startswith("/") else posixpath.join(base, part)


def _expand(path: str) -> str:
    if path == "~" or path.startswith("~/"):
        return HOME + path[1:]
    return path


def _present(files: dict, path: str):
    """"file" / "dir" / None for `path` in a world whose created files are `files` (HOME and parents are dirs)."""
    if path == HOME:
        return "dir"
    if path in files:
        return files[path]
    if any(other.startswith(path + "/") for other in files):
        return "dir"
    return None


def _text(node) -> str:
    try:
        return ast.unparse(node)[:120]
    except Exception:
        return type(node).__name__


# --- activation search ------------------------------------------------------------------------------------------------

def constants(tests, scope: Scope) -> dict:
    """The constants a set of conditions compares against, in source order, by kind."""
    found = {"str": [], "int": [], "time": [], "delta": []}

    def add(kind, value):
        if value not in found[kind]:
            found[kind].append(value)

    def visit(node, in_ctor=False, depth=0):
        if isinstance(node, ast.Name) and depth < RESOLVE_DEPTH:
            _, values = scope.assignment(node.id)
            for value in values or []:
                if value is not None:
                    visit(value, False, depth + 1)
        value = _fold(node, scope)
        if isinstance(value, str):
            add("str", value)
        elif isinstance(value, bool):
            pass
        elif isinstance(value, (int, float)) and not in_ctor:
            add("int", value)
        elif isinstance(value, (dt.date, dt.datetime)):
            add("time", value)
        elif isinstance(value, dt.timedelta):
            add("delta", value)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            for item in node.elts:
                value = _fold(item, scope)
                if isinstance(value, str):
                    add("str", value)
        ctor = isinstance(node, ast.Call) and dotted(node.func, scope) in DATE_CTORS
        for child in ast.iter_child_nodes(node):
            visit(child, ctor, depth)

    for test in tests:
        visit(test)
    return found


def _fold(node, scope):
    """The value of a sub-expression that reads nothing of the world, else None."""
    if isinstance(node, (ast.expr_context, ast.cmpop, ast.operator, ast.boolop, ast.unaryop)):
        return None
    try:
        value = Evaluator(scope, World(now=dt.datetime(2000, 1, 1)), constant_only=True).ev(node)
    except _NotConstant:
        return None
    return None if isinstance(value, (Unknown, Raised, Ref, Bound, Environ, PathValue, Uname, list, tuple, slice)) else value


def time_candidates(found, now) -> list:
    day = dt.timedelta(days=1)
    out = {now}
    for value in found["time"]:
        base = value if isinstance(value, dt.datetime) else dt.datetime(value.year, value.month, value.day, 12)
        base = base.replace(tzinfo=None)
        out.update({base - day, base + day})
        for count in found["int"]:
            if isinstance(count, int) and 0 < count <= 36500:
                out.update({base + dt.timedelta(days=count - 1), base + dt.timedelta(days=count + 1)})
        for delta in found["delta"]:
            out.update({base + delta - day, base + delta + day})
    for number in found["int"]:
        if isinstance(number, (int, float)) and 10 ** 9 <= number <= 4 * 10 ** 9:
            stamp = dt.datetime(1970, 1, 1) + dt.timedelta(seconds=number)
            out.update({stamp - day, stamp + day})
    out = sorted(t.replace(microsecond=0) for t in out if dt.datetime(1971, 1, 1) <= t <= dt.datetime(2100, 1, 1))
    return out[:MAX_TIMES]


def evaluate(tests, world):
    """The truth of all `tests` ((node, polarity, scope)) in `world`: True, False, or an Unknown."""
    unknown = None
    for node, polarity, scope in tests:
        value = Evaluator(scope, world).test(node)
        if isinstance(value, Raised):
            return False
        if isinstance(value, Unknown):
            unknown = unknown or value
            continue
        if value is not polarity:
            return False
    return unknown or True


def search(tests, now, fixed=None):
    """(activation or None, baseline_takes_it, reason, reads) for the conjunction of `tests`."""
    reads = set()
    keys = {"env": [], "file": [], "time": False, "host": False, "user": False, "argv": False}

    def run(world):
        result = evaluate(tests, world)
        reads.update(world.reads)
        result_t = result
        if result is True and world.now is not None and ("time", None) in world.reads:
            later = World(world.env, world.now + dt.timedelta(seconds=60), world.files, world.hostname, world.user,
                          world.argv, fixed)
            result_t = evaluate(tests, later)
        return result_t

    baseline_files = {path: "file" for path in CANARY_FILES}
    base_world = World(now=now, files=baseline_files, fixed=fixed)
    baseline = run(base_world)
    scopes = {id(scope): scope for _, _, scope in tests}
    found = {"str": [], "int": [], "time": [], "delta": []}
    for scope in scopes.values():
        part = constants([node for node, _, s in tests if s is scope], scope)
        for kind in found:
            found[kind] += [v for v in part[kind] if v not in found[kind]]
    invalid_hosts = []
    best, unknown = None, baseline if isinstance(baseline, Unknown) else None
    for _ in range(4):  # a key read only behind another key shows up in a later round
        for family, key in sorted(reads, key=repr):
            if family in ("env", "file") and key is not None and key not in keys[family]:
                keys[family].append(key)
            elif family in ("time", "host", "user", "argv"):
                keys[family] = True
        options = []
        for key in keys["env"]:
            if RESERVED_ENV.match(key):  # fixed by the sandbox: only its value
                values = [BASELINE_ENV.get(key)]
            elif key in BASELINE_ENV:  # a canary variable: always set; a trigger may set it to a constant, never unset
                values = [BASELINE_ENV[key]] + [v for v in ["1", "true", *found["str"]] if isinstance(v, str)]
            else:
                values = [None] + [v for v in ["1", "true", *found["str"]] if isinstance(v, str)]
            options.append([("env", key, v) for v in dict.fromkeys(values)])
        for key in keys["file"]:
            options.append([("file", key, kind) for kind in (None, "file", "dir")])
        if keys["time"]:
            options.append([("time", None, t) for t in time_candidates(found, now)])
        if keys["host"]:
            hosts = [SANDBOX["hostname"]] + [s for s in found["str"] if isinstance(s, str) and HOSTNAME.fullmatch(s)]
            invalid_hosts = [s for s in found["str"] if isinstance(s, str) and not HOSTNAME.fullmatch(s)]
            options.append([("host", None, h) for h in dict.fromkeys(hosts)])
        if keys["user"]:
            users = [None] + [s for s in found["str"] if isinstance(s, str) and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", s)]
            options.append([("user", None, u) for u in dict.fromkeys(users)])
        if keys["argv"]:
            lists = [list(SANDBOX["argv"])] + [[*SANDBOX["argv"], s] for s in found["str"] if isinstance(s, str)]
            lists += [[*SANDBOX["argv"], *["cavr-arg"] * k] for k in (1, 2, 3)]
            options.append([("argv", None, a) for a in lists])
        total = 1
        for option in options:
            total *= len(option)
        if total > MAX_COMBINATIONS:
            return None, False, (f"{total} candidate environments, more than the {MAX_COMBINATIONS} CAVR tries"), reads
        before = len(reads)
        best = None
        # The smallest change wins; between equal ones, the first in candidate order (unset, "1", "true", then the
        # constants in source order; absent, file, dir; earlier times first).
        for index, combo in enumerate(itertools.product(*options)):
            world = _world(combo, now, baseline_files, fixed)
            result = run(world)
            if result is True:
                change = _activation(combo, now)
                rank = (_changes(change), index)
                if best is None or rank < best[0]:
                    best = (rank, change)
            elif isinstance(result, Unknown) and unknown is None:
                unknown = result
        if len(reads) == before:
            break
    if baseline is True:
        return _activation((), now), True, None, reads
    if best is not None:
        return best[1], False, None, reads
    if unknown is not None:
        return None, False, unknown.why, reads
    reason = "no environment CAVR can build makes the condition true"
    if invalid_hosts:
        reason += f"; the hostname constant(s) {', '.join(map(repr, invalid_hosts))} cannot be set (not a valid hostname)"
    return None, False, reason, reads


def _world(combo, now, baseline_files, fixed):
    world = World(now=now, files=baseline_files, fixed=fixed)
    for family, key, value in combo:
        if family == "env" and value is None:
            world.env.pop(key, None)
        elif family == "env":
            world.env[key] = value
        elif family == "file" and value is not None:
            world.files[key] = value
        elif family == "time":
            world.now = value
        elif family == "host":
            world.hostname = value
        elif family == "user":
            world.user = value
        elif family == "argv":
            world.argv = value
    return world


def _activation(combo, now) -> dict:
    out = {"env": {}, "time": None, "files": {}, "hostname": None, "argv": None}
    for family, key, value in combo:
        if family == "env" and value is not None and value != BASELINE_ENV.get(key):
            out["env"][key] = value
        elif family == "file" and value is not None:
            out["files"][key] = value
        elif family == "time" and value != now:
            out["time"] = value.isoformat(timespec="seconds")
        elif family == "host" and value != SANDBOX["hostname"]:
            out["hostname"] = value
        elif family == "user" and value is not None:
            out["env"].update({"LOGNAME": value, "USER": value})
        elif family == "argv" and value != list(SANDBOX["argv"]):
            out["argv"] = value
    out["env"] = dict(sorted(out["env"].items()))
    out["files"] = dict(sorted(out["files"].items()))
    return out


def _changes(activation) -> int:
    return (len(activation["env"]) + len(activation["files"]) + (activation["time"] is not None)
            + (activation["hostname"] is not None) + (activation["argv"] is not None))


def activate(tests, now, env_written=frozenset()):
    """The activation search, and for a condition the sandbox cannot satisfy, why (another platform, UID 0)."""
    written = {"env_written": frozenset(env_written)}
    activation, baseline, reason, reads = search(tests, now, fixed=written)
    if activation is None and not reason.startswith(("obfuscated", "os.getlogin")) and "outside the sandbox HOME" not in reason:
        families = {family for family, _ in reads}
        if "platform" in families:
            for other in OTHER_PLATFORMS:
                if search(tests, now, fixed={**other, **written})[0] is not None:
                    reason = (f"the condition is true only when sys.platform is {other['platform']!r} (os.name "
                              f"{other['os_name']!r}, platform.system() {other['system']!r}); the sandbox runs Linux")
                    break
        if "user" in families and search(tests, now, fixed={"uid": 0, **written})[0] is not None:
            reason = "the condition is true only for UID 0; package code never runs as root (NFR-1)"
    return activation, baseline, reason


# --- guards and sinks ------------------------------------------------------------------------------------------------

def families_of(node, scope: Scope, depth=0) -> set:
    """The families a condition reads, found syntactically (through names assigned in its scope)."""
    found = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            if sub.id in OBFUSCATION and scope.alias(sub.id) is None:
                found.add("obfuscated")
            if scope.alias(sub.id) is None and depth < RESOLVE_DEPTH:
                _, values = scope.assignment(sub.id)
                for value in values or []:
                    if value is not None:
                        found |= families_of(value, scope, depth + 1)
        if isinstance(sub, (ast.Name, ast.Attribute)):
            name = dotted(sub, scope)
            if name:
                if name.split(".")[0] == "importlib":
                    found.add("obfuscated")
                for prefix, family in FAMILY_OF.items():
                    if name == prefix or name.startswith(prefix + "."):
                        found.add(family)
                if name.startswith(("pathlib.Path", "pathlib.PosixPath")):
                    found.add("file")
        if isinstance(sub, ast.Attribute) and sub.attr in FILE_METHODS:
            found.add("file")
    return found


class FileScan:
    """Guards and sinks of one parsed module."""

    def __init__(self, package, version, file, tree, rules):
        self.package, self.version, self.file, self.tree, self.rules = package, version, file, tree, rules
        self.module = build_scope(tree.body)
        # A `global X` in a function rebinds the module's X: it is then assigned more than once (review of PRs 10-11).
        for function in ast.walk(tree):
            if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for node in ast.walk(function):
                    if isinstance(node, ast.Global):
                        for name in node.names:
                            self.module.assigned.setdefault(name, []).append(None)
        self.functions = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        self.function_scopes = {}
        self.found = []  # (path, sink)

    def run(self):
        self.block(self.tree.body, [], self.module, "module")
        return self.found

    def scope_for(self, function, parent):
        while parent is not None and parent.name.startswith("class "):
            parent = parent.parent  # a method does not see its class's names (Python's scoping)
        key = id(function)
        if key not in self.function_scopes:
            args = [a.arg for a in function.args.posonlyargs + function.args.args + function.args.kwonlyargs]
            args += [a.arg for a in (function.args.vararg, function.args.kwarg) if a is not None]
            self.function_scopes[key] = build_scope(function.body, parent, f"function {function.name}", args)
        return self.function_scopes[key]

    def block(self, statements, path, scope, where):
        path = list(path)
        for index, statement in enumerate(statements):
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.expressions(statement.decorator_list + statement.args.defaults, path, scope, where)
                self.block(statement.body, [], self.scope_for(statement, scope), f"function {statement.name}")
                continue
            if isinstance(statement, ast.ClassDef):
                class_scope = build_scope(statement.body, scope, f"class {statement.name}")
                self.expressions(statement.decorator_list + statement.bases, path, scope, where)
                self.block(statement.body, [], class_scope, f"class {statement.name}")
                continue
            if isinstance(statement, ast.If):
                self.expressions([statement.test], path, scope, where)
                guard = (statement.test, scope, statement.lineno)
                self.block(statement.body, path + [(guard, True, "body")], scope, where)
                self.block(statement.orelse, path + [(guard, False, "else")], scope, where)
                # What follows runs only if the if / elif chain falls through: each early exit puts its negated
                # condition in front of it; a nested exit CAVR cannot state as conditions makes it opaque.
                through = _fall_through(statement, scope)
                path = path + (through if through is not None else [(guard, None, "may-exit")])
                continue
            if isinstance(statement, ast.While):
                self.expressions([statement.test], path, scope, where)
                self.block(statement.body, path + [((statement.test, scope, statement.lineno), True, "body")], scope, where)
                self.block(statement.orelse, path, scope, where)
            elif isinstance(statement, (ast.For, ast.AsyncFor)):
                self.expressions([statement.iter], path, scope, where)
                self.block(statement.body, path, scope, where)
                self.block(statement.orelse, path, scope, where)
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                self.expressions([item.context_expr for item in statement.items], path, scope, where)
                self.block(statement.body, path, scope, where)
            elif isinstance(statement, ast.Try) or type(statement).__name__ == "TryStar":
                self.block(statement.body, path, scope, where)
                for handler in statement.handlers:
                    self.block(handler.body, path, scope, where)
                self.block(statement.orelse, path, scope, where)
                self.block(statement.finalbody, path, scope, where)
            elif isinstance(statement, ast.Match):
                self.expressions([statement.subject], path, scope, where)
                for case in statement.cases:
                    self.block(case.body, path, scope, where)
            else:
                self.expressions([statement], path, scope, where)
                continue
            if _may_exit([statement]):  # a return / raise / exit inside it may skip what follows
                path = path + [((statement, scope, statement.lineno), None, "may-exit")]

    def expressions(self, nodes, path, scope, where):
        for node in nodes:
            for sub in _walk_no_defs(node):
                if isinstance(sub, ast.Call):
                    for sink in self.sinks_of_call(sub, scope, depth=0, via=[]):
                        self.found.append((path, where, sink))

    def sinks_of_call(self, call, scope, depth, via):
        name = dotted(call.func, scope)
        found = []
        if name and name.startswith("builtins."):
            name = name[len("builtins."):]
        if name in self.rules:
            capability = normalize_name(self.rules[name]["event"])
            found.append({"sink": name, "capability": capability, "line": call.lineno,
                          "via": " -> ".join(via) or None})
        is_read = (name in READ_CALLS or (isinstance(call.func, ast.Name) and call.func.id == "open"
                                          and scope.alias("open") is None)
                   or (isinstance(call.func, ast.Attribute) and call.func.attr in READ_METHODS))
        if is_read and _names_secret(call):
            found.append({"sink": name or f".{call.func.attr}", "capability": "SECRET_READ", "line": call.lineno,
                          "via": " -> ".join(via) or None})
        if (isinstance(call.func, ast.Name) and call.func.id in self.functions and depth < CALL_DEPTH
                and scope.alias(call.func.id) is None and f"{call.func.id}()" not in via):
            function = self.functions[call.func.id]
            inner = self.scope_for(function, self.module)
            for sub in _walk_no_defs_body(function.body):
                if isinstance(sub, ast.Call):
                    found += self.sinks_of_call(sub, inner, depth + 1, via + [f"{call.func.id}()"])
        return found


def _walk_no_defs(node):
    """ast.walk that does not enter nested function, class or lambda bodies."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        for child in ast.iter_child_nodes(current):
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                stack.append(child)


def _walk_no_defs_body(body):
    for statement in body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield from _walk_no_defs(statement)


def _names_secret(call) -> bool:
    for sub in ast.walk(call):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and any(m in sub.value for m in SECRET_MARKERS):
            return True
    if isinstance(call.func, ast.Attribute):
        for sub in ast.walk(call.func.value):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and any(m in sub.value for m in SECRET_MARKERS):
                return True
    return False


def _fall_through(statement, scope):
    """The (guard, polarity, "after") conditions under which control falls through an if / elif chain whose branches
    end in an exit; [] when no branch can exit; None when it cannot be stated as conditions (opaque)."""
    guard = (statement.test, scope, statement.lineno)
    body_exits, else_exits = _exits(statement.body), _exits(statement.orelse)
    if body_exits and else_exits:
        return None  # nothing after it runs through this statement
    if body_exits:
        rest = _fall_through_block(statement.orelse, scope)
        return None if rest is None else [(guard, False, "after")] + rest
    if else_exits:
        rest = _fall_through_block(statement.body, scope)
        return None if rest is None else [(guard, True, "after")] + rest
    if _may_exit(statement.body) or _may_exit(statement.orelse):
        return None
    return []


def _fall_through_block(statements, scope):
    if not statements:
        return []
    if len(statements) == 1 and isinstance(statements[0], ast.If):  # an elif
        return _fall_through(statements[0], scope)
    return None if _may_exit(statements) else []


def _may_exit(statements, in_loop=False) -> bool:
    """A return, raise or exit call anywhere in `statements` (not in nested functions or classes); break / continue
    only when they leave the block, not a loop inside it."""
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(statement, (ast.Return, ast.Raise)):
            return True
        if isinstance(statement, (ast.Break, ast.Continue)) and not in_loop:
            return True
        if isinstance(statement, ast.Expr) and _exits([statement]):
            return True
        loop = isinstance(statement, (ast.For, ast.AsyncFor, ast.While))
        for field in ("body", "orelse", "finalbody"):
            inner = getattr(statement, field, None)
            if isinstance(inner, list) and _may_exit(inner, in_loop or (loop and field == "body")):
                return True
        for handler in getattr(statement, "handlers", []) or []:
            if _may_exit(handler.body, in_loop):
                return True
        for case in getattr(statement, "cases", []) or []:
            if _may_exit(case.body, in_loop):
                return True
    return False


def env_writes(tree, scope) -> set:
    """Variables the module sets (os.environ[...] =, setdefault, pop, update, putenv, unsetenv, del); "*" when the
    name is computed or the whole mapping changes (review of PRs 10-11)."""
    found = set()

    def key_of(node):
        return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else "*"

    for node in ast.walk(tree):
        targets = []
        if isinstance(node, (ast.Assign, ast.Delete)):
            targets = node.targets
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            targets = [node.target]
        for target in targets:
            if isinstance(target, ast.Subscript) and dotted(target.value, scope) == "os.environ":
                found.add(key_of(target.slice))
        if isinstance(node, ast.Call):
            name = dotted(node.func, scope)
            if name in ("os.putenv", "os.unsetenv"):
                found.add(key_of(node.args[0]) if node.args else "*")
            elif name and name.startswith("os.environ."):
                method = name[len("os.environ."):]
                if method in ("setdefault", "pop", "__setitem__", "__delitem__"):
                    found.add(key_of(node.args[0]) if node.args else "*")
                elif method == "update" and not node.args and all(k.arg for k in node.keywords):
                    found.update(k.arg for k in node.keywords)
                elif method in ("update", "clear", "popitem", "__ior__"):
                    found.add("*")
    return found


def _exits(statements) -> bool:
    if not statements:
        return False
    last = statements[-1]
    if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
        func = last.value.func
        name = ast.unparse(func) if isinstance(func, (ast.Name, ast.Attribute)) else ""
        return name in EXITS
    return False


# --- the frontier ----------------------------------------------------------------------------------------------------

def frontier(nodes, contract, *, now=None, limit: int = LIMIT, knowledge=None) -> dict:
    """The ordered, bounded frontier of the verified tree `nodes`. Never raises."""
    now = (now or dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)).replace(microsecond=0)
    try:
        return _frontier(list(nodes or []), contract, now, limit, knowledge or {"records": seeds()})
    except Exception as exc:
        return _out(False, "INTERNAL_ERROR", f"the frontier scan failed: {type(exc).__name__}: {exc}", now)


def _frontier(nodes, contract, now, limit, knowledge):
    if not nodes:
        return _out(False, "FRONTIER_NO_WHEEL", "the tree has no wheel to scan", now)
    rules = python_sinks(knowledge)
    grants, problem = read_contract(contract)
    findings, raw, packages, writes = [], [], [], set()
    for node in sorted(nodes, key=lambda n: (str(n.get("name")), str(n.get("version")))):
        name, version = node.get("name"), node.get("version")
        try:
            data = Path(str(node.get("path"))).read_bytes()
        except (OSError, TypeError) as exc:
            return _out(False, "ARTIFACT_CHANGED", f"{name} {version}: the verified wheel cannot be read: {exc}", now)
        actual = hashlib.sha256(data).hexdigest()
        if actual != node.get("sha256"):
            return _out(False, "ARTIFACT_CHANGED", f"{name} {version}: the wheel has SHA-256 {actual}, the verified tree "
                        f"says {node.get('sha256')}; it was not scanned", now)
        packages.append({"name": name, "version": version, "sha256": actual})
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                raw += _scan_wheel(archive, name, version, rules, findings, writes)
        except WheelProblem as exc:
            findings.append({"package": name, "file": None, "kind": exc.rule, "detail": exc.reason})
        except ZIP_ERRORS as exc:
            findings.append({"package": name, "file": None, "kind": "NOT_A_WHEEL", "detail": str(exc)})
    entries, other = _entries(raw, grants, problem, now, writes)
    entries.sort(key=lambda e: (RISK_RANK[e["risk"]], -e["priority"]["score"], e["package"], e["file"], e["line"], e["id"]))
    _novelty(entries)
    entries.sort(key=lambda e: (RISK_RANK[e["risk"]], -e["priority"]["score"], e["package"], e["file"], e["line"], e["id"]))
    kept, cut = entries[:limit], entries[limit:]
    by_risk = {}
    for entry in cut:
        by_risk[entry["risk"]] = by_risk.get(entry["risk"], 0) + 1
    other.sort(key=lambda g: (g["package"], g["file"], g["line"], g["id"]))
    complete = not findings
    rule = "FRONTIER_COMPLETE" if complete else "FRONTIER_INCOMPLETE"
    reason = (f"{len(entries)} trigger(s) in front of a sink ({len(kept)} kept, {len(cut)} dropped), "
              f"{len(other)} other guard(s)")
    if not complete:
        reason += f"; not all code was scanned: {findings[0]['file'] or findings[0]['package']}: {findings[0]['detail']}"
    result = _out(complete, rule, reason, now)
    result.update({"entries": kept, "total": len(entries), "dropped": {"count": len(cut), "by_risk": by_risk},
                   "other_guards": other, "other_guards_count": len(other), "findings": findings,
                   "packages": packages, "contract_readable": problem is None})
    return result


def _scan_wheel(archive, package, version, rules, findings, writes):
    out, total = [], 0
    infos = sorted((info for info in check_entries(archive) if not info.is_dir()), key=lambda info: info.filename)
    for info in infos:
        name = info.filename
        if NATIVE.search(name) or name.lower().endswith(".pyc"):
            findings.append({"package": package, "file": name, "kind": "NOT_SCANNED", "detail": "compiled code, no source"})
            continue
        if not name.endswith(SOURCE_SUFFIXES):
            continue
        if info.file_size > MAX_SOURCE_BYTES or total + info.file_size > MAX_TOTAL_SOURCE_BYTES:
            findings.append({"package": package, "file": name, "kind": "SOURCE_TOO_LARGE", "detail": "over the scan budget"})
            continue
        total += info.file_size
        try:
            data = archive.read(info)
            encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
            tree = ast.parse(data.decode(encoding))
        except (SyntaxError, UnicodeDecodeError, LookupError, ValueError, RecursionError, MemoryError) as exc:
            findings.append({"package": package, "file": name, "kind": "PARSE_ERROR", "detail": f"{type(exc).__name__}: {exc}"})
            continue
        scan = FileScan(package, version, name, tree, rules)
        writes.update(env_writes(tree, scan.module))
        for path, where, sink in scan.run():
            out.append({"package": package, "version": version, "file": name, "path": path, "scope": where, "sink": sink})
    return out


def _entries(raw, grants, problem, now, writes=frozenset()):
    groups = {}
    for item in raw:
        if not item["path"]:
            continue
        key = (item["package"], item["version"], item["file"],
               tuple((g[2], polarity, how) for g, polarity, how in item["path"]))
        groups.setdefault(key, {"item": item, "sinks": []})["sinks"].append(item["sink"])
    entries, other = [], []
    for key, group in sorted(groups.items(), key=lambda kv: repr(kv[0])):
        item = group["item"]
        triggers, opaque = [], []
        for guard, polarity, how in item["path"]:
            node, scope, line = guard
            families = families_of(node, scope) if how != "may-exit" else set()
            (triggers if families else opaque).append((node, scope, line, polarity, how, families))
        sinks = sorted({json.dumps(s, sort_keys=True) for s in group["sinks"]})
        sinks = [json.loads(s) for s in sinks]
        ident = hashlib.sha256(json.dumps([item["package"], item["version"], item["file"],
                                           [list(k) for k in key[3]]]).encode()).hexdigest()[:16]
        if not triggers:
            last = item["path"][-1]
            other.append({"id": ident, "package": item["package"], "version": item["version"], "file": item["file"],
                          "line": last[0][2], "predicate": _text(last[0][0]), "scope": item["scope"],
                          "guards": [{"line": g[0][2], "predicate": _text(g[0][0]), "polarity": g[1], "how": g[2]}
                                     for g in item["path"]],
                          "sinks": sinks, "risk": _risk(sinks, grants, problem)[0]})
            continue
        activation, baseline, reason = activate([(t[0], t[3], t[1]) for t in triggers], now, writes)
        risk, why = _risk(sinks, grants, problem)
        confidence = min(CONFIDENCE[t[4]] for t in triggers)
        if any(s["via"] for s in sinks) and all(s["via"] for s in sinks):
            confidence = min(confidence, VIA_CALL_CONFIDENCE)
        if opaque:
            confidence *= OPAQUE_FACTOR
        sink_risk = max(SINK_RISK.get(s["capability"], DEFAULT_SINK_RISK) for s in sinks)
        entries.append({
            "id": ident, "package": item["package"], "version": item["version"], "file": item["file"],
            "line": triggers[-1][2], "scope": item["scope"],
            "guards": [{"line": t[2], "predicate": _text(t[0]), "polarity": t[3], "how": t[4]} for t in triggers],
            "predicate": " and ".join(f"({_text(t[0])})" if t[3] else f"not ({_text(t[0])})" for t in triggers),
            "families": sorted({f for t in triggers for f in t[5]}),
            "opaque_guards": [{"line": o[2], "predicate": _text(o[0]), "how": o[4]} for o in opaque],
            "sinks": sinks, "risk": risk, "risk_why": why,
            "priority": {"sink_risk": sink_risk, "reachability_confidence": round(confidence, 3), "novelty": 1.0,
                         "run_cost": 1.0, "score": 0.0, "formula": FORMULA},
            "simulable": activation is not None, "unsimulable_reason": reason if activation is None else None,
            # A guard CAVR cannot evaluate decides too: the baseline run is not known to reach the sink.
            "activation": activation, "baseline_takes_it": bool(baseline) and not opaque})
    for entry in entries:
        _score(entry)
    return entries, other


def _risk(sinks, grants, problem):
    if problem:
        return "high", f"the contract cannot be read ({problem}): every sink counts as denied"
    worst, why = "low", None
    for sink in sinks:
        capability = sink["capability"]
        scope = grants.get(capability)
        if scope is None:
            level, text = "high", f"{capability} is not granted by the contract"
        elif scope == "*":
            level, text = "low", f"{capability} is granted with scope *"
        else:
            level, text = "medium", f"{capability} is granted only for {scope!r}"
        if why is None or RISK_RANK[level] < RISK_RANK[worst]:
            worst, why = level, text
    return worst, why


def _score(entry):
    p = entry["priority"]
    p["score"] = round(p["sink_risk"] * p["reachability_confidence"] * p["novelty"] / p["run_cost"], 3)


def _novelty(entries):
    seen = set()
    for entry in entries:
        if entry["activation"] is None:
            continue
        key = json.dumps(entry["activation"], sort_keys=True)
        if key in seen:
            entry["priority"]["novelty"] = 0.5
            _score(entry)
        seen.add(key)


def _out(ok, rule, reason, now) -> dict:
    return {"version": VERSION, "ok": ok, "rule": rule, "reason": reason, "now": now.isoformat(timespec="seconds"),
            "entries": [], "total": 0, "dropped": {"count": 0, "by_risk": {}}, "other_guards": [],
            "other_guards_count": 0, "findings": [], "packages": [], "contract_readable": None}


# --- the check PR 12 calls -------------------------------------------------------------------------------------------

def frontier_residual(found, explored=()) -> dict:
    """Can the frontier still allow a deep VERIFIED? Pure; `explored` are the ids of entries a completed run explored.

    UNRESOLVED (verified_possible False) when the frontier is missing, malformed (counts that do not add up, an
    entry without an id), incomplete or truncated, when any entry is unsimulable (an explored id does not change that:
    CAVR could not build its environment), or when a simulable entry is not in `explored`. `baseline_takes_it` is a
    prediction, never evidence: PR 12 puts an id in `explored` only when a completed run (the baseline run for such an
    entry) showed the entry's sink. Otherwise status None: the frontier is no reason left.
    """
    explored = set(explored or ())
    if not isinstance(found, dict) or found.get("version") != VERSION or not isinstance(found.get("entries"), list):
        return _residual("FRONTIER_MISSING", "no trigger frontier was computed", [], [])
    entries = found["entries"]
    dropped = (found.get("dropped") or {}).get("count", 0)
    if (not all(isinstance(e, dict) and isinstance(e.get("id"), str) for e in entries)
            or found.get("total") != len(entries) + dropped
            or found.get("other_guards_count") != len(found.get("other_guards") or [])):
        return _residual("FRONTIER_MALFORMED", "the frontier's entries or counts do not add up", [], [])
    if not found.get("ok"):
        return _residual("FRONTIER_INCOMPLETE", f"the trigger frontier is incomplete: {found.get('reason')}", [], [])
    if dropped:
        return _residual("FRONTIER_TRUNCATED", f"{dropped} trigger(s) were cut from the bounded frontier and never "
                         "considered", [], [])
    unsimulable = [e["id"] for e in entries if e.get("simulable") is not True]
    unexplored = [e["id"] for e in entries if e.get("simulable") is True and e["id"] not in explored]
    if unsimulable:
        first = next(e for e in entries if e["id"] == unsimulable[0])
        return _residual("TRIGGER_UNSIMULABLE", f"{len(unsimulable)} trigger(s) CAVR cannot simulate; first: "
                         f"{first.get('package')} {first.get('file')}:{first.get('line')} `{first.get('predicate')}` "
                         f"({first.get('risk')} risk): {first.get('unsimulable_reason')}", unsimulable, unexplored)
    if unexplored:
        return _residual("TRIGGER_UNEXPLORED", f"{len(unexplored)} simulable trigger(s) were not explored by any run",
                         unsimulable, unexplored)
    return {"verified_possible": True, "status": None, "rule": "FRONTIER_EXPLORED",
            "reason": f"a run showed the sink of every one of the {len(entries)} trigger(s)",
            "unsimulable": [], "unexplored": []}


def _residual(rule, reason, unsimulable, unexplored) -> dict:
    return {"verified_possible": False, "status": "UNRESOLVED", "rule": rule, "reason": reason,
            "unsimulable": unsimulable, "unexplored": unexplored}
