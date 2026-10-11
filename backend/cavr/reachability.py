"""Which sinks found in the wheels can the project's call sites reach?

`judge_sinks(nodes, scans, contract, context)` gives every sink of the AST scan one verdict:

    ALLOWED         the contract allows its capability without a scope limit ("*") -> evidence
    GUARD_DISABLED  a reachability proof shows the project has switched it off     -> evidence
    UNREACHABLE     its module is not in the import closure of the modules the
                    project imports from these wheels                              -> evidence
    REACHABLE       none of the above                                              -> UNRESOLVED

The result is OK `NO_DENIED_SINK_REACHABLE` or UNRESOLVED `SINK_REACHABLE`; the pipeline adds
the escalation to deep analysis. A sink never makes a verdict REJECTED here: a syntactic scan
cannot tell a hostile call from an honest one.

Scoped grants. A grant such as `NETWORK_CONNECT:billing.example.com` does not clear a sink:
the scan sees that a call connects, not where to, so the scope cannot be checked here. Such a
sink is judged by reachability like a denied one.

Import closure. Entry modules are the modules of any wheel of the tree that the project
imports or uses by name (the requested package and any dependency it imports directly), plus
`sitecustomize` / `usercustomize`, which Python runs at start-up. From them every `import`
statement is followed, in all wheels; importing `a.b.c` also runs `a` and `a.b`, and
`from a import *` may bind every submodule of `a`. The closure is only a bound on what
importing can run when a module's path in the archive is the name it is imported by, so no
sink is called unreachable when

- reached code calls `__import__` or `importlib.import_module`,
- a `.pth` file of the tree adds a directory to the import path,
- no module that the project imports is a module of the wheels, or
- a wheel cannot be read;

and a sink in a file that is not an importable module always counts as reachable.
Not followed: other ways to import at run time (`runpy`, `pkgutil`, `sys.path` edits).

Reachability proof. The one proof is the existing pypdf guard,
`fast_gate.disabled_jbig2_sinks` (imported, not edited): the two `subprocess.run` calls in
`pypdf/filters.py` cannot run while `apply_configuration(jbig2dec_binary=None)` is in force.
That function looks for the text `PdfReader(` only, counts a reader once per enclosing guard
and does not ask where the names come from, so on its own it accepts projects with an
unguarded way into pypdf. Its answer is therefore accepted only when all of this holds:

- pypdf is the package that was asked for, and no other wheel of the tree imports it;
- every use of pypdf that the contract records is a call written `PdfReader(...)` or
  `apply_configuration(...)`: no alias, no `pypdf.PdfReader`, no other pypdf symbol;
- in the project's source the two names mean pypdf's and nothing else: they are imported only
  as `from pypdf import PdfReader, apply_configuration`, are never defined, assigned or
  reached as an attribute (`x.PdfReader`), and every call of them is one of the contract's
  call sites;
- every `apply_configuration` call is exactly `with apply_configuration(jbig2dec_binary=None)`;
- every reader is created as `name = PdfReader(...)` inside such a block, and that name is
  only used inside a guard block, as `name.<attribute>`, in code that runs there (not in a
  nested function, a lambda, or the lazily evaluated part of a generator expression). pypdf
  decodes a page when it is read, so a reader that leaves the block is not covered.

Known limit of the proof, also stated in the evidence (`limit`): an object taken from the
reader (a page, a stream) and used after the block is not followed.
"""
from __future__ import annotations
import ast
import hashlib
import zipfile
from pathlib import Path

from backend.cavr.context_extractor import usage_of
from backend.cavr.fast_gate import disabled_jbig2_sinks
from backend.cavr.wheel_meta import ZIP_ERRORS, WheelProblem, check_entries, read_member
from backend.threat_repo.behavior_rules import normalize_name

UNRESTRICTED_SCOPE = "*"
DYNAMIC_IMPORTS = ("__import__", "importlib.import_module")
ALWAYS_RUN = ("sitecustomize", "usercustomize")
PROOF_ID = "pypdf-jbig2dec-disabled"
READER, GUARD = "PdfReader", "apply_configuration"
PROOF_USES = {(f"pypdf.{READER}", READER), (f"pypdf.{GUARD}", GUARD)}
PROOF_LIMIT = "an object taken from the reader (a page, a stream) and used after the block is not followed"
RUNS_LATER = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
PARSE_ERRORS = (SyntaxError, ValueError, RecursionError, MemoryError)


def judge_sinks(nodes: list[dict], scans: list[dict], contract: dict, context: dict) -> dict:
    """Judge the sinks of `scans` (one scan per tree node, same order) against the contract and reachability."""
    if len(nodes) != len(scans):
        raise ValueError("one scan result is needed for every tree node")
    unrestricted = {entry["capability"] for entry in contract["allowed"] if entry["scope"] == UNRESTRICTED_SCOPE}
    scoped = {entry["capability"]: entry["scope"] for entry in contract["allowed"] if entry["scope"] != UNRESTRICTED_SCOPE}
    graph = import_graph(nodes)
    entries = sorted(_project_entries(context, contract, graph["modules"]) | {name for name in ALWAYS_RUN if name in graph["modules"]})
    reached = _closure(entries, graph["imports"])
    widened_by = [{"package": node["name"], **call} for node, scan in zip(nodes, scans) for call in scan["dynamic_code"]
                  if call["call"] in DYNAMIC_IMPORTS and module_name(call["file"]) in reached]
    widened_by += [{"package": node["name"], "file": pth["file"], "line": None, "call": "import path added by a .pth file"}
                   for node, scan in zip(nodes, scans) for pth in scan["pth_files"] if pth["path_lines"]]
    # When the closure is not a bound on what importing can run, this says why, and no sink is called unreachable.
    unbounded = None
    if not graph["complete"]:
        unbounded = "a wheel of the tree could not be read, so no module can be called unreached"
    elif any(item["line"] is None for item in widened_by):
        unbounded = "a .pth file adds an import path, so a module's place in the wheel is not the name it is imported by"
    elif not entries:
        unbounded = "none of the modules the project imports is a module of these wheels, so the imports cannot be followed"
    elif widened_by:
        unbounded = "reached code imports modules at run time"
    if unbounded:
        reached = set(graph["modules"])
    proofs = [proof for proof in (_pypdf_proof(nodes, graph, contract, context),) if proof]
    disabled = {(proof["package"], proof["file"], line) for proof in proofs for line in proof["lines"]}

    sinks = []
    for node, scan in zip(nodes, scans):
        for sink in scan["sinks"]:
            module = module_name(sink["file"])
            capability = normalize_name(sink["capability"])
            if capability in unrestricted:
                verdict, why = "ALLOWED", f"{capability} is allowed by the capability contract without a scope limit"
            elif (node["name"], sink["file"], sink["line"]) in disabled:
                verdict, why = "GUARD_DISABLED", f"disabled by the project (proof {PROOF_ID})"
            elif unbounded:
                verdict, why = "REACHABLE", unbounded
            elif module is None:
                verdict, why = "REACHABLE", "the file is not an importable module, so imports say nothing about it"
            elif module in reached:
                verdict, why = "REACHABLE", f"{module} is imported, directly or indirectly, by what the project uses"
            else:
                verdict, why = "UNREACHABLE", f"{module} is not imported by anything the project's call sites reach"
            if verdict == "REACHABLE" and capability in scoped:
                why += f"; {capability} is granted only for the scope {scoped[capability]!r}, which a static scan cannot check"
            sinks.append({"package": node["name"], "version": node["version"], "file": sink["file"], "line": sink["line"],
                          "sink": sink["sink"], "capability": capability, "module": module, "verdict": verdict, "why": why})

    fields = {"sinks": sinks, "entry_modules": entries, "modules": len(graph["modules"]), "reachable_modules": sorted(reached),
              "widened_by": widened_by, "proofs": proofs, "graph_complete": graph["complete"]}
    reachable = [sink for sink in sinks if sink["verdict"] == "REACHABLE"]
    if reachable:
        first = reachable[0]
        return {"result": "UNRESOLVED", "rule": "SINK_REACHABLE", **fields,
                "reason": f"{first['package']} {first['file']}:{first['line']} calls {first['sink']} ({first['capability']}), "
                          f"which the contract does not allow and the project's call sites can reach"
                          + (f" (and {len(reachable) - 1} more)" if len(reachable) > 1 else "")}
    return {"result": "OK", "rule": "NO_DENIED_SINK_REACHABLE", **fields,
            "reason": f"{len(sinks)} sink calls found; none is both denied by the contract and reachable from the project"}


def module_name(path: str):
    """The dotted module name of a wheel entry (`pkg/sub/mod.py` -> `pkg.sub.mod`), or None when it is not one."""
    parts = path.split("/")
    if parts[0].endswith(".data"):
        if len(parts) < 3 or parts[1] not in ("purelib", "platlib"):
            return None
        parts = parts[2:]
    if parts[0].endswith(".dist-info") or not parts[-1].endswith(".py"):
        return None
    parts[-1] = parts[-1][:-len(".py")]
    if parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts or not all(part.isidentifier() for part in parts):
        return None
    return ".".join(parts)


def import_graph(nodes: list[dict]) -> dict:
    """{"modules": {name: is a package}, "imports": {name: modules it imports}, "owners": {name: packages that
    ship it}, "complete": every wheel was read}."""
    modules, trees, owners, complete = {}, {}, {}, True
    for node in nodes:
        try:
            with zipfile.ZipFile(Path(node["path"])) as archive:
                for info in check_entries(archive):
                    name = None if info.is_dir() else module_name(info.filename)
                    if name is None:
                        continue
                    modules[name] = modules.get(name, False) or info.filename.endswith("/__init__.py")
                    owners.setdefault(name, set()).add(node["name"])
                    trees.setdefault(name, []).append(ast.parse(read_member(archive, info)))
        except (WheelProblem, KeyError, TypeError, *ZIP_ERRORS, *PARSE_ERRORS):
            complete = False
    imports = {name: set() for name in modules}
    for name, parsed in trees.items():
        package = name if modules[name] else name.rpartition(".")[0]
        for tree in parsed:
            for target in _imported(tree, package, modules):
                imports[name] |= {prefix for prefix in _prefixes(target) if prefix in modules and prefix != name}
    return {"modules": modules, "imports": imports, "owners": owners, "complete": complete}


class ProjectSources:
    """What `fast_gate.disabled_jbig2_sinks` expects of a project: `.manifest` and `.read(path)`.

    That function only reads paths under `app/` or `vendor/`. So that it sees every project
    file wherever the project keeps its code, each file is listed as `app/<its path>`. A file
    whose bytes no longer have the SHA-256 recorded in the context is not served.
    """

    def __init__(self, context: dict):
        self.root = Path(context["project_dir"])
        self.manifest = {"app/" + entry["path"]: entry["sha256"] for entry in context["files"]}

    def read(self, path: str) -> bytes:
        data = (self.root / path[len("app/"):]).read_bytes() if path in self.manifest else None
        if data is None:
            raise KeyError(path)
        if hashlib.sha256(data).hexdigest() != self.manifest[path]:
            raise ValueError(f"{path} changed after the project was read")
        return data


# --- internals ---------------------------------------------------------------

def _prefixes(dotted: str) -> list[str]:
    parts = dotted.split(".")
    return [".".join(parts[:end]) for end in range(1, len(parts) + 1)]


def _imported(tree: ast.AST, package: str, modules: dict) -> set[str]:
    """Dotted names one module may import. `package` is the package the module lives in ("" at top level)."""
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parents = package.split(".") if package else []
                if node.level - 1 > len(parents):
                    continue  # a relative import that leaves the top-level package
                parents = parents[:len(parents) - (node.level - 1)]
                base = ".".join(parents + ([node.module] if node.module else []))
            if not base:
                continue
            found.add(base)
            for alias in node.names:
                if alias.name == "*":
                    found |= {name for name in modules if name.startswith(base + ".")}
                else:
                    found.add(f"{base}.{alias.name}")
    return found


def _closure(entries: list[str], imports: dict) -> set[str]:
    reached, pending = set(), list(entries)
    while pending:
        name = pending.pop()
        if name not in reached:
            reached.add(name)
            pending.extend(imports.get(name, ()))
    return reached


def _project_entries(context: dict, contract: dict, modules: dict) -> set[str]:
    """The modules of the wheels that the project's own source imports or uses by name."""
    names = set(contract["entry_modules"])
    for record in context.get("imports", []):
        if not record["module"].startswith("."):
            names.add(record["module"])
            if record["name"]:
                names.add(f"{record['module']}.{record['name']}")
    names |= {use["symbol"] for use in context.get("call_sites", []) + context.get("references", [])}
    for star in context.get("star_imports", []):
        if not star["module"].startswith("."):
            names |= {star["module"]} | {name for name in modules if name.startswith(star["module"] + ".")}
    return {prefix for name in names for prefix in _prefixes(name) if prefix in modules}


def _pypdf_proof(nodes: list[dict], graph: dict, contract: dict, context: dict):
    """The pypdf guard proof for this tree and project, or None when the tree has no pypdf."""
    node = next((node for node in nodes if node["name"] == "pypdf"), None)
    if node is None:
        return None
    proof = {"id": PROOF_ID, "package": "pypdf", "version": node["version"], "file": "pypdf/filters.py", "accepted": False,
             "lines": [], "guard_result": [], "function": "backend.cavr.fast_gate.disabled_jbig2_sinks", "limit": PROOF_LIMIT}
    try:
        with zipfile.ZipFile(Path(node["path"])) as archive:
            info = next((info for info in check_entries(archive) if info.filename == proof["file"]), None)
            source = read_member(archive, info).decode("utf-8") if info else ""
        sources = ProjectSources(context)
        proof["guard_result"] = sorted(disabled_jbig2_sinks({"sources": {proof["file"]: source}}, sources))
        if not proof["guard_result"]:
            return {**proof, "reason": "disabled_jbig2_sinks found no disabled sink: a PdfReader call is outside "
                                       "apply_configuration(jbig2dec_binary=None), or the wheel has no guarded JBIG2 decoder"}
        import_names = node.get("import_names") or ["pypdf"]
        usage = usage_of(context, import_names)
        problem = (_other_callers(graph, contract) or _unseen_use(usage) or _foreign_names(context, import_names)
                   or _guard_problem(sources, usage))
    except Exception as exc:  # the proof must never be the reason a request fails; it is only not accepted
        return {**proof, "reason": f"the proof could not be checked: {type(exc).__name__}: {exc}"}
    if problem:
        return {**proof, "reason": "not accepted: " + problem}
    return {**proof, "accepted": True, "lines": proof["guard_result"],
            "reason": "every PdfReader of the project is created and used inside `with apply_configuration(jbig2dec_binary=None)`, "
                      "and JBIG2Decode returns before calling the external decoder when that setting is None"}


def _other_callers(graph: dict, contract: dict):
    """Code other than the project's that can call into pypdf, as text; None when there is none."""
    if contract.get("package") != "pypdf":
        return (f"pypdf is a dependency of {contract.get('package')} here; the code that calls it is in another wheel, "
                "which a guard in the project does not govern")
    ours = {name for name, packages in graph["owners"].items() if "pypdf" in packages}
    for name in sorted(graph["imports"]):
        if graph["owners"][name] != {"pypdf"} and graph["imports"][name] & ours:
            return f"{name} (another wheel of the tree) imports pypdf"
    return None


def _unseen_use(usage: dict):
    """A use of pypdf that `disabled_jbig2_sinks` does not look at, as text; None when there is none."""
    if usage["star_imports"]:
        return "the project star-imports pypdf"
    for use in usage["references"]:
        return f"{use['file']}:{use['line']} uses {use['symbol']} without calling it"
    for use in usage["call_sites"]:
        if use["kind"] != "call" or (use["symbol"], use["expression"]) not in PROOF_USES:
            return f"{use['file']}:{use['line']} enters pypdf through {use['expression']} ({use['symbol']}), which the guard does not cover"
    return None


def _foreign_names(context: dict, import_names: list[str]):
    """An import that binds `PdfReader` / `apply_configuration` to something that is not pypdf's, as text; else None."""
    for record in context["imports"]:
        if record["name"] in (READER, GUARD) or record["bound_as"] in (READER, GUARD):
            if not (record["module"] in import_names and record["name"] == record["bound_as"]):
                return (f"{record['file']}:{record['line']} imports {record['name'] or record['module']} as {record['bound_as']} "
                        f"from {record['module']}, not as pypdf's own name")
    return None


def _is_guard(expression) -> bool:
    return (isinstance(expression, ast.Call) and isinstance(expression.func, ast.Name) and expression.func.id == GUARD
            and not expression.args and len(expression.keywords) == 1 and expression.keywords[0].arg == "jbig2dec_binary"
            and isinstance(expression.keywords[0].value, ast.Constant) and expression.keywords[0].value.value is None)


def _guard_around(node, parents: dict):
    """The guard block whose body runs `node` where it is written, or None.

    Walking up from the node: code inside a nested function or a lambda runs later, and so does
    everything in a generator expression except its first iterable.
    """
    below, child, parent = None, node, parents.get(id(node))
    while parent is not None:
        if isinstance(parent, RUNS_LATER):
            return None
        if isinstance(parent, ast.GeneratorExp) and not (child is parent.generators[0] and below is child.iter):
            return None
        if isinstance(parent, ast.With) and any(child is statement for statement in parent.body) \
                and any(_is_guard(item.context_expr) for item in parent.items):
            return parent
        below, child, parent = child, parent, parents.get(id(parent))
    return None


def _guard_problem(sources: ProjectSources, usage: dict):
    """Why the project's own source does not keep every reader inside the guard, as text; None when it does."""
    sites = {name: {(use["file"], use["line"]) for use in usage["call_sites"] if use["symbol"] == f"pypdf.{name}"}
             for name in (READER, GUARD)}
    readers = 0
    for path in sorted(sources.manifest):
        where = path[len("app/"):]
        tree = ast.parse(sources.read(path))
        parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        for node in ast.walk(tree):
            at = f"{where}:{getattr(node, 'lineno', '?')}"
            defined = (node.name if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.ExceptHandler))
                       else node.arg if isinstance(node, ast.arg) else None)
            if defined in (READER, GUARD):
                return f"{at} defines its own {defined}"
            if isinstance(node, ast.Attribute) and node.attr in (READER, GUARD):
                return f"{at} reaches {node.attr} as an attribute of something else"
            if not isinstance(node, ast.Name) or node.id not in (READER, GUARD):
                continue
            call = parents.get(id(node))
            if not (isinstance(call, ast.Call) and call.func is node):
                return f"{at} uses {node.id} without calling it"
            if (where, call.lineno) not in sites[node.id]:
                return f"{at} calls a {node.id} that the contract does not trace to pypdf"
            if node.id == GUARD:
                item = parents.get(id(call))
                if not (_is_guard(call) and isinstance(item, ast.withitem) and isinstance(parents.get(id(item)), ast.With)):
                    return f"{at} calls apply_configuration in another way than `with apply_configuration(jbig2dec_binary=None)`"
            else:
                readers += 1
                problem = _reader_problem(call, parents, where)
                if problem:
                    return problem
    return None if readers else "the project has no PdfReader call"


def _reader_problem(call, parents: dict, where: str):
    """Why one `PdfReader(...)` call is not covered by the guard, as text; None when it is."""
    at = f"{where}:{call.lineno}"
    assign = parents.get(id(call))
    if not (isinstance(assign, ast.Assign) and assign.value is call and len(assign.targets) == 1
            and isinstance(assign.targets[0], ast.Name)):
        return f"{at} does not bind the reader to one plain name (`reader = PdfReader(...)`), so its later use cannot be followed"
    if _guard_around(assign, parents) is None:
        return f"{at} calls PdfReader outside the guard"
    name = assign.targets[0].id
    scope = parents.get(id(assign))
    while scope is not None and not isinstance(scope, (*RUNS_LATER, ast.Module)):
        scope = parents.get(id(scope))
    for node in ast.walk(scope):
        if isinstance(node, (ast.Global, ast.Nonlocal)) and name in node.names:
            return f"{where}:{node.lineno} makes the reader `{name}` visible outside the function"
        if isinstance(node, ast.Name) and node.id == name and node is not assign.targets[0]:
            holder = parents.get(id(node))
            as_attribute = isinstance(node.ctx, ast.Load) and isinstance(holder, ast.Attribute) and holder.value is node
            if not as_attribute or _guard_around(node, parents) is None:
                return (f"{where}:{node.lineno}: the reader `{name}` is used outside the guard, or handed on as an object; "
                        "pypdf decodes a page when it is read")
    return None
