"""Which sinks found in the wheels can the project's call sites reach?

`judge_sinks(nodes, scans, contract, context)` gives every sink of the AST scan one verdict:

    ALLOWED         its capability is allowed by the capability contract        -> evidence
    GUARD_DISABLED  a reachability proof shows the project has switched it off   -> evidence
    UNREACHABLE     its module is not in the import closure of the modules the
                    project enters the package through                           -> evidence
    REACHABLE       none of the above                                            -> UNRESOLVED

The result is OK `NO_DENIED_SINK_REACHABLE` or UNRESOLVED `SINK_REACHABLE`; the pipeline adds
the escalation to deep analysis. A sink never makes a verdict REJECTED here: a syntactic scan
cannot tell a hostile call from an honest one.

Import closure. The contract lists the dotted names the project imports and uses
(`entry_modules`). Starting from the ones that are modules of the wheels, every `import`
statement is followed, in all wheels of the tree; importing `a.b.c` also runs `a` and `a.b`,
and `from a import *` may bind every submodule of `a`. This over-approximates what importing
the entry modules can execute. It cannot follow imports made at run time, so when reached
code calls `__import__` or `importlib.import_module`, every module of the tree counts as
reached. A sink in a file that is not an importable module also counts as reachable, and so
does every sink when a wheel cannot be read.

Reachability proof. The one proof is the existing pypdf guard,
`fast_gate.disabled_jbig2_sinks` (imported, not edited): the two `subprocess.run` calls in
`pypdf/filters.py` cannot run when the project reads PDFs only inside
`with apply_configuration(jbig2dec_binary=None)`. That function looks for the text
`PdfReader(` only and counts a reader once per enclosing guard, so on its own it accepts
projects that also enter pypdf in other ways. The proof is therefore accepted only when it
returns lines and both of these hold:

- every use of pypdf that the contract records is a call written `PdfReader(...)` or
  `apply_configuration(...)`: no alias, no `pypdf.PdfReader`, no other pypdf symbol, no
  reference without a call;
- in the project's source, every `apply_configuration` call is exactly the `with` guard with
  the single keyword `jbig2dec_binary=None`, and every `PdfReader(...)` call is inside one.

Known limit of the proof: it is about where the reader is created. Pages decoded after the
`with` block has ended are not covered.
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

DYNAMIC_IMPORTS = ("__import__", "importlib.import_module")
PROOF_ID = "pypdf-jbig2dec-disabled"
PROOF_USES = {("pypdf.PdfReader", "PdfReader"), ("pypdf.apply_configuration", "apply_configuration")}
PARSE_ERRORS = (SyntaxError, ValueError, RecursionError, MemoryError)


def judge_sinks(nodes: list[dict], scans: list[dict], contract: dict, context: dict) -> dict:
    """Judge the sinks of `scans` (one scan per tree node, same order) against the contract and reachability."""
    if len(nodes) != len(scans):
        raise ValueError("one scan result is needed for every tree node")
    allowed = {entry["capability"] for entry in contract["allowed"]}
    graph = import_graph(nodes)
    entries = sorted(name for name in contract["entry_modules"] if name in graph["modules"])
    reached = _closure(entries, graph["imports"])
    widened_by = [{"package": node["name"], **call} for node, scan in zip(nodes, scans) for call in scan["dynamic_code"]
                  if call["call"] in DYNAMIC_IMPORTS and module_name(call["file"]) in reached]
    if widened_by:
        reached = set(graph["modules"])
    proofs = [proof for proof in (_pypdf_proof(nodes, context),) if proof]
    disabled = {(proof["package"], proof["file"], line) for proof in proofs for line in proof["lines"]}

    sinks = []
    for node, scan in zip(nodes, scans):
        for sink in scan["sinks"]:
            module = module_name(sink["file"])
            capability = normalize_name(sink["capability"])
            if capability in allowed:
                verdict, why = "ALLOWED", f"{capability} is allowed by the capability contract"
            elif (node["name"], sink["file"], sink["line"]) in disabled:
                verdict, why = "GUARD_DISABLED", f"disabled by the project (proof {PROOF_ID})"
            elif not graph["complete"]:
                verdict, why = "REACHABLE", "a wheel of the tree could not be read, so no module can be called unreached"
            elif module is None:
                verdict, why = "REACHABLE", "the file is not an importable module, so imports say nothing about it"
            elif module in reached:
                verdict, why = "REACHABLE", (f"{module} is imported, directly or indirectly, by what the project uses"
                                             if not widened_by else "reached code imports modules at run time")
            else:
                verdict, why = "UNREACHABLE", f"{module} is not imported by anything the project's call sites reach"
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
    """{"modules": {name: is a package}, "imports": {name: modules it imports}, "complete": every wheel was read}."""
    modules, trees, complete = {}, {}, True
    for node in nodes:
        try:
            with zipfile.ZipFile(Path(node["path"])) as archive:
                for info in check_entries(archive):
                    name = None if info.is_dir() else module_name(info.filename)
                    if name is None:
                        continue
                    modules[name] = modules.get(name, False) or info.filename.endswith("/__init__.py")
                    trees.setdefault(name, []).append(ast.parse(read_member(archive, info)))
        except (WheelProblem, KeyError, TypeError, *ZIP_ERRORS, *PARSE_ERRORS):
            complete = False
    imports = {name: set() for name in modules}
    for name, parsed in trees.items():
        package = name if modules[name] else name.rpartition(".")[0]
        for tree in parsed:
            for target in _imported(tree, package, modules):
                imports[name] |= {prefix for prefix in _prefixes(target) if prefix in modules and prefix != name}
    return {"modules": modules, "imports": imports, "complete": complete}


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


def _pypdf_proof(nodes: list[dict], context: dict):
    """The pypdf guard proof for this tree and project, or None when the tree has no pypdf."""
    node = next((node for node in nodes if node["name"] == "pypdf"), None)
    if node is None:
        return None
    proof = {"id": PROOF_ID, "package": "pypdf", "version": node["version"], "file": "pypdf/filters.py", "accepted": False,
             "lines": [], "guard_result": [], "function": "backend.cavr.fast_gate.disabled_jbig2_sinks"}
    try:
        with zipfile.ZipFile(Path(node["path"])) as archive:
            info = next((info for info in check_entries(archive) if info.filename == proof["file"]), None)
            source = read_member(archive, info).decode("utf-8") if info else ""
        sources = ProjectSources(context)
        proof["guard_result"] = sorted(disabled_jbig2_sinks({"sources": {proof["file"]: source}}, sources))
        if not proof["guard_result"]:
            return {**proof, "reason": "disabled_jbig2_sinks found no disabled sink: a PdfReader call is outside "
                                       "apply_configuration(jbig2dec_binary=None), or the wheel has no guarded JBIG2 decoder"}
        usage = usage_of(context, node.get("import_names") or ["pypdf"])
        problem = _unseen_use(usage) or _guard_problem(sources)
    except Exception as exc:  # the proof must never be the reason a request fails; it is only not accepted
        return {**proof, "reason": f"the proof could not be checked: {type(exc).__name__}: {exc}"}
    if problem:
        return {**proof, "reason": "not accepted: " + problem}
    return {**proof, "accepted": True, "lines": proof["guard_result"],
            "reason": "every PdfReader call site of the project is inside `with apply_configuration(jbig2dec_binary=None)`, "
                      "and JBIG2Decode returns before calling the external decoder when that setting is None"}


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


def _is_guard(expression) -> bool:
    return (isinstance(expression, ast.Call) and isinstance(expression.func, ast.Name) and expression.func.id == "apply_configuration"
            and not expression.args and len(expression.keywords) == 1 and expression.keywords[0].arg == "jbig2dec_binary"
            and isinstance(expression.keywords[0].value, ast.Constant) and expression.keywords[0].value.value is None)


def _guard_problem(sources: ProjectSources):
    """Why the project's own source does not keep every reader inside the guard, as text; None when it does."""
    readers = 0
    for path in sorted(sources.manifest):
        tree = ast.parse(sources.read(path))
        guards = [node for node in ast.walk(tree) if isinstance(node, ast.With)
                  and any(_is_guard(item.context_expr) for item in node.items)]
        guard_calls = {id(item.context_expr) for node in guards for item in node.items if _is_guard(item.context_expr)}
        inside = {id(inner) for node in guards for statement in node.body for inner in ast.walk(statement)}
        where = path[len("app/"):]
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id == "apply_configuration" and id(node) not in guard_calls:
                return f"{where}:{node.lineno} calls apply_configuration in another way than the guard"
            if node.func.id == "PdfReader":
                readers += 1
                if id(node) not in inside:
                    return f"{where}:{node.lineno} calls PdfReader outside the guard"
    return None if readers else "the project has no PdfReader call"
