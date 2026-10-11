"""C4: the capability contract of one distribution in one project.

`infer_capability_contract(distribution, context, policy)` answers two questions from real
inputs only:

1. Authority: does the project use this distribution, and where? The import names come from
   the wheel itself (`wheel_meta.read_wheel`: top_level.txt, else RECORD, else the archive), not
   from the distribution's name, and are matched against the imports and call sites that
   `context_extractor.extract_project_context` read from the project's source.
2. Allowed capabilities: what may code reached through those call sites do? A capability is
   allowed when the project policy grants it (`allowed_scopes`: "CAPABILITY:scope", where the
   scope "none" is a denial) and no threat-repository capability rule for the project's task
   denies it. A rule applies when every word of its `task` occurs in the policy's
   `project_task_description`. Everything that is not allowed is denied (default deny).

    CAPABILITY_POLICY_INVALID   no policy, or `allowed_scopes` / the task description
                                cannot be read                                       -> UNRESOLVED
    IMPORT_NAMES_UNKNOWN        no import names from a wheel were given              -> UNRESOLVED
    PROJECT_NOT_READ            no project context was given
    (or the context's own rule: PROJECT_MISSING, PROJECT_BUDGET, SOURCE_NOT_READ,
     SOURCE_NOT_PARSED)                                                              -> UNRESOLVED
    STAR_IMPORT                 `from <package> import *`: the names used cannot be
                                followed                                             -> UNRESOLVED
    NO_CALL_SITE_AUTHORITY      the project never imports the package, or imports it
                                and never uses it                                    -> UNRESOLVED
    CONTRACT_INFERRED           none of the above                                    -> OK

`digest` is the SHA-256 of the canonical JSON of everything the contract says, with every
list sorted, plus the digest of all project sources that were read. The sources are in it
because the verdict also depends on the code around a call site (see
`fast_gate.disabled_jbig2_sinks`): two project states with the same call sites and a different
guard must not share a cached verdict.

`infer(context, node)` at the end of the file is the older orchestrator contract; it is used
by `analyzer.py` until plan step 14. Its call-site evidence is the orchestrator's
`ContextService.dependency_context` plus `use_through_local_artifacts` (below), which follows
the one hop that the orchestrator's reader does not: application -> vendored LOCAL artifact -> pypdf.
"""
from __future__ import annotations
import ast
import json
import re
from pathlib import PurePosixPath

from packaging.utils import canonicalize_name

from backend.cavr.context_extractor import extract_project_context, usage_of
from backend.orchestrator.hashing import digest
from backend.threat_repo.behavior_rules import normalize_name
from backend.threat_repo.repository import active

CONTEXT_LISTS = ("files", "imports", "call_sites", "references", "star_imports")
DEFAULT_DENY = "not granted by the policy (default deny)"
APPLICATION_DIR = "app/"  # the only directory `ContextService.dependency_context` reads
PDF_IMPORT_NAME = "pypdf"  # the import name the older contract knows (its alias map says the same)


def infer_capability_contract(distribution, context=None, policy=None, knowledge=None) -> dict:
    """The contract of `distribution` in the project described by `context`. Every result has the same keys.

    `distribution` is the wheel's own metadata as `wheel_meta.read_wheel` returns it (`name`,
    `version`, `import_names`, `undeclared_import_names`). A bare package name is accepted so
    that a caller without a wheel still gets the capability rows, but its import names are
    unknown and the result is UNRESOLVED. `knowledge` is a threat-repository snapshot; by
    default the seed rules are used.
    """
    described = distribution if isinstance(distribution, dict) else {"name": distribution}
    name = described.get("name")
    fields = {"package": canonicalize_name(name) if isinstance(name, str) and name else None, "version": described.get("version"),
              "vocabulary": vocabulary(knowledge)}

    def result(outcome, rule, reason):
        return _contract(outcome, rule, reason, fields)

    capabilities, problem = _capabilities(policy, knowledge, fields["vocabulary"])
    if problem:
        return result("UNRESOLVED", "CAPABILITY_POLICY_INVALID", problem)
    fields.update(capabilities)

    import_names = _import_names(described)
    if fields["package"] is None or not import_names:
        return result("UNRESOLVED", "IMPORT_NAMES_UNKNOWN",
                      f"no import names read from a wheel of {name!r}; the project's imports cannot be matched to it")
    fields.update(import_names=import_names, import_names_source=described.get("import_names_source"))

    if not _is_context(context):
        return result("UNRESOLVED", "PROJECT_NOT_READ", "no project context: the project's source was not read")
    fields["sources_digest"] = context["sources_digest"]
    if context["result"] != "OK":
        return result("UNRESOLVED", context["rule"], "project source not fully read: " + str(context["reason"]))

    usage = usage_of(context, import_names)
    order = lambda item: (item["file"], item["line"], item.get("symbol") or item.get("module") or "", item.get("name") or "",
                          item.get("expression") or item.get("bound_as") or "")
    fields.update({key: sorted(usage[key], key=order) for key in usage})
    fields["entry_modules"] = _entry_modules(usage)
    where = ", ".join(import_names)
    if usage["star_imports"]:
        first = usage["star_imports"][0]
        return result("UNRESOLVED", "STAR_IMPORT", f"{first['file']}:{first['line']} has `from {first['module']} import *`; "
                      "the names it binds cannot be followed to call sites")
    if not usage["imports"]:
        return result("UNRESOLVED", "NO_CALL_SITE_AUTHORITY",
                      f"no call-site authority: the project never imported {fields['package']} (import names: {where})")
    if not usage["call_sites"] and not usage["references"]:
        first = fields["imports"][0]
        return result("UNRESOLVED", "NO_CALL_SITE_AUTHORITY", f"no call-site authority: {fields['package']} is imported "
                      f"({first['file']}:{first['line']}) but never used")
    return result("OK", "CONTRACT_INFERRED", f"{len(usage['call_sites'])} call sites and {len(usage['references'])} other uses "
                  f"of {fields['package']}; {len(fields['allowed'])} capabilities allowed, {len(fields['denied'])} denied")


def vocabulary(knowledge=None) -> list[str]:
    """Every capability name the threat-repository behaviour rules know, in one spelling."""
    names = set()
    for record in active(knowledge, "behaviors"):
        names.add(normalize_name(record["name"]))
        names.add(normalize_name(record["data"].get("runtime_event", record["name"])))
    return sorted(names)


# --- internals ---------------------------------------------------------------

def _contract(outcome, rule, reason, fields: dict) -> dict:
    contract = {"result": outcome, "rule": rule, "reason": reason, "package": None, "version": None, "import_names": [],
                "import_names_source": None, "imports": [], "call_sites": [], "references": [], "star_imports": [],
                "entry_modules": [], "allowed": [], "denied": [], "conflicts": [], "capability_rules": [],
                "task_description": None, "vocabulary": [], "sources_digest": None, **fields}
    contract["authority"] = "project call sites + policy allowed_scopes + threat-repository capability rules"
    rows = [{"capability": f"{entry['capability']}({entry['scope']})", "status": entry["status"],
             "evidence": entry["source"], "justification": entry["justification"]} for entry in contract["allowed"]]
    rows += [{"capability": entry["capability"], "status": "DENIED", "evidence": entry["source"],
              "justification": "Not allowed for code reached from this project's call sites"} for entry in contract["denied"]]
    contract["contract_rows"] = rows
    contract["summary"] = {f"{status.lower()}_count": sum(row["status"] == status for row in rows)
                           for status in ("REQUIRED", "OPTIONAL", "DENIED")}
    contract["digest"] = digest({key: value for key, value in contract.items()
                                 if key not in ("reason", "version", "contract_rows", "summary", "authority")})
    return contract


def _import_names(described: dict) -> list[str]:
    """Top-level import names the wheel provides, or [] when they were not given as lists of identifiers."""
    declared, undeclared = described.get("import_names"), described.get("undeclared_import_names", [])
    if not isinstance(declared, list) or not isinstance(undeclared, list):
        return []
    names = [*declared, *undeclared]
    if not all(isinstance(name, str) and name.isidentifier() for name in names):
        return []
    return sorted(set(names))


def _is_context(context) -> bool:
    return (isinstance(context, dict) and isinstance(context.get("result"), str) and "rule" in context
            and "sources_digest" in context and all(isinstance(context.get(key), list) for key in CONTEXT_LISTS))


def _entry_modules(usage: dict) -> list[str]:
    """Dotted names through which the project enters the package: what it imports and every prefix of what it uses.

    Some are modules (`pypdf`, `pypdf.filters`) and some are objects (`pypdf.PdfReader`); the
    reachability check keeps the ones that are modules of the wheel.
    """
    found = set()
    for record in usage["imports"]:
        found.add(record["module"])
        if record["name"]:
            found.add(f"{record['module']}.{record['name']}")
    for use in usage["call_sites"] + usage["references"]:
        found.add(use["symbol"])
    return sorted({".".join(parts[:end]) for parts in (name.split(".") for name in found) for end in range(1, len(parts) + 1)})


def _capabilities(policy, knowledge, names: list[str]):
    """({allowed, denied, conflicts, capability_rules, task_description}, None), or (None, reason) for an unusable policy."""
    if not isinstance(policy, dict):
        return None, "no project policy; no capability can be allowed"
    description = policy.get("project_task_description", "")
    if not isinstance(description, str):
        return None, "policy project_task_description must be text"
    scopes = policy.get("allowed_scopes", [])
    if not isinstance(scopes, list):
        return None, "policy allowed_scopes must be a list of CAPABILITY:scope entries"
    granted, refused = {}, {}
    for entry in scopes:
        capability, colon, scope = entry.partition(":") if isinstance(entry, str) else ("", "", "")
        capability, scope = normalize_name(capability.strip()), scope.strip()
        if not colon or not scope or capability not in names:
            return None, f"policy allowed_scopes entry is not a known CAPABILITY:scope: {entry!r} (known: {', '.join(names)})"
        if capability in granted or capability in refused:
            return None, f"policy allowed_scopes names {capability} more than once"
        (refused if scope.lower() == "none" else granted)[capability] = (scope, entry)

    words = set(re.findall(r"[a-z0-9]+", description.lower()))
    rules = [rule for rule in active(knowledge, "capability_rules")
             if (task := re.findall(r"[a-z0-9]+", str(rule["data"].get("task", "")).lower())) and set(task) <= words]
    rules.sort(key=lambda rule: rule["id"])
    rule_denies, rule_requires = {}, {}
    for rule in rules:
        for capability in rule["data"].get("denied", []):
            rule_denies.setdefault(normalize_name(capability), rule)
        for item in rule["data"].get("required", []):
            rule_requires.setdefault(normalize_name(item["capability"]), rule)

    allowed, denied, conflicts = [], [], []
    for capability in names:
        if capability in granted and capability not in rule_denies:
            scope, entry = granted[capability]
            rule = rule_requires.get(capability)
            allowed.append({"capability": capability, "scope": scope, "status": "REQUIRED" if rule else "OPTIONAL",
                            "source": f"policy allowed_scopes: {entry}",
                            "justification": f"Granted by the policy and required by rule {rule['id']} ({rule['name']})" if rule
                            else "Granted by the policy; no task rule requires it"})
            continue
        if capability in granted:
            conflicts.append({"capability": capability, "scope": granted[capability][0], "denied_by": rule_denies[capability]["id"]})
        if capability in refused:
            source = f"policy allowed_scopes: {refused[capability][1]}"
        elif capability in rule_denies:
            rule = rule_denies[capability]
            source = f"rule {rule['id']} denies it for the task {rule['data']['task']!r}"
        else:
            source = DEFAULT_DENY
        denied.append({"capability": capability, "source": source})
    return {"allowed": allowed, "denied": denied, "conflicts": conflicts, "task_description": description,
            "capability_rules": [{"id": rule["id"], "version": rule["version"], "task": rule["data"]["task"]} for rule in rules]}, None


def use_through_local_artifacts(context) -> list[dict]:
    """pypdf call sites that the application reaches through a vendored LOCAL artifact of the lock.

    `ContextService.dependency_context` reads `app/*.py` only, and matches a call to an import
    of the same file. When the adapter is `from vendor.invoice_pdf_safe import extract_invoice_text`,
    the `PdfReader` call is written in `vendor/invoice_pdf_safe.py`, so it finds no use of pypdf.
    This follows that one hop in the project's real source. Every link has to be there:

        1. the lock pins pypdf, and a LOCAL `.py` artifact whose file has the locked SHA-256
        2. a file in app/ imports that artifact's module
        3. the application calls what it imported: in that file, or in an app/ file that takes
           the name from that file with a relative import (`from .pdf_adapter import name`)
        4. the artifact's own source calls into pypdf

    One record per pypdf call site of link 4, in the shape of the orchestrator's attributions plus
    `through` (the chain). A missing link, or project source that was not fully read and parsed,
    gives [] and the contract stays `insufficient`. Limits: syntactic like the rest of the file;
    link 4 is per file, not per function; a re-export is followed one file deep.
    """
    packages = json.loads(context.read("dependencies.lock.json") or '{"packages":[]}').get("packages", [])
    pinned = next((p for p in packages if canonicalize_name(p["name"]) == PDF_IMPORT_NAME), None)
    local = [p for p in packages if p.get("ecosystem") == "LOCAL" and str(p.get("artifact", "")).endswith(".py")]
    if not pinned or not local:
        return []
    project = extract_project_context(context.path)
    if project["result"] != "OK":
        return []
    hashes = {entry["path"]: entry["sha256"] for entry in project["files"]}
    found = []
    for package in local:
        artifact = package["artifact"]
        if hashes.get(artifact) != package.get("sha256"):  # link 1: not in the project, or not the locked bytes
            continue
        module = artifact[:-len(".py")].replace("/", ".")
        imported = next((i for i in project["imports"] if _in_app(i) and i["module"] == module), None)  # link 2
        called = _application_call(context, project, module) if imported else None  # link 3
        if not called:
            continue
        for site in usage_of(project, [PDF_IMPORT_NAME])["call_sites"]:  # link 4
            if site["file"] != artifact:
                continue
            found.append({"package": pinned["name"], "version": pinned.get("version"), "imported_module": PDF_IMPORT_NAME,
                          "imported_name": site["symbol"].rsplit(".", 1)[-1],
                          "call_site": {"file": site["file"], "line": site["line"], "expression": site["expression"],
                                        "imported_module": PDF_IMPORT_NAME},
                          "purpose": "PDF text extraction",
                          "through": {"local_package": package["name"], "artifact": artifact, "sha256": package["sha256"],
                                      "imported_at": {"file": imported["file"], "line": imported["line"]}, "called_at": called},
                          "method": "AST: app/ import of a hash-checked LOCAL lock artifact, a call of the imported name "
                                    "in app/, and a call site in the artifact",
                          "scope": "syntactic attribution through one vendored module; no general dataflow"})
    return found


def _application_call(context, project: dict, module: str):
    """{file, line} of the first call in app/ of something imported from `module`, or None (link 3)."""
    direct = next((c for c in project["call_sites"] if _in_app(c) and c["symbol"].startswith(module + ".")), None)
    if direct:
        return {"file": direct["file"], "line": direct["line"]}
    # A re-export: app/pdf_adapter.py binds the name, app/main.py imports it from `.pdf_adapter` and calls it.
    # `context_extractor` does not follow relative imports (they are the project's own code), so the call is read here.
    exported = {(i["file"], i["bound_as"]) for i in project["imports"] if _in_app(i) and i["module"] == module and i["name"]}
    for record in project["imports"]:
        if not _in_app(record) or (_relative_target(record), record["name"]) not in exported:
            continue
        tree = ast.parse((context.path / record["file"]).read_bytes())  # the same bytes the project context parsed
        line = min((node.lineno for node in ast.walk(tree) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name) and node.func.id == record["bound_as"]), default=None)
        if line is not None:
            return {"file": record["file"], "line": line}
    return None


def _in_app(record: dict) -> bool:
    return record["file"].startswith(APPLICATION_DIR)


def _relative_target(record: dict):
    """The project file a relative `from .x import name` reads, as written; None for an absolute import or `from . import x`."""
    dots = len(record["module"]) - len(record["module"].lstrip("."))
    rest = record["module"][dots:]
    if not dots or not rest:
        return None
    base = PurePosixPath(record["file"]).parent
    for _ in range(dots - 1):
        base = base.parent
    return (base / rest.replace(".", "/")).as_posix() + ".py"


def infer(context, node):
    from backend.orchestrator.hashing import digest
    from backend.threat_repo.capability_rules import rule
    from backend.threat_repo.repository import active

    usage = context.dependency_context()
    # The orchestrator's reader sees a pypdf call only when it is written in app/. A call the
    # application reaches through a vendored LOCAL artifact is added here, with its whole chain.
    through_local = use_through_local_artifacts(context)
    is_pdf = 'pdf' in getattr(context, 'srs', '').lower() and any(
        x['package'].lower() in ('pypdf', 'pypdf2') and x['purpose'] == 'PDF text extraction'
        for x in usage.get('dependency_attributions', []) + through_local
    )
    pdf = rule(context.knowledge, 'CAP-PDF-001')
    minimum_denied = {'SECRET_ACCESS', 'NETWORK_CONNECT', 'PROCESS_CREATE', 'PERSISTENCE_WRITE', 'EXECUTE_BINARY'}
    supported = bool(is_pdf and pdf and minimum_denied.issubset(pdf['data'].get('denied', [])))
    contract = {
        'purpose': 'local invoice PDF text extraction' if is_pdf else 'unresolved',
        'vocabulary': [r['name'] for r in active(context.knowledge, 'behaviors')],
        'required': pdf['data'].get('required', []) if supported else [],
        'denied': sorted(minimum_denied | set(pdf['data'].get('denied', []) if pdf else [])),
        'evidence': usage,
        'local_artifact_use': through_local,
        'knowledge_rule': pdf['id'] if pdf else None,
        'confidence': 'rule-grounded' if supported else 'insufficient',
        'package': node['name'],
        'authority': 'SRS + actual call sites + reusable knowledge + minimum local-PDF boundary'
    }
    contract['digest'] = digest(contract)
    return contract
