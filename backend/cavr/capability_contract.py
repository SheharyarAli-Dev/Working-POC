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
by `analyzer.py` until plan step 14 and is unchanged.
"""
from __future__ import annotations
import re

from packaging.utils import canonicalize_name

from backend.cavr.context_extractor import usage_of
from backend.orchestrator.hashing import digest
from backend.threat_repo.behavior_rules import normalize_name
from backend.threat_repo.repository import active

CONTEXT_LISTS = ("files", "imports", "call_sites", "references", "star_imports")
DEFAULT_DENY = "not granted by the policy (default deny)"


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


def infer(context, node):
    from backend.orchestrator.hashing import digest
    from backend.threat_repo.capability_rules import rule
    from backend.threat_repo.repository import active

    usage = context.dependency_context()
    is_pdf = 'pdf' in getattr(context, 'srs', '').lower() and any(
        x['package'].lower() in ('pypdf', 'pypdf2') and x['purpose'] == 'PDF text extraction'
        for x in usage.get('dependency_attributions', [])
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
        'knowledge_rule': pdf['id'] if pdf else None,
        'confidence': 'rule-grounded' if supported else 'insufficient',
        'package': node['name'],
        'authority': 'SRS + actual call sites + reusable knowledge + minimum local-PDF boundary'
    }
    contract['digest'] = digest(contract)
    return contract
