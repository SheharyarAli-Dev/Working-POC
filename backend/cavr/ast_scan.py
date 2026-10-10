"""C3: light AST risk scan of the Python sources inside a wheel. Nothing is imported or run.

`scan_wheel(path)` reads every `.py` entry of the wheel (after the archive checks of
`wheel_meta.check_entries`), parses it with `ast`, and applies the rule-driven scan of
`backend.cavr.trigger_discovery.scan` (imported, not edited): calls to sensitive sinks from the
threat-repository rules, and `if` / `while` branches that gate such a call behind an environment
variable or a file-existence check. On top of that this module adds:

- sinks called through an import alias (`import socket as s`, `from subprocess import run`),
  which the rule scan misses because it compares the call text literally;
- dynamic imports and `compile` calls, as `DYNAMIC_CODE` findings;
- everything the scan cannot cover, as explicit findings.

A `.pth` file is decoded as `site.py` decodes it (UTF-8, optional BOM), not by a PEP 263 coding
line, so the lines the scan sees are the lines the interpreter would run.

The result says whether the scan covered all code in the wheel:

    NOT_A_WHEEL, ZIP_BUDGET, DUPLICATE_ENTRY, UNSAFE_PATH   from the archive checks (step 5)
    SCAN_BUDGET                a source file or the total source size is over the budget -> UNRESOLVED
    SOURCE_NOT_PARSED          a `.py` file (or a `.pth` import line) cannot be decoded
                               or parsed, or the rule scan failed on it                  -> UNRESOLVED
    PTH_EXECUTES_CODE          a `.pth` file has `import` lines; Python runs them at
                               every interpreter start, with no call site               -> UNRESOLVED
    COMPILED_CODE_NOT_SCANNED  native extensions or `.pyc` files: no source to parse     -> UNRESOLVED
    SCAN_COMPLETE              every `.py` file was parsed and scanned                   -> OK

OK does not mean "safe": the sinks and triggers found are evidence, and the pipeline judges
them against the capability contract and call-site reachability. This is a syntactic scan:
no data flow, no call graph, and a sink reached through `getattr`, a re-export or a string is
not found (see `coverage` in the result).
"""
from __future__ import annotations
import ast
import io
import tokenize
import zipfile
from pathlib import Path

from backend.cavr.trigger_discovery import scan
from backend.cavr.wheel_meta import NATIVE, ZIP_ERRORS, WheelProblem, check_entries
from backend.orchestrator.hashing import digest
from backend.threat_repo.behavior_rules import python_sinks
from backend.threat_repo.repository import seeds

ANALYZER_VERSION = "cavr-ast-scan/1"
MAX_SOURCE_BYTES = 5 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 100 * 1024 * 1024
DYNAMIC_CALLS = ("compile", "__import__", "importlib.import_module")
PARSE_ERRORS = (SyntaxError, ValueError, RecursionError, MemoryError)
# When more than one applies, the first in this order becomes the rule of the result.
INCOMPLETE = {"SOURCE_TOO_LARGE": "SCAN_BUDGET", "PARSE_ERROR": "SOURCE_NOT_PARSED",
              "PTH_EXECUTABLE": "PTH_EXECUTES_CODE", "NATIVE_EXTENSION": "COMPILED_CODE_NOT_SCANNED",
              "BYTECODE_ONLY": "COMPILED_CODE_NOT_SCANNED"}
OWN_COVERAGE = ("; import aliases of sinks resolved per module; .pth import lines scanned; "
                "native extensions and .pyc files not scanned")


def scan_wheel(path, knowledge=None) -> dict:
    """Scan the wheel at `path`. Every result has the same keys.

    `knowledge` is a threat-repository snapshot ({"records": [...]}); by default the seed
    rules are used. `rules_digest` identifies the sink rules that were applied.
    """
    fields = {"path": str(path) if path is not None else None}
    try:
        with zipfile.ZipFile(Path(path)) as archive:
            _scan(archive, fields, knowledge or {"records": seeds()})
    except WheelProblem as problem:
        return _result(problem.outcome, problem.rule, problem.reason, **fields)
    except ZIP_ERRORS + (TypeError, ValueError) as exc:
        return _result("UNRESOLVED", "NOT_A_WHEEL", f"cannot read the file as a wheel: {exc}", **fields)

    for kind, rule in INCOMPLETE.items():
        first = next((finding for finding in fields["findings"] if finding["kind"] == kind), None)
        if first:
            count = sum(INCOMPLETE.get(finding["kind"]) == rule for finding in fields["findings"])
            return _result("UNRESOLVED", rule, f"{first['file']}: {first['detail']}"
                           + (f" (and {count - 1} more)" if count > 1 else ""), **fields)
    return _result("OK", "SCAN_COMPLETE",
                   f"{fields['python_files']} Python files scanned: {len(fields['sinks'])} sink calls, "
                   f"{len(fields['triggers'])} gated branches", **fields)


# --- internals ---------------------------------------------------------------

def _scan(archive: zipfile.ZipFile, fields: dict, knowledge: dict) -> None:
    rules = python_sinks(knowledge)
    infos = sorted((info for info in check_entries(archive) if not info.is_dir()), key=lambda info: info.filename)
    findings, sinks, triggers, dynamic, parse_errors, scanned, pth_files = [], [], [], [], [], [], []
    total = 0
    fields.update(rules_digest=digest(rules), python_files=sum(info.filename.endswith(".py") for info in infos),
                  findings=findings, sinks=sinks, triggers=triggers, dynamic_code=dynamic, parse_errors=parse_errors,
                  files_scanned=scanned, pth_files=pth_files,
                  native_files=[info.filename for info in infos if NATIVE.search(info.filename)],
                  bytecode_files=[info.filename for info in infos if info.filename.lower().endswith(".pyc")])
    findings += [_finding("NATIVE_EXTENSION", name, None, "native code; there is no source to parse") for name in fields["native_files"]]
    findings += [_finding("BYTECODE_ONLY", name, None, "compiled bytecode; the source is not checked against it") for name in fields["bytecode_files"]]
    try:
        fields["coverage"] = scan({}, knowledge)["coverage"] + OWN_COVERAGE
    except Exception:
        fields["coverage"] = "rule scan coverage statement unavailable" + OWN_COVERAGE

    def scan_source(name: str, source: str) -> bool:
        """Parse and scan one source text. False (with a PARSE_ERROR finding) when that is not possible."""
        try:
            tree = ast.parse(source)
            found = scan({name: source}, knowledge)
            if found["parse_errors"]:
                raise SyntaxError(found["parse_errors"][0]["error"])
            extra_sinks, dynamic_calls = _alias_pass(name, tree, rules)
        except PARSE_ERRORS as exc:
            error = f"{type(exc).__name__}: {exc}"
        except Exception as exc:  # one file must not stop the scan of the others
            error = f"scanner failed: {type(exc).__name__}: {exc}"
        else:
            sinks.extend([{**sink, "via_alias": False} for sink in found["sinks"]] + extra_sinks)
            triggers.extend(found["triggers"])
            dynamic.extend(dynamic_calls)
            return True
        parse_errors.append({"file": name, "error": error})
        findings.append(_finding("PARSE_ERROR", name, None, f"cannot be parsed ({error})"))
        return False

    for info in infos:
        name = info.filename
        if name.endswith(".py"):
            if info.file_size > MAX_SOURCE_BYTES or total + info.file_size > MAX_TOTAL_SOURCE_BYTES:
                findings.append(_finding("SOURCE_TOO_LARGE", name, None,
                                         f"{info.file_size} bytes; over the scan budget "
                                         f"({MAX_SOURCE_BYTES} per file, {MAX_TOTAL_SOURCE_BYTES} in total)"))
                continue
            total += info.file_size
            source = _decode(archive.read(info), name, parse_errors, findings)
            if source is not None and scan_source(name, source):
                scanned.append(name)
        elif name.lower().endswith(".pth") and info.file_size <= MAX_SOURCE_BYTES:
            # Read it the way site.py does: UTF-8 with an optional BOM. A coding cookie means nothing
            # in a .pth file, so honouring one here would hide an import line from the scan.
            try:
                source = archive.read(info).decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                error = f"UnicodeDecodeError: {exc}"
                parse_errors.append({"file": name, "error": error})
                findings.append(_finding("PARSE_ERROR", name, None, f"cannot be decoded ({error})"))
                continue
            lines = source.splitlines()
            executable = [number for number, line in enumerate(lines, 1) if line.startswith(("import ", "import\t"))]
            paths = sum(1 for line in lines if line.strip() and not line.startswith(("#", "import ", "import\t")))
            pth_files.append({"file": name, "executable_lines": executable, "path_lines": paths})
            if executable:
                findings.append(_finding("PTH_EXECUTABLE", name, executable[0],
                                         "a .pth import line runs at every interpreter start"))
                # Keep the line numbers: every other line becomes an empty line.
                scan_source(name, "\n".join(line if number in executable else "" for number, line in enumerate(lines, 1)) + "\n")
            else:
                findings.append(_finding("PTH_FILE", name, None, f"adds {paths} entries to sys.path"))
        elif name.lower().endswith(".pth"):
            findings.append(_finding("SOURCE_TOO_LARGE", name, None, f"{info.file_size} bytes; over the scan budget"))

    sinks.sort(key=lambda sink: (sink["file"], sink["line"], sink["sink"]))
    triggers.sort(key=lambda trigger: (-trigger["priority"], trigger["id"]))
    dynamic.sort(key=lambda call: (call["file"], call["line"], call["call"]))
    findings += [_finding("SINK", sink["file"], sink["line"], f"{sink['sink']} ({sink['capability']})") for sink in sinks]
    findings += [_finding("TRIGGER", trigger["file"], trigger["line"], f"branch on {trigger['predicate']} gates "
                          + ", ".join(sorted({s["sink"] for s in trigger["reachable_sinks"]}))) for trigger in triggers]
    findings += [_finding("DYNAMIC_CODE", call["file"], call["line"], call["call"]) for call in dynamic]
    findings.sort(key=lambda finding: (finding["kind"], finding["file"], finding["line"] or 0, finding["detail"]))
    fields["bytes_scanned"] = sum(info.file_size for info in infos if info.filename in scanned)


def _alias_pass(name: str, tree: ast.AST, rules: dict):
    """Sinks reached through an import alias, and dynamic-code calls, in one parsed module."""
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    extra_sinks, dynamic_calls = [], []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        written = _dotted(node.func)
        if written is None:
            continue
        head, _, rest = written.partition(".")
        resolved = aliases[head] + ("." + rest if rest else "") if head in aliases else written
        if resolved.startswith("builtins."):
            resolved = resolved[len("builtins."):]
        if resolved in rules and written not in rules:
            extra_sinks.append({"file": name, "line": node.lineno, "sink": resolved, "capability": rules[resolved]["event"],
                                "rule_id": rules[resolved]["rule_id"], "via_alias": True})
        if resolved in DYNAMIC_CALLS:
            dynamic_calls.append({"file": name, "line": node.lineno, "call": resolved})
    return extra_sinks, dynamic_calls


def _dotted(node):
    """`a.b.c` for a Name / Attribute chain, otherwise None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    return ".".join([node.id, *reversed(parts)])


def _decode(data: bytes, name: str, parse_errors: list, findings: list):
    """Source text using the file's declared encoding (PEP 263), or None with a PARSE_ERROR finding."""
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        return data.decode(encoding)
    except (SyntaxError, UnicodeDecodeError, LookupError) as exc:
        error = f"{type(exc).__name__}: {exc}"
        parse_errors.append({"file": name, "error": error})
        findings.append(_finding("PARSE_ERROR", name, None, f"cannot be decoded ({error})"))
        return None


def _finding(kind: str, file: str, line, detail: str) -> dict:
    return {"kind": kind, "file": file, "line": line, "detail": detail}


def _result(outcome, rule, reason, path=None, rules_digest=None, python_files=0, files_scanned=None, bytes_scanned=0,
            findings=None, sinks=None, triggers=None, dynamic_code=None, parse_errors=None, native_files=None,
            bytecode_files=None, pth_files=None, coverage=None) -> dict:
    return {"result": outcome, "rule": rule, "reason": reason, "path": path, "analyzer_version": ANALYZER_VERSION,
            "rules_digest": rules_digest, "python_files": python_files, "files_scanned": files_scanned or [],
            "bytes_scanned": bytes_scanned, "findings": findings or [], "sinks": sinks or [], "triggers": triggers or [],
            "dynamic_code": dynamic_code or [], "parse_errors": parse_errors or [], "native_files": native_files or [],
            "bytecode_files": bytecode_files or [], "pth_files": pth_files or [], "coverage": coverage}
