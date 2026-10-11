"""C4: what the project's own source says about the packages it uses. Nothing is imported or run.

`extract_project_context(project_dir)` reads every `.py` file of the project, parses it with
`ast`, and writes down:

    imports       one record per imported name: file, line, module, name, bound_as
    call_sites    calls (and bare decorators) that go through an imported name: file, line,
                  symbol (the real dotted name), expression (as written), kind
    references    other uses of an imported name (base class, except clause, argument)
    star_imports  `from x import *` lines; the names they bind cannot be followed
    files         every file read, with the SHA-256 of its bytes; `sources_digest` is the
                  digest of that list

An imported name is resolved per file: after `import pypdf as p` the call `p.PdfReader(x)` has
the symbol `pypdf.PdfReader`, and after `from pypdf import PdfReader as R` so has `R(x)`.
Which distribution a module belongs to is not decided here; `usage_of(context, import_names)`
selects the records for the import names that a wheel really provides.

Results:

    PROJECT_MISSING     the directory does not exist                               -> UNRESOLVED
    PROJECT_BUDGET      too many files, or a file / the total is too large         -> UNRESOLVED
    SOURCE_NOT_READ     a symbolic link (not followed) or an unreadable file       -> UNRESOLVED
    SOURCE_NOT_PARSED   a `.py` file that cannot be decoded or parsed              -> UNRESOLVED
    PROJECT_READ        every `.py` file was read and parsed                       -> OK

Not read as project code: directories whose name starts with a dot, `__pycache__`,
`node_modules`, and virtual environments (a directory holding `pyvenv.cfg`).

A directory or file that cannot be examined (no permission, an I/O error) is never skipped
silently and never raises: it is listed in `not_read` and the result is SOURCE_NOT_READ. The
checks use `os.stat` / `os.lstat` and catch `OSError` themselves, because `pathlib`'s `is_file()`
and `is_symlink()` raise `PermissionError` on Python 3.12 and return False on Python 3.14.

Limits: this is syntactic. Names are resolved per file, not per scope; a call on an object
(`reader.pages`) or through `getattr` is not a call site; a local name that hides an import is
still counted as that import.
"""
from __future__ import annotations
import ast
import hashlib
import os
import stat
from pathlib import Path

from backend.orchestrator.hashing import digest

SAMPLE_PROJECT_DIR = Path(__file__).parent / "sample_project"
MAX_FILES = 5000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 50 * 1024 * 1024
SKIPPED_DIRECTORY_NAMES = ("__pycache__", "node_modules")
PARSE_ERRORS = (SyntaxError, ValueError, RecursionError, MemoryError)


def extract_project_context(project_dir=None) -> dict:
    """Imports and call sites of the project at `project_dir`. Every result has the same keys.

    Without an argument the bundled sample project is read (the dashboard path uses this).
    """
    root = Path(project_dir) if project_dir is not None else SAMPLE_PROJECT_DIR
    fields = {"project_dir": str(root)}
    try:
        is_directory = stat.S_ISDIR(os.stat(root).st_mode)
    except (FileNotFoundError, NotADirectoryError):
        is_directory = False
    except OSError as exc:  # it may exist, but this process may not look: not the same as "missing"
        reason = exc.strerror or str(exc)
        return _result("UNRESOLVED", "SOURCE_NOT_READ", f"project directory cannot be examined: {root} ({reason})",
                       not_read=[{"file": ".", "reason": reason}], **fields)
    if not is_directory:
        return _result("UNRESOLVED", "PROJECT_MISSING", f"project directory does not exist: {root}", **fields)

    paths, skipped, not_read = _python_files(root)
    fields.update(skipped_directories=skipped, not_read=not_read)
    if len(paths) > MAX_FILES:
        return _result("UNRESOLVED", "PROJECT_BUDGET", f"{len(paths)} Python files; the budget is {MAX_FILES}", **fields)

    files, imports, uses, stars, parse_errors, over_budget = [], [], [], [], [], []
    total = 0
    for relative in paths:
        try:
            size = (root / relative).stat().st_size
            if size > MAX_FILE_BYTES or total + size > MAX_TOTAL_BYTES:
                over_budget.append(relative)
                continue
            data = (root / relative).read_bytes()
        except OSError as exc:
            not_read.append({"file": relative, "reason": exc.strerror or str(exc)})
            continue
        total += len(data)
        files.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest()})
        try:
            tree = ast.parse(data)  # bytes: the file's own coding line is honoured (PEP 263)
            found = _Uses(relative, tree)
        except PARSE_ERRORS as exc:
            parse_errors.append({"file": relative, "error": f"{type(exc).__name__}: {exc}"})
            continue
        imports += found.imports
        uses += found.uses
        stars += found.stars

    order = lambda item: (item["file"], item["line"], item.get("symbol") or item.get("module") or "", item.get("name") or "")
    fields.update(files=files, sources_digest=digest({entry["path"]: entry["sha256"] for entry in files}),
                  imports=sorted(imports, key=order), star_imports=sorted(stars, key=order), parse_errors=parse_errors,
                  call_sites=sorted((use for use in uses if use["kind"] != "reference"), key=order),
                  references=sorted(({key: value for key, value in use.items() if key != "kind"}
                                     for use in uses if use["kind"] == "reference"), key=order))
    if over_budget:
        return _result("UNRESOLVED", "PROJECT_BUDGET", f"{over_budget[0]} is over the budget of {MAX_FILE_BYTES} bytes per file "
                       f"and {MAX_TOTAL_BYTES} in total" + _and_more(over_budget), **fields)
    if not_read:
        return _result("UNRESOLVED", "SOURCE_NOT_READ", f"{not_read[0]['file']} was not read: {not_read[0]['reason']}"
                       + _and_more(not_read), **fields)
    if parse_errors:
        return _result("UNRESOLVED", "SOURCE_NOT_PARSED", f"{parse_errors[0]['file']} cannot be parsed "
                       f"({parse_errors[0]['error']})" + _and_more(parse_errors), **fields)
    return _result("OK", "PROJECT_READ", f"{len(files)} Python files read: {len(fields['imports'])} imported names, "
                   f"{len(fields['call_sites'])} call sites through them", **fields)


def usage_of(context: dict, import_names) -> dict:
    """The records of `context` that belong to the top-level import names in `import_names`."""
    names = set(import_names)
    top = lambda dotted: dotted.split(".")[0]
    return {"imports": [i for i in context["imports"] if not i["module"].startswith(".") and top(i["module"]) in names],
            "call_sites": [c for c in context["call_sites"] if top(c["symbol"]) in names],
            "references": [r for r in context["references"] if top(r["symbol"]) in names],
            "star_imports": [s for s in context["star_imports"] if not s["module"].startswith(".") and top(s["module"]) in names]}


# --- internals ---------------------------------------------------------------

def _result(outcome, rule, reason, project_dir=None, files=None, sources_digest=None, imports=None, call_sites=None,
            references=None, star_imports=None, parse_errors=None, not_read=None, skipped_directories=None) -> dict:
    return {"result": outcome, "rule": rule, "reason": reason, "project_dir": project_dir, "files": files or [],
            "sources_digest": sources_digest, "imports": imports or [], "call_sites": call_sites or [],
            "references": references or [], "star_imports": star_imports or [], "parse_errors": parse_errors or [],
            "not_read": not_read or [], "skipped_directories": skipped_directories or []}


def _and_more(items: list) -> str:
    return f" (and {len(items) - 1} more)" if len(items) > 1 else ""


def _python_files(root: Path):
    """(sorted relative paths of the `.py` files, skipped directories, symbolic links that were not followed)."""
    paths, skipped, not_read = [], [], []

    def unlistable(error: OSError) -> None:
        # Without this `os.walk` skips a directory it may not list and says nothing.
        not_read.append({"file": Path(error.filename).relative_to(root).as_posix(), "reason": error.strerror or str(error)})

    for base, directories, names in os.walk(root, followlinks=False, onerror=unlistable):
        relative = lambda name: (Path(base) / name).relative_to(root).as_posix()
        kept = []
        for name in sorted(directories):
            path = Path(base) / name
            try:
                if _is_symlink(path):
                    not_read.append({"file": relative(name), "reason": "symbolic link"})
                elif name.startswith(".") or name in SKIPPED_DIRECTORY_NAMES or _is_virtualenv(path):
                    skipped.append(relative(name))
                else:
                    kept.append(name)
            except OSError as exc:  # not kept: `os.walk` does not enter it, so it is reported once
                not_read.append({"file": relative(name), "reason": exc.strerror or str(exc)})
        directories[:] = kept
        for name in sorted(names):
            if not name.endswith(".py"):
                continue
            try:
                link = _is_symlink(Path(base) / name)
            except OSError as exc:
                not_read.append({"file": relative(name), "reason": exc.strerror or str(exc)})
                continue
            if link:
                not_read.append({"file": relative(name), "reason": "symbolic link"})
            else:
                paths.append(relative(name))
    return sorted(paths), sorted(skipped), sorted(not_read, key=lambda item: item["file"])


def _is_symlink(path) -> bool:
    """Whether `path` is a symbolic link. Raises OSError when that cannot be found out."""
    return stat.S_ISLNK(os.lstat(path).st_mode)


def _is_virtualenv(directory) -> bool:
    """Whether `directory` holds a `pyvenv.cfg` file. Raises OSError when that cannot be found out (e.g. no permission)."""
    try:
        return stat.S_ISREG(os.stat(Path(directory) / "pyvenv.cfg").st_mode)
    except (FileNotFoundError, NotADirectoryError):
        return False


def _dotted(node):
    """`a.b.c` for a Name / Attribute chain, otherwise None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    return ".".join([node.id, *reversed(parts)])


class _Uses(ast.NodeVisitor):
    """Imports of one parsed file, and every use of a name those imports bind."""

    def __init__(self, file: str, tree: ast.AST):
        self.file, self.imports, self.uses, self.stars = file, [], [], []
        self.aliases = {}  # local name -> the dotted name it stands for
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    bound = alias.asname or alias.name.split(".")[0]
                    self.aliases[bound] = alias.name if alias.asname else bound
                    self.imports.append(self._import(node, alias.name, None, bound))
            elif isinstance(node, ast.ImportFrom):
                module = "." * node.level + (node.module or "")
                for alias in node.names:
                    if alias.name == "*":
                        self.stars.append({"file": file, "line": node.lineno, "module": module})
                        continue
                    bound = alias.asname or alias.name
                    self.imports.append(self._import(node, module, alias.name, bound))
                    if node.level == 0:  # a relative import is the project's own code
                        self.aliases[bound] = f"{module}.{alias.name}"
                    else:
                        self.aliases.pop(bound, None)
        self.visit(tree)

    def _import(self, node, module, name, bound) -> dict:
        return {"file": self.file, "line": node.lineno, "module": module, "name": name, "bound_as": bound}

    def _record(self, node, kind: str) -> bool:
        written = _dotted(node)
        if written is None:
            return False
        head, _, rest = written.partition(".")
        if head not in self.aliases:
            return False
        self.uses.append({"file": self.file, "line": node.lineno, "symbol": self.aliases[head] + ("." + rest if rest else ""),
                          "expression": written, "kind": kind})
        return True

    def visit_Call(self, node):
        if not self._record(node.func, "call"):
            self.visit(node.func)
        for child in [*node.args, *node.keywords]:
            self.visit(child)

    def visit_Attribute(self, node):
        if not self._record(node, "reference"):
            self.generic_visit(node)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load):
            self._record(node, "reference")

    def _decorated(self, node):
        for decorator in node.decorator_list:
            # `@functools.cache` calls the name without writing a call.
            if isinstance(decorator, ast.Call) or not self._record(decorator, "decorator"):
                self.visit(decorator)
        for field, value in ast.iter_fields(node):
            if field != "decorator_list":
                for child in value if isinstance(value, list) else [value]:
                    if isinstance(child, ast.AST):
                        self.visit(child)

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _decorated
