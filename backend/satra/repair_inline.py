"""Bounded deterministic repair for handlers that read an object by id with the ownership guard removed.

No arbitrary code generation: a single known guard statement is inserted after the not-found check,
and only if the handler contains no 403 at all. The caller must re-verify the patch in the sandbox."""
import ast
from pathlib import Path

GUARD = (
    'if user["role"] != "admin" and row["owner_id"] != user["id"]:\n'
    '    raise HTTPException(403, "forbidden")'
)


def restore_inline_ownership_guard(root, handler="read_invoice", rel="app/main.py"):
    path = Path(root) / rel
    if not path.exists():
        return []
    tree = ast.parse(path.read_text())
    changed = False
    for fn in ast.walk(tree):
        if not (isinstance(fn, ast.FunctionDef) and fn.name == handler):
            continue
        if any(isinstance(n, ast.Constant) and n.value == 403 for n in ast.walk(fn)):
            continue
        at = next((i for i, s in enumerate(fn.body) if isinstance(s, ast.If) and "None" in ast.unparse(s.test)), None)
        if at is None:
            continue
        fn.body.insert(at + 1, ast.parse(GUARD).body[0])
        changed = True
    if not changed:
        return []
    ast.fix_missing_locations(tree)
    path.write_text(ast.unparse(tree) + "\n")
    return [rel]
