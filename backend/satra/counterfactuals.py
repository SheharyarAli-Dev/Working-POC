import ast
from pathlib import Path


def mutate_file_ast(file_path, operator_fn):
    p = Path(file_path)
    if not p.is_file():
        return False
    source = p.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False

    tree, modified = operator_fn(tree)
    if modified:
        ast.fix_missing_locations(tree)
        new_source = ast.unparse(tree) + "\n"
        try:
            ast.parse(new_source)
        except SyntaxError:
            return False
        p.write_text(new_source, encoding="utf-8")
        return True
    return False


def op_replace_ownership_predicate(tree):
    modified = False
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            rendered = ast.unparse(node.test).lower()
            if "owner" in rendered or "admin" in rendered or "user" in rendered:
                node.test = ast.Constant(value=False)
                modified = True
    return tree, modified


def op_remove_containment_check(tree):
    modified = False
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            new_body = []
            for stmt in node.body:
                if isinstance(stmt, ast.If):
                    rendered = ast.unparse(stmt.test).lower()
                    if "relative_to" in rendered or "commonpath" in rendered:
                        modified = True
                        continue
                new_body.append(stmt)
            if modified:
                node.body = new_body
    return tree, modified


def op_parameterized_to_fstring(tree):
    modified = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            if len(node.args) >= 2 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                query_str = node.args[0].value
                if "?" in query_str:
                    unsafe_str = query_str.replace("?", "''")
                    node.args = [ast.Constant(value=unsafe_str)]
                    modified = True
    return tree, modified


def mutate_candidate_worktree(worktree_dir, operator_name):
    work_path = Path(worktree_dir)
    target_files = list(work_path.glob("app/**/*.py")) + list(work_path.glob("*.py"))
    mutated_any = False

    for tf in target_files:
        if operator_name == "MUT_AUTHZ_IDOR_RETURN_TRUE":
            if mutate_file_ast(tf, op_replace_ownership_predicate):
                mutated_any = True
        elif operator_name == "MUT_PATH_TRAV_REMOVE_GUARD":
            if mutate_file_ast(tf, op_remove_containment_check):
                mutated_any = True
        elif operator_name == "MUT_SQLI_FSTRING":
            if mutate_file_ast(tf, op_parameterized_to_fstring):
                mutated_any = True
    return mutated_any


def mutate_ownership(root):
    path = Path(root) / "app" / "security.py"
    if not path.exists():
        path = Path(root) / "app" / "main.py"
    if not path.exists():
        return False

    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    found = False
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in ("can_access_invoice", "read_invoice"):
            for child in ast.walk(node):
                if isinstance(child, ast.If):
                    child.test = ast.Constant(value=False)
                    found = True
    if found:
        ast.fix_missing_locations(tree)
        path.write_text(ast.unparse(tree) + "\n", encoding="utf-8")
        return True
    return False
