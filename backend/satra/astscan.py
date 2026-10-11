import ast
import difflib

ROUTE_VERBS = {"get", "post", "put", "delete", "patch", "route", "head", "options"}
STATE_VERBS = {"post", "put", "delete", "patch"}
SQL_CALLS = {"execute", "executemany", "executescript"}
FILE_CALLS = {"read_text", "read_bytes", "send_file", "send_from_directory", "FileResponse"}
CONTAINMENT_CALLS = {"is_relative_to", "commonpath", "relative_to", "samefile"}
COMMAND_CALLS = {"system", "popen", "getoutput", "getstatusoutput", "run", "Popen", "call", "check_output", "check_call"}
COMMAND_OWNERS = {"os", "subprocess", "commands"}
HTTP_OWNERS = {"requests", "httpx", "urllib", "urlopen", "aiohttp"}
TEMPLATE_CALLS = {"render_template_string", "Markup"}
PROTECTIVE_KINDS = {"ownership_compare", "deny_guard", "role_check", "auth_dependency", "containment_check", "sql_parameterized"}
KEYWORD_TOKENS = ("owner", "auth", "user", "role", "invoice", "password", "execute", "subprocess", "path", "pickle", "request", "token", "session")


def parse_source(text):
    try:
        return ast.parse(text)
    except (SyntaxError, ValueError):
        return None


def collect_functions(tree):
    gathered = []

    def descend(parent, trail):
        for child in ast.iter_child_nodes(parent):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                gathered.append((".".join(trail + [child.name]), child))
                descend(child, trail + [child.name])
            elif isinstance(child, ast.ClassDef):
                descend(child, trail + [child.name])
            else:
                descend(child, trail)

    descend(tree, [])
    return gathered


def own_nodes(function_node):
    pending = list(function_node.body) + list(function_node.args.defaults) + [item for item in function_node.args.kw_defaults if item is not None]
    while pending:
        current = pending.pop()
        yield current
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        pending.extend(ast.iter_child_nodes(current))


def span_start(function_node):
    firsts = [item.lineno for item in function_node.decorator_list]
    return min(firsts + [function_node.lineno])


def short(node):
    return ast.unparse(node)[:160]


def route_of(function_node):
    for decorator in function_node.decorator_list:
        if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute) and decorator.func.attr in ROUTE_VERBS:
            if decorator.args and isinstance(decorator.args[0], ast.Constant) and isinstance(decorator.args[0].value, str):
                verb = decorator.func.attr.upper()
                if verb == "ROUTE":
                    methods = [kw.value for kw in decorator.keywords if kw.arg == "methods"]
                    verb = "GET"
                    if methods and isinstance(methods[0], (ast.List, ast.Tuple)) and methods[0].elts:
                        first = methods[0].elts[0]
                        verb = str(getattr(first, "value", "GET")).upper()
                return {"method": verb, "path": decorator.args[0].value, "state_changing": verb.lower() in STATE_VERBS}
    return None


def owner_name_of(callee):
    if isinstance(callee, ast.Attribute):
        inner = callee.value
        while isinstance(inner, ast.Attribute):
            inner = inner.value
        if isinstance(inner, ast.Name):
            return inner.id
    if isinstance(callee, ast.Name):
        return callee.id
    return ""


def text_has_owner_and_actor(expression):
    rendered = ast.unparse(expression).lower()
    return "owner" in rendered and any(word in rendered for word in ("user", "current", "actor", "caller", "session"))


def raise_status(branch):
    for statement in ast.walk(branch):
        if isinstance(statement, ast.Raise) and isinstance(statement.exc, ast.Call):
            for argument in statement.exc.args:
                if isinstance(argument, ast.Constant) and argument.value in (401, 403):
                    return argument.value
            for keyword in statement.exc.keywords:
                if isinstance(keyword.value, ast.Constant) and keyword.value.value in (401, 403):
                    return keyword.value.value
        if isinstance(statement, ast.Return) and isinstance(statement.value, ast.Tuple) and len(statement.value.elts) == 2:
            tail = statement.value.elts[1]
            if isinstance(tail, ast.Constant) and tail.value in (401, 403):
                return tail.value
    return None


def sql_shape(call):
    if not call.args:
        return None
    first = call.args[0]
    built = isinstance(first, ast.JoinedStr) or (isinstance(first, ast.BinOp) and isinstance(first.op, (ast.Add, ast.Mod))) or (
        isinstance(first, ast.Call) and isinstance(first.func, ast.Attribute) and first.func.attr == "format"
    )
    if isinstance(first, ast.Name):
        return "sql_dynamic"
    if built:
        constant_only = all(isinstance(piece, ast.Constant) for piece in ast.walk(first) if not isinstance(piece, (ast.BinOp, ast.JoinedStr, ast.Add, ast.Load)))
        return "sql_parameterized" if constant_only and len(call.args) > 1 else "sql_string_built"
    return "sql_parameterized"


def scan_function(function_node):
    markers = []

    def note(kind, node, extra=None):
        entry = {"kind": kind, "line": getattr(node, "lineno", function_node.lineno), "text": short(node)}
        if extra:
            entry.update(extra)
        markers.append(entry)

    for default in list(function_node.args.defaults) + [item for item in function_node.args.kw_defaults if item is not None]:
        if isinstance(default, ast.Call) and owner_name_of(default.func) == "Depends" and default.args:
            dependency = ast.unparse(default.args[0]).lower()
            if any(word in dependency for word in ("user", "auth", "token", "session", "principal")):
                note("auth_dependency", default)
    for decorator in function_node.decorator_list:
        label = ast.unparse(decorator).lower()
        if any(word in label for word in ("login_required", "requires_auth", "jwt_required", "permission", "auth")) and route_of(function_node) is None:
            note("auth_dependency", decorator)

    for node in own_nodes(function_node):
        if isinstance(node, ast.Compare) and any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            if text_has_owner_and_actor(node):
                note("ownership_compare", node)
            rendered = ast.unparse(node).lower()
            if "role" in rendered and "admin" in rendered:
                note("role_check", node)
        if isinstance(node, ast.If):
            code = raise_status(ast.Module(body=node.body, type_ignores=[]))
            if code is not None:
                note("deny_guard", node, {"status": code})
            if any(isinstance(inner, ast.Call) and owner_name_of(inner.func) != "" and getattr(inner.func, "attr", "") in CONTAINMENT_CALLS for inner in ast.walk(node.test)):
                note("containment_check", node)
        if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
            for argument in node.exc.args:
                if isinstance(argument, ast.Constant) and argument.value == 401:
                    note("deny_guard", node, {"status": 401})
        if isinstance(node, ast.Call):
            attribute = node.func.attr if isinstance(node.func, ast.Attribute) else (node.func.id if isinstance(node.func, ast.Name) else "")
            holder = owner_name_of(node.func)
            if attribute in SQL_CALLS:
                shape = sql_shape(node)
                if shape:
                    note(shape, node)
            if attribute in COMMAND_CALLS and holder in COMMAND_OWNERS:
                shell_flag = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
                note("command_exec", node, {"shell": shell_flag})
            if attribute in FILE_CALLS or (isinstance(node.func, ast.Name) and node.func.id == "open"):
                note("file_access", node)
            if attribute in CONTAINMENT_CALLS:
                note("containment_check", node)
            if attribute in ("loads", "load") and holder in ("pickle", "cPickle", "dill", "marshal"):
                note("deserialize_pickle", node)
            if attribute in ("load", "unsafe_load") and holder == "yaml":
                note("deserialize_pickle", node)
            if holder in HTTP_OWNERS and attribute in ("get", "post", "put", "request", "urlopen", "Request", "head", "delete"):
                note("outbound_http", node)
            if attribute in TEMPLATE_CALLS or (attribute == "render" and "template" in ast.unparse(node.func).lower()):
                note("template_render", node)
            if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                note("dynamic_exec", node)
        if isinstance(node, ast.Subscript) and owner_name_of(node.value) == "session":
            note("session_use", node)
    route = route_of(function_node)
    if route and route["state_changing"]:
        note("state_changing_route", function_node)
    return {"route": route, "markers": markers, "kinds": sorted({item["kind"] for item in markers})}


def families_for(kinds, route):
    chosen = []
    kind_set = set(kinds)
    path_has_parameter = bool(route and "{" in route["path"] or route and "<" in route["path"])
    if kind_set & {"ownership_compare"} or (path_has_parameter and "deny_guard" in kind_set and "role_check" in kind_set):
        chosen.append("AUTHZ.IDOR.001")
    elif "role_check" in kind_set and "deny_guard" in kind_set:
        chosen.append("AUTHZ.ROLE.001")
    if "deny_guard" in kind_set and "ownership_compare" not in kind_set and "role_check" not in kind_set:
        chosen.append("AUTH.REQ.001")
    if "auth_dependency" in kind_set and route and route["state_changing"]:
        chosen.append("AUTH.REQ.001")
    if "auth_dependency" in kind_set and route and path_has_parameter and "AUTHZ.IDOR.001" not in chosen:
        chosen.append("AUTHZ.IDOR.001")
    if kind_set & {"sql_string_built", "sql_parameterized", "sql_dynamic"}:
        chosen.append("INJ.SQL.001")
    if kind_set & {"file_access", "containment_check"}:
        chosen.append("PATH.TRAV.001")
    if "command_exec" in kind_set:
        chosen.append("INJ.CMD.001")
    if "deserialize_pickle" in kind_set:
        chosen.append("DESER.INSEC.001")
    if "outbound_http" in kind_set:
        chosen.append("SSRF.WEBHOOK.001")
    if "template_render" in kind_set:
        chosen.append("XSS.STORED.001")
    if "state_changing_route" in kind_set and "session_use" in kind_set:
        chosen.append("AUTH.CSRF.001")
    seen = []
    for item in chosen:
        if item not in seen:
            seen.append(item)
    return seen


def keyword_score(function_node):
    rendered = ast.unparse(function_node).lower()
    return sum(rendered.count(word) for word in KEYWORD_TOKENS)


def structure_signature(function_node):
    return ast.dump(function_node, annotate_fields=False, include_attributes=False)


def changed_line_ranges(before_text, after_text):
    matcher = difflib.SequenceMatcher(a=before_text.splitlines(), b=after_text.splitlines(), autojunk=False)
    ranges = []
    for tag, first_a, last_a, first_b, last_b in matcher.get_opcodes():
        if tag == "equal":
            continue
        ranges.append({"tag": tag, "before": [first_a + 1, last_a], "after": [first_b + 1, last_b], "zero_width_after": first_b == last_b})
    return ranges


def span_touches(function_node, ranges):
    begin, finish = span_start(function_node), function_node.end_lineno
    for item in ranges:
        low, high = item["after"]
        if item["zero_width_after"]:
            if begin <= low <= finish or begin <= low + 1 <= finish:
                return True
        elif low <= finish and high >= begin:
            return True
    return False


def derive_notes(lost, gained, before_kinds, after_kinds):
    notes = []
    if lost & {"ownership_compare", "deny_guard", "role_check"} and "ownership_compare" in before_kinds and "ownership_compare" not in after_kinds:
        notes.append("ownership check removed")
    elif "deny_guard" in lost:
        notes.append("denial guard removed")
    if "auth_dependency" in lost:
        notes.append("authentication dependency removed")
    if "containment_check" in lost:
        notes.append("path containment check removed")
    if "sql_string_built" in gained and "sql_string_built" not in before_kinds:
        notes.append("sql statement became string-built")
    if "sql_dynamic" in gained:
        notes.append("sql statement built outside the call site")
    if "command_exec" in gained:
        notes.append("command execution introduced")
    if "deserialize_pickle" in gained:
        notes.append("unsafe deserialization introduced")
    if "outbound_http" in gained:
        notes.append("outbound http call introduced")
    if "template_render" in gained:
        notes.append("template rendering sink introduced")
    return notes
