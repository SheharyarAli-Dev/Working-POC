"""
ASENT SATRA Security Dictionary Engine.
Contains trusted security rule specifications across the 8 core vulnerability families.
Maps rules to versioned specifications and executable pytest test files.
"""
from __future__ import annotations
from pathlib import Path

TRUSTED_DIR = Path(__file__).resolve().parent / "trusted"

RULES = [
    {
        "id": "AUTHZ.IDOR.001",
        "tier": 1,
        "cwe": "CWE-639",
        "family": "Authorization / IDOR",
        "status": "FULL",
        "applicability": ["FastAPI", "Flask", "InvoiceHub", "REST APIs"],
        "preconditions": ["object ID from request", "authenticated user", "invoice ownership binding"],
        "security_obligation": "Enforce explicit owner matching before returning or modifying invoice resources",
        "safe_outcome": "HTTP 403 Forbidden with zero data disclosure and no state modification",
        "test_file": "trusted_tests/test_authz_idor.py",
        "counterfactual_operator": "MUT_AUTHZ_IDOR_RETURN_TRUE",
        "validation_rules": ["parses", "secure baseline passes", "valid mutant killed by assertion", "repeatable", "local", "bounded runtime"],
        "runnable_counterfactual": True,
        "version": 1
    },
    {
        "id": "INJ.SQL.001",
        "tier": 1,
        "cwe": "CWE-89",
        "family": "SQL Injection",
        "status": "FULL",
        "applicability": ["FastAPI", "Flask", "SQLAlchemy", "SQLite", "PostgreSQL"],
        "preconditions": ["user-supplied query parameter", "database lookup query", "search / filter"],
        "security_obligation": "All database operations must use parameterized queries or ORM bindings; raw string interpolation forbidden",
        "safe_outcome": "Tautological payloads treated as literal strings; 0 unintended records returned",
        "test_file": "trusted_tests/test_sqli.py",
        "counterfactual_operator": "MUT_SQLI_FSTRING",
        "validation_rules": ["parses", "secure baseline passes", "syntax compliant", "repeatable", "local"],
        "runnable_counterfactual": True,
        "version": 1
    },
    {
        "id": "PATH.TRAV.001",
        "tier": 1,
        "cwe": "CWE-22",
        "family": "Path Traversal",
        "status": "FULL",
        "applicability": ["FastAPI", "Flask", "Static File Handlers", "Attachment Downloads"],
        "preconditions": ["file path parameter from request", "filesystem read / download"],
        "security_obligation": "Canonicalized file paths must be strictly contained within safe application upload directory",
        "safe_outcome": "HTTP 403 or 404; attempts to access parent directories via ../ traversal are rejected",
        "test_file": "trusted_tests/test_path_traversal.py",
        "counterfactual_operator": "MUT_PATH_TRAV_REMOVE_GUARD",
        "validation_rules": ["parses", "secure baseline passes", "local", "repeatable"],
        "runnable_counterfactual": True,
        "version": 1
    },
    {
        "id": "AUTH.REQ.001",
        "tier": 1,
        "cwe": "CWE-306",
        "family": "Authentication Required",
        "status": "FULL",
        "applicability": ["FastAPI", "Flask", "InvoiceHub"],
        "preconditions": ["state-changing route", "private resource access"],
        "security_obligation": "Require valid Bearer token for protected resources",
        "safe_outcome": "HTTP 401 Unauthorized without token",
        "test_file": "trusted_tests/test_auth_required.py",
        "counterfactual_operator": "MUT_AUTH_REMOVE_DEPENDENCY",
        "validation_rules": ["parses", "baseline passes", "local"],
        "runnable_counterfactual": True,
        "version": 1
    },
    {
        "id": "INJ.CMD.001",
        "tier": 2,
        "cwe": "CWE-78",
        "family": "Command Injection",
        "status": "PARTIAL",
        "applicability": ["FastAPI", "Flask", "CLI Utilities", "PDF Generators"],
        "preconditions": ["external tool invocation", "file conversion", "export parameter"],
        "security_obligation": "Never pass unvalidated user inputs to shell=True or system command interpreters (static check plus harmless probe)",
        "safe_outcome": "HTTP 400 Validation Error; zero subprocess invocation containing shell metacharacters",
        "test_file": None,
        "counterfactual_operator": None,
        "validation_rules": ["static AST detection", "harmless marker probe"],
        "runnable_counterfactual": False,
        "version": 1
    },
    {
        "id": "DESER.INSEC.001",
        "tier": 2,
        "cwe": "CWE-502",
        "family": "Insecure Deserialization",
        "status": "PARTIAL",
        "applicability": ["FastAPI", "Flask", "Pickle", "PyYAML"],
        "preconditions": ["request body contains binary or serialized payload"],
        "security_obligation": "Pickle loads on request data strictly forbidden; static AST detection plus rejection probe",
        "safe_outcome": "HTTP 400; unsafe object deseralization rejected",
        "test_file": None,
        "counterfactual_operator": None,
        "validation_rules": ["static AST detection"],
        "runnable_counterfactual": False,
        "version": 1
    },
    {
        "id": "SSRF.WEBHOOK.001",
        "tier": 2,
        "cwe": "CWE-918",
        "family": "Server-Side Request Forgery",
        "status": "PARTIAL",
        "applicability": ["Webhooks", "HTTP Clients", "OAuth callbacks"],
        "preconditions": ["outbound request URL supplied or influenced by client"],
        "security_obligation": "Loopback (127.0.0.1), RFC1918 private subnets, and cloud metadata (169.254.169.254) blocked via recorded stub",
        "safe_outcome": "HTTP 400 Validation Error; outbound request blocked",
        "test_file": None,
        "counterfactual_operator": None,
        "validation_rules": ["stub recording assert"],
        "runnable_counterfactual": False,
        "version": 1
    },
    {
        "id": "XSS.STORED.001",
        "tier": 2,
        "cwe": "CWE-79",
        "family": "Cross-Site Scripting (XSS)",
        "status": "PARTIAL",
        "applicability": ["HTML Templates", "Jinja2", "React SSR", "Invoice PDF Rendering"],
        "preconditions": ["invoice customer note", "HTML rendering context"],
        "security_obligation": "User-supplied text rendered into HTML contexts must be contextually escaped",
        "safe_outcome": "HTML metacharacters `<script>` escaped as `&lt;script&gt;`",
        "test_file": None,
        "counterfactual_operator": None,
        "validation_rules": ["static AST template detection"],
        "runnable_counterfactual": False,
        "version": 1
    },
    {
        "id": "AUTH.CSRF.001",
        "tier": 2,
        "cwe": "CWE-352",
        "family": "Cross-Site Request Forgery",
        "status": "PARTIAL",
        "applicability": ["Cookie Auth", "Session Based APIs"],
        "preconditions": ["cookie-authenticated session", "state-changing HTTP route"],
        "security_obligation": "State-changing request without valid anti-CSRF token rejected",
        "safe_outcome": "HTTP 403 Forbidden with CSRF failure",
        "test_file": None,
        "counterfactual_operator": None,
        "validation_rules": ["static route/cookie check"],
        "runnable_counterfactual": False,
        "version": 1
    }
]

RULE_BY_ID = {r["id"]: r for r in RULES}
RULE_BY_FAMILY = {r["family"]: r for r in RULES}


def get_rule(rule_id: str) -> dict | None:
    return RULE_BY_ID.get(rule_id)


def get_coverage_matrix() -> list[dict]:
    matrix = []
    for r in RULES:
        matrix.append({
            "id": r["id"],
            "tier": r["tier"],
            "cwe": r["cwe"],
            "family": r["family"],
            "status": r["status"],
            "runnable_counterfactual": r.get("runnable_counterfactual", False),
            "test_file": r.get("test_file"),
            "safe_outcome": r["safe_outcome"],
            "version": r["version"]
        })
    return matrix


def generate_coverage_markdown() -> str:
    lines = [
        "# SATRA Security Dictionary Coverage Matrix",
        "",
        "This matrix is automatically generated from `backend/satra/dictionary.py` and documents executable vs partial rules across vulnerability families.",
        "",
        "| ID | Tier | Family | CWE | Status | Executable Test Path | Runnable Mutant |",
        "|---|---|---|---|---|---|---|"
    ]
    for r in RULES:
        test_path = f"`{r['test_file']}`" if r.get("test_file") else "*Static / Stub Only*"
        mutant = "Yes" if r.get("runnable_counterfactual") else "No"
        lines.append(f"| {r['id']} | Tier {r['tier']} | {r['family']} | {r['cwe']} | **{r['status']}** | {test_path} | {mutant} |")
    lines.append("")
    return "\n".join(lines)
