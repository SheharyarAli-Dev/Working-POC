import pytest
from backend.satra import astscan, diff_localizer, security_contract
from test_satra_gitkit import git_do, make_settings, record, start_repo
from backend.satra.ingest import ingest_commit, prepare_run_dirs, release_run_dirs

SNIPPET_SAFE_IDOR = """
@app.get("/invoices/{invoice_id}")
def read_invoice(invoice_id: int, user=Depends(current_user)):
    row = db.find(invoice_id)
    if user["role"] != "admin" and row["owner_id"] != user["id"]:
        raise HTTPException(403, "forbidden")
    return row
"""

SNIPPET_BYPASS_IDOR = """
@app.get("/invoices/{invoice_id}")
def read_invoice(invoice_id: int, user=Depends(current_user)):
    row = db.find(invoice_id)
    return row
"""

SNIPPET_SAFE_SQL = """
@app.get("/invoices")
def search(search: str, user=Depends(current_user)):
    return conn.execute("SELECT * FROM invoices WHERE owner_id = ? AND desc LIKE ?", (user["id"], search)).fetchall()
"""

SNIPPET_UNSAFE_SQL = """
@app.get("/invoices")
def search(search: str, user=Depends(current_user)):
    return conn.execute(f"SELECT * FROM invoices WHERE owner_id = {user['id']} AND desc LIKE '%{search}%'").fetchall()
"""


def test_astscan_detects_removed_ownership_guard():
    base_tree = astscan.parse_source(SNIPPET_SAFE_IDOR)
    cand_tree = astscan.parse_source(SNIPPET_BYPASS_IDOR)

    base_fn = dict(astscan.collect_functions(base_tree))["read_invoice"]
    cand_fn = dict(astscan.collect_functions(cand_tree))["read_invoice"]

    b_scan = astscan.scan_function(base_fn)
    c_scan = astscan.scan_function(cand_fn)

    lost = set(b_scan["kinds"]) - set(c_scan["kinds"])
    gained = set(c_scan["kinds"]) - set(b_scan["kinds"])

    notes = astscan.derive_notes(lost, gained, set(b_scan["kinds"]), set(c_scan["kinds"]))
    assert "ownership check removed" in notes
    fams = astscan.families_for(b_scan["kinds"], b_scan["route"])
    assert "AUTHZ.IDOR.001" in fams


def test_astscan_detects_string_built_sql():
    base_tree = astscan.parse_source(SNIPPET_SAFE_SQL)
    cand_tree = astscan.parse_source(SNIPPET_UNSAFE_SQL)

    base_fn = dict(astscan.collect_functions(base_tree))["search"]
    cand_fn = dict(astscan.collect_functions(cand_tree))["search"]

    b_scan = astscan.scan_function(base_fn)
    c_scan = astscan.scan_function(cand_fn)

    lost = set(b_scan["kinds"]) - set(c_scan["kinds"])
    gained = set(c_scan["kinds"]) - set(b_scan["kinds"])

    notes = astscan.derive_notes(lost, gained, set(b_scan["kinds"]), set(c_scan["kinds"]))
    assert "sql statement became string-built" in notes


def test_end_to_end_localization_on_repo(tmp_path):
    repo = start_repo(tmp_path, "target")
    record(repo, {"app/main.py": SNIPPET_SAFE_IDOR, "docs/readme.md": "v1\n"}, message="base")
    idor_sha = record(repo, {"app/main.py": SNIPPET_BYPASS_IDOR}, message="idor bypass")
    docs_sha = record(repo, {"docs/readme.md": "v2\n"}, message="docs update")

    settings = make_settings(tmp_path / "ws", repo)

    # 1. Test IDOR bypass commit
    cs_idor = ingest_commit(repo, idor_sha)
    handle_idor = prepare_run_dirs(settings, repo, cs_idor)
    try:
        loc = diff_localizer.localize_change_set(cs_idor, handle_idor["baseline"], handle_idor["candidate"])
        assert len(loc["regions"]) == 1
        reg = loc["regions"][0]
        assert reg["function"] == "read_invoice"
        assert "AUTHZ.IDOR.001" in reg["families"]
        assert "ownership check removed" in reg["regression_notes"]

        contracts = security_contract.derive_contracts_for_regions(loc["regions"])
        assert len(contracts) >= 1
        assert any(c["family"] == "AUTHZ.IDOR.001" for c in contracts)
    finally:
        release_run_dirs(handle_idor)

    # 2. Test docs-only commit -> NOT_APPLICABLE
    cs_docs = ingest_commit(repo, docs_sha)
    handle_docs = prepare_run_dirs(settings, repo, cs_docs)
    try:
        loc = diff_localizer.localize_change_set(cs_docs, handle_docs["baseline"], handle_docs["candidate"])
        assert len(loc["regions"]) == 0
        assert len(loc["test_changes"]) == 0
    finally:
        release_run_dirs(handle_docs)
