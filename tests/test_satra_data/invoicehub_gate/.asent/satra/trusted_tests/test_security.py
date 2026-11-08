"""Trusted security tests. Each test names the SRS requirement it checks."""
FIVE_MIB = 5 * 1024 * 1024
PASSWORD = "demo-password"  # seeded by create_app(seed=True)


def test_nonowner_read_denied_without_state_change(case):
    # FR-03 / contract AUTHZ.IDOR.001: another user's invoice -> 403, nothing changes.
    c, alice, bob, admin, i = case
    before = c.get("/invoices", headers=alice).json()
    assert c.get(f"/invoices/{i}", headers=bob).status_code == 403
    assert c.get("/invoices", headers=alice).json() == before


def test_nonowner_delete_denied_without_state_change(case):
    # FR-03, FR-04: a normal user cannot delete another user's invoice.
    c, alice, bob, admin, i = case
    assert c.delete(f"/invoices/{i}", headers=bob).status_code == 403
    assert c.get(f"/invoices/{i}", headers=alice).status_code == 200


def test_user_lists_only_own_invoices(case):
    # FR-03: users may list only their own invoices.
    c, alice, bob, admin, i = case
    assert i in [row["id"] for row in c.get("/invoices", headers=alice).json()]
    assert i not in [row["id"] for row in c.get("/invoices", headers=bob).json()]


def test_unauthenticated_denied(case):
    # FR-08 authentication: no token or an unknown token -> 401.
    c, alice, bob, admin, i = case
    assert c.get(f"/invoices/{i}").status_code == 401
    assert c.get(f"/invoices/{i}", headers={"Authorization": "Bearer not-a-token"}).status_code == 401
    assert c.get("/invoices").status_code == 401


def test_normal_user_cannot_call_admin_endpoints(case):
    # FR-04: a normal user cannot call administrator endpoints; denial changes nothing.
    c, alice, bob, admin, i = case
    assert c.get("/admin/invoices", headers=alice).status_code == 403
    assert c.delete(f"/admin/invoices/{i}", headers=bob).status_code == 403
    assert c.post("/admin/archive", headers=alice).status_code == 403
    assert c.get(f"/invoices/{i}", headers=alice).status_code == 200


def test_registration_never_grants_admin(case, bearer):
    # FR-01: registration never grants administrator privileges.
    c, *_ = case
    body = {"username": "mallory", "password": "mallory-password"}
    r = c.post("/auth/register", json={**body, "role": "admin"})
    assert r.status_code == 201
    assert r.json()["role"] == "user"
    headers = bearer(c, body["username"], body["password"])
    assert c.get("/auth/me", headers=headers).json()["role"] == "user"
    assert c.get("/admin/invoices", headers=headers).status_code == 403


def test_reject_non_pdf(case):
    # FR-02, FR-08 upload validation: content that is not a PDF is refused.
    c, alice, *_ = case
    r = c.post("/invoices", headers=alice, files={"file": ("../bad.txt", b"not PDF")})
    assert r.status_code == 415


def test_reject_oversized_upload(case):
    # FR-02: uploads are limited to 5 MiB.
    c, alice, *_ = case
    r = c.post("/invoices", headers=alice, files={"file": ("big.pdf", b"%PDF-" + b"0" * FIVE_MIB, "application/pdf")})
    assert r.status_code == 413


def test_sql_injection_login_refused(case):
    # FR-08: parameterized queries; a classic injection payload does not log in.
    c, *_ = case
    r = c.post("/auth/login", json={"username": "admin' OR 1=1 --", "password": PASSWORD})
    assert r.status_code in (401, 422)
