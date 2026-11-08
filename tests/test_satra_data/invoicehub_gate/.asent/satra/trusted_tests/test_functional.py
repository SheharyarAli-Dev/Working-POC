"""Trusted functional tests: the secure behaviour must not be bought by breaking the service."""

def test_owner_can_read_extracted_text(case):
    # FR-02, FR-03: the owner reads their invoice and its locally extracted text.
    c, alice, bob, admin, i = case
    r = c.get(f"/invoices/{i}", headers=alice)
    assert r.status_code == 200
    assert "Invoice" in r.json()["text"]


def test_admin_can_view_any_invoice(case):
    # FR-04: an administrator may view invoices.
    c, alice, bob, admin, i = case
    assert c.get(f"/invoices/{i}", headers=admin).status_code == 200
    assert i in [row["id"] for row in c.get("/admin/invoices", headers=admin).json()]


def test_owner_can_delete_own_invoice(case, upload):
    # FR-04: a user may delete their own invoice.
    c, alice, *_ = case
    j = upload(c, alice, "mine.pdf")
    assert c.delete(f"/invoices/{j}", headers=alice).status_code == 200
    assert c.get(f"/invoices/{j}", headers=alice).status_code == 404


def test_admin_can_delete_invoice(case, upload):
    # FR-04: an administrator may delete invoices.
    c, alice, bob, admin, i = case
    j = upload(c, bob, "bobs.pdf")
    assert c.delete(f"/admin/invoices/{j}", headers=admin).status_code == 200
    assert c.get(f"/invoices/{j}", headers=bob).status_code == 404


def test_registration_and_login(case):
    # FR-01: users register and log in with a password.
    c, *_ = case
    body = {"username": "charlie", "password": "strong-password"}
    assert c.post("/auth/register", json=body).status_code == 201
    assert c.post("/auth/login", json=body).status_code == 200
