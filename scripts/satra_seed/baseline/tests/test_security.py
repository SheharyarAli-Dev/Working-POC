from conftest import auth


def test_other_user_cannot_read_invoice(client):
    reply = client.get("/invoices/1", headers=auth("tok-bob"))
    assert reply.status_code == 403


def test_anonymous_cannot_read_invoice(client):
    assert client.get("/invoices/1").status_code == 401


def test_admin_can_read_any_invoice(client):
    assert client.get("/invoices/1", headers=auth("tok-admin")).status_code == 200


def test_anonymous_cannot_create_invoice(client):
    assert client.post("/invoices", json={"description": "x", "amount": 1}).status_code == 401


def test_search_attack_text_returns_no_foreign_rows(client):
    reply = client.get("/invoices", params={"search": "' OR 1=1 --"}, headers=auth("tok-alice"))
    assert reply.status_code == 200
    assert all(item["owner_id"] == 1 for item in reply.json()["items"])


def test_traversal_is_blocked(client, tmp_path):
    (tmp_path / "canary.txt").write_text("outside")
    reply = client.get("/files/..%2fcanary.txt")
    assert reply.status_code in (400, 404)
    assert "outside" not in reply.text
