from conftest import auth


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_owner_reads_own_invoice(client):
    reply = client.get("/invoices/1", headers=auth("tok-alice"))
    assert reply.status_code == 200
    assert reply.json()["description"] == "alice consulting retainer"


def test_missing_invoice_is_not_found(client):
    assert client.get("/invoices/999", headers=auth("tok-alice")).status_code == 404


def test_search_finds_own_invoice(client):
    reply = client.get("/invoices", params={"search": "retainer"}, headers=auth("tok-alice"))
    assert [item["id"] for item in reply.json()["items"]] == [1]


def test_create_invoice_for_caller(client):
    reply = client.post("/invoices", json={"description": "new work", "amount": 10}, headers=auth("tok-bob"))
    assert reply.status_code == 201
    assert reply.json()["owner_id"] == 2


def test_upload_is_served(client, tmp_path):
    (tmp_path / "uploads" / "note.txt").write_text("note body")
    assert client.get("/files/note.txt").text == "note body"
