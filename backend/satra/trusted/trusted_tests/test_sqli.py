import pytest

FAMILY = "INJ.SQL.001"
ATTACK_TEXTS = ["' OR 1=1 --", "%' OR '1'='1", "x' UNION SELECT 1,2,3,4 --", "'", "\"; DROP TABLE invoices; --"]
ERROR_MARKERS = ("sqlite", "syntax", "operationalerror", "unrecognized token", "near ")


def run_search(world, text):
    return world.client.get("/invoices", params={"search": text}, headers=world.headers["alice"])


def test_sanity_benign_search_finds_own_invoice(world):
    reply = run_search(world, "retainer")
    assert reply.status_code == 200
    assert [item["id"] for item in reply.json()["items"]] == [1]


def test_sanity_benign_search_without_match_is_empty(world):
    reply = run_search(world, "zzzz-no-match")
    assert reply.status_code == 200
    assert reply.json()["items"] == []


@pytest.mark.parametrize("attack", ATTACK_TEXTS)
def test_attack_text_is_treated_as_data(world, attack):
    benign = run_search(world, "retainer")
    reply = run_search(world, attack)
    assert reply.status_code == benign.status_code
    lowered = reply.text.lower()
    assert not any(marker in lowered for marker in ERROR_MARKERS)
    assert {item["owner_id"] for item in reply.json()["items"]} <= {world.subjects["alice"]["id"]}
    assert len(reply.content) <= len(benign.content)
