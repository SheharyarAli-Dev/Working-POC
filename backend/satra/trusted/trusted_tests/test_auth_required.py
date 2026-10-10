from conftest import rule_of

FAMILY = "AUTH.REQ.001"


def count_for_alice(world):
    return len(world.client.get("/invoices", headers=world.headers["alice"]).json()["items"])


def test_sanity_authenticated_create_succeeds(world):
    before = count_for_alice(world)
    reply = world.client.post("/invoices", json={"description": "probe", "amount": 5}, headers=world.headers["alice"])
    assert reply.status_code == 201
    assert count_for_alice(world) == before + 1


def test_anonymous_create_is_rejected(world, policy):
    rule = rule_of(policy, FAMILY)
    before = count_for_alice(world)
    reply = world.client.post("/invoices", json={"description": "probe", "amount": 5})
    assert reply.status_code == rule["unauthenticated_status"]
    assert count_for_alice(world) == before


def test_garbage_token_create_is_rejected(world, policy):
    rule = rule_of(policy, FAMILY)
    reply = world.client.post("/invoices", json={"description": "probe", "amount": 5}, headers={"Authorization": "Bearer nonsense"})
    assert reply.status_code == rule["unauthenticated_status"]
