from conftest import rule_of

FAMILY = "AUTHZ.IDOR.001"


def read_invoice(world, number, who=None):
    headers = world.headers[who] if who else {}
    return world.client.get("/invoices/%d" % number, headers=headers)


def test_sanity_owner_reads_own_invoice(world):
    reply = read_invoice(world, 1, "alice")
    assert reply.status_code == 200
    assert reply.json()["id"] == 1


def test_sanity_second_owner_reads_own_invoice(world):
    reply = read_invoice(world, 2, "bob")
    assert reply.status_code == 200


def test_other_user_is_denied(world, policy):
    rule = rule_of(policy, FAMILY)
    reply = read_invoice(world, 1, "bob")
    assert reply.status_code == rule["denied_status"]
    assert world.seeds[0]["marker"] not in reply.text


def test_other_user_is_denied_in_reverse(world, policy):
    rule = rule_of(policy, FAMILY)
    reply = read_invoice(world, 2, "alice")
    assert reply.status_code == rule["denied_status"]
    assert world.seeds[1]["marker"] not in reply.text


def test_admin_allowed_per_policy(world, policy):
    rule = rule_of(policy, FAMILY)
    expected = 200 if "admin" in rule["roles_allowed_any_object"] else rule["denied_status"]
    assert read_invoice(world, 1, "admin").status_code == expected
    assert read_invoice(world, 2, "admin").status_code == expected


def test_anonymous_is_unauthenticated(world, policy):
    rule = rule_of(policy, FAMILY)
    assert read_invoice(world, 1).status_code == rule["unauthenticated_status"]


def test_denied_read_has_no_state_effect(world):
    before = world.client.get("/invoices", headers=world.headers["alice"]).json()
    read_invoice(world, 1, "bob")
    after = world.client.get("/invoices", headers=world.headers["alice"]).json()
    assert before == after
