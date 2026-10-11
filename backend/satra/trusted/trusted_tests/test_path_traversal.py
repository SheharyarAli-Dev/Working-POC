from urllib.parse import quote

import pytest

FAMILY = "PATH.TRAV.001"
CANARY_TEXT = "SATRA-CANARY-7f3a91c2"


@pytest.fixture
def planted(world):
    outside = world.data_dir / "canary.txt"
    outside.write_text(CANARY_TEXT)
    uploads = world.data_dir / "uploads"
    uploads.mkdir(exist_ok=True)
    (uploads / "hello.txt").write_text("hello upload")
    return outside


def test_sanity_regular_upload_is_served(world, planted):
    reply = world.client.get("/files/hello.txt")
    assert reply.status_code == 200
    assert reply.text == "hello upload"


def test_sanity_canary_exists_outside_uploads(world, planted):
    assert planted.read_text() == CANARY_TEXT
    assert planted.parent != world.data_dir / "uploads"


@pytest.mark.parametrize("payload", ["..%2fcanary.txt", "%2e%2e%2fcanary.txt", "..%2f..%2fcanary.txt", "....%2f%2fcanary.txt", "%2e%2e%5ccanary.txt"])
def test_dot_dot_payloads_do_not_leak_canary(world, planted, payload):
    reply = world.client.get("/files/" + payload)
    assert CANARY_TEXT not in reply.text
    assert reply.status_code in (400, 403, 404)


def test_absolute_payload_does_not_leak_canary(world, planted):
    reply = world.client.get("/files/" + quote(str(planted), safe=""))
    assert CANARY_TEXT not in reply.text
    assert reply.status_code in (400, 403, 404)
