"""Host-header check on the local dashboard server (DNS-rebinding defence).

A page on evil.example can re-point its own DNS name at 127.0.0.1 and then talk to the dashboard as a
"same-origin" site. The browser still sends `Host: evil.example`, so the server refuses every Host that
is not loopback (or explicitly listed in ASENT_ALLOWED_HOSTS) with 400, before any route runs.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI, WebSocket
from fastapi.testclient import TestClient
from starlette.testclient import WebSocketDenialResponse

from backend.host_check import DEFAULT_HOSTS, allowed_hosts, protect

ROOT = Path(__file__).resolve().parents[1]

# Runs in a subprocess so that importing backend.main (which creates its Service and the InvoiceHub demo
# data) writes only into ASENT_DATA=tmp, never into the checkout. A host of None sends no Host header at
# all, which httpx cannot do, so that case drives the ASGI app directly.
PROBE = r"""
import asyncio, json, sys
from fastapi.testclient import TestClient
import backend.main as m

async def no_host(method, path):
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method,
             "scheme": "http", "path": path, "raw_path": path.encode(), "root_path": "", "query_string": b"",
             "headers": [], "server": ("127.0.0.1", 8000), "client": ("127.0.0.1", 50000)}
    status = []
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}
    async def send(message):
        if message["type"] == "http.response.start":
            status.append(message["status"])
    await m.app(scope, receive, send)
    return status[0]

client = TestClient(m.app, base_url="http://127.0.0.1:8000")
out = []
for method, path, host in json.loads(sys.argv[1]):
    if host is None:
        out.append(asyncio.run(no_host(method, path)))
    else:
        out.append(client.request(method, path, headers={"host": host}).status_code)
print(json.dumps(out))
"""


def probe_real_app(cases, data_dir, allowed=None):
    """Status code of each (method, path, host) request against the real backend.main:app."""
    env = {k: v for k, v in os.environ.items() if k != "ASENT_ALLOWED_HOSTS"}
    env["ASENT_DATA"] = str(data_dir)
    if allowed is not None:
        env["ASENT_ALLOWED_HOSTS"] = allowed
    done = subprocess.run([sys.executable, "-c", PROBE, json.dumps(cases)], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


ALLOWED = ["127.0.0.1", "127.0.0.1:8000", "localhost", "localhost:8000",
           "localhost:5173",   # what the Vite dev/preview proxy forwards (no changeOrigin)
           "127.0.0.1:5173", "[::1]", "[::1]:8000"]
REFUSED = ["evil.example", "evil.example:8000", "127.0.0.1.evil.example", "localhost.evil.example",
           "evil.localhost.example", "", "[::1", "127.0.0.1:abc", "::1", "127.0.0.2", "0.0.0.0", None]


@pytest.fixture(scope="module")
def default_results(tmp_path_factory):
    cases = [["GET", "/api/health", h] for h in ALLOWED + REFUSED]
    cases += [["GET", "/api/runs/no-such-run/stream", "127.0.0.1:8000"],   # SSE route reached -> 404
              ["GET", "/api/runs/no-such-run/stream", "evil.example"],
              ["GET", "/invoicehub/", "evil.example"],
              ["POST", "/api/runs", "evil.example"],
              ["GET", "/api/runs/x/report/download", "127.0.0.1.evil.example"],
              ["GET", "/api/health", "asent.internal"]]
    results = probe_real_app(cases, tmp_path_factory.mktemp("asent-data"))
    return {(method, path, host): status for (method, path, host), status in zip(cases, results)}


@pytest.mark.parametrize("host", ALLOWED)
def test_loopback_hosts_with_or_without_port_are_allowed(default_results, host):
    assert default_results[("GET", "/api/health", host)] == 200


@pytest.mark.parametrize("host", REFUSED)
def test_other_hosts_and_a_missing_host_are_refused_with_400(default_results, host):
    assert default_results[("GET", "/api/health", host)] == 400


def test_sse_stream_is_checked_before_routing(default_results):
    # Allowed Host reaches the route (unknown run -> 404); a rebinding Host never gets that far.
    assert default_results[("GET", "/api/runs/no-such-run/stream", "127.0.0.1:8000")] == 404
    assert default_results[("GET", "/api/runs/no-such-run/stream", "evil.example")] == 400


def test_mounted_apps_post_and_download_are_covered(default_results):
    assert default_results[("GET", "/invoicehub/", "evil.example")] == 400
    # 400, not the Origin check's 403: the Host check runs first, even with no Origin header at all.
    assert default_results[("POST", "/api/runs", "evil.example")] == 400
    assert default_results[("GET", "/api/runs/x/report/download", "127.0.0.1.evil.example")] == 400


def test_extra_host_is_refused_by_default(default_results):
    assert default_results[("GET", "/api/health", "asent.internal")] == 400


def test_setting_adds_a_host_on_the_real_app(tmp_path):
    cases = [["GET", "/api/health", h] for h in ("asent.internal", "asent.internal:8000", "127.0.0.1:8000",
                                                 "evil.example", "other.internal")]
    assert probe_real_app(cases, tmp_path, allowed="asent.internal") == [200, 200, 200, 400, 400]


# --- allowed_hosts(): parsing ASENT_ALLOWED_HOSTS ---------------------------------------------------------------------

def test_default_is_loopback_only():
    assert allowed_hosts({}) == ["127.0.0.1", "localhost", "[::1]"] == list(DEFAULT_HOSTS)
    assert allowed_hosts({"ASENT_ALLOWED_HOSTS": ""}) == list(DEFAULT_HOSTS)
    assert allowed_hosts({"ASENT_ALLOWED_HOSTS": " , ,"}) == list(DEFAULT_HOSTS)


def test_setting_appends_lowercased_deduplicated_hosts():
    env = {"ASENT_ALLOWED_HOSTS": " Asent.Internal , 10.0.0.5,,[FD00::1], localhost, asent.internal"}
    assert allowed_hosts(env) == [*DEFAULT_HOSTS, "asent.internal", "10.0.0.5", "[fd00::1]"]


@pytest.mark.parametrize("entry", ["*", "*.example", "evil.*", "http://asent.internal", "asent.internal:8000",
                                   "asent.internal/path", "::1", "fd00::1", "[::1]:8000", "asent..internal",
                                   "asent.internal.", "bad host", "[not-ipv6]"])
def test_invalid_setting_fails_at_startup(entry):
    with pytest.raises(ValueError, match="ASENT_ALLOWED_HOSTS"):
        allowed_hosts({"ASENT_ALLOWED_HOSTS": f"asent.internal,{entry}"})


# --- protect() on a small app: HTTP and WebSocket scopes ---------------------------------------------------------------

def small_app(environ):
    app = FastAPI()

    @app.get("/ping")
    def ping():
        return {"ok": True}

    @app.websocket("/ws")
    async def ws(socket: WebSocket):
        await socket.accept()
        await socket.send_text("hello")
        await socket.close()

    protect(app, environ)
    return app


def test_websocket_with_loopback_host_connects():
    # websocket_connect ignores base_url and always targets ws://testserver, so the Host is set explicitly.
    client = TestClient(small_app({}), base_url="http://127.0.0.1:8000")
    with client.websocket_connect("/ws", headers={"host": "127.0.0.1:8000"}) as socket:
        assert socket.receive_text() == "hello"


@pytest.mark.parametrize("host", ["evil.example", "127.0.0.1.evil.example"])
def test_websocket_with_rebinding_host_is_refused_with_400(host):
    client = TestClient(small_app({}), base_url="http://127.0.0.1:8000")
    with pytest.raises(WebSocketDenialResponse) as denied:
        with client.websocket_connect("/ws", headers={"host": host}):
            pass
    assert denied.value.status_code == 400


def test_setting_adds_a_host_for_websocket_and_http():
    client = TestClient(small_app({"ASENT_ALLOWED_HOSTS": "asent.internal"}), base_url="http://asent.internal")
    assert client.get("/ping").status_code == 200
    with client.websocket_connect("/ws", headers={"host": "asent.internal"}) as socket:
        assert socket.receive_text() == "hello"
    assert client.get("/ping", headers={"host": "evil.example"}).status_code == 400


def test_test_client_default_host_is_not_allowed():
    # Starlette's TestClient sends Host "testserver"; the rule is not widened for it.
    assert TestClient(small_app({})).get("/ping").status_code == 400
