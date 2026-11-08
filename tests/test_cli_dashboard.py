"""Packaging step 5: `asent dashboard` serves the existing dashboard on 127.0.0.1 only.

There is no --host option: the address is fixed in backend/commands/dashboard.py. One test starts the
real server in a subprocess and checks that it answers on 127.0.0.1 and refuses connections on this
machine's other address.
"""
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from backend import cli
from backend.commands import dashboard

REPO = Path(__file__).resolve().parents[1]


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def served(monkeypatch):
    calls = []
    monkeypatch.setattr(dashboard, "serve", lambda port: calls.append(port))
    return calls


def test_default_is_port_8000_on_loopback(served, capsys, monkeypatch):
    monkeypatch.setattr(dashboard, "port_free", lambda port: True)
    assert cli.main(["dashboard"]) == 0
    assert served == [8000] and dashboard.HOST == "127.0.0.1"
    assert "http://127.0.0.1:8000/" in capsys.readouterr().out


def test_serve_passes_the_fixed_host_to_uvicorn(monkeypatch):
    import uvicorn
    seen = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.update(app=app, **kw))
    dashboard.serve(8123)
    assert seen["app"] == "backend.main:app" and seen["host"] == "127.0.0.1" and seen["port"] == 8123


def test_there_is_no_host_option(served, capsys):
    with pytest.raises(SystemExit) as stop:
        cli.main(["dashboard", "--host", "0.0.0.0"])
    assert stop.value.code == 2 and served == []


@pytest.mark.parametrize("port", ["0", "65536", "-1", "http"])
def test_invalid_port_is_a_usage_error(served, capsys, port):
    with pytest.raises(SystemExit) as stop:
        cli.main(["dashboard", "--port", port])
    assert stop.value.code == 2 and served == []


def test_port_in_use_is_a_plain_error(served, capsys):
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        port = busy.getsockname()[1]
        assert cli.main(["dashboard", "--port", str(port)]) == 2
    assert served == []
    assert f"port {port} on 127.0.0.1 is already in use" in capsys.readouterr().err


def test_json_prints_one_line_before_serving(served, capsys, monkeypatch):
    monkeypatch.setattr(dashboard, "port_free", lambda port: True)
    monkeypatch.setattr(dashboard, "ui_bundled", lambda: False)
    assert cli.main(["dashboard", "--port", "8765", "--json"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1
    info = json.loads(lines[0])
    assert info == {"url": "http://127.0.0.1:8765/", "api": "http://127.0.0.1:8765/api", "ui_bundled": False,
                    "data_dir": info["data_dir"]}


def test_without_ui_the_text_says_api_only(served, capsys, monkeypatch):
    monkeypatch.setattr(dashboard, "port_free", lambda port: True)
    monkeypatch.setattr(dashboard, "ui_bundled", lambda: False)
    cli.main(["dashboard"])
    out = capsys.readouterr().out
    assert "no dashboard UI" in out and "API only" in out and "http://127.0.0.1:8000/api" in out


def other_address():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))  # TEST-NET-1: no packet is sent for a UDP connect
            address = s.getsockname()[0]
    except OSError:
        return None
    return None if address.startswith("127.") else address


def test_the_real_server_answers_on_loopback_only(tmp_path):
    port = free_port()
    env = {**os.environ, "ASENT_DATA": str(tmp_path / "data"), "PYTHONPATH": str(REPO)}
    proc = subprocess.Popen([sys.executable, "-m", "backend.cli", "dashboard", "--port", str(port), "--json"], cwd=tmp_path,
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        info = json.loads(proc.stdout.readline())
        assert info["url"] == f"http://127.0.0.1:{port}/"
        deadline, answer = time.monotonic() + 60, None
        while time.monotonic() < deadline and proc.poll() is None:
            try:
                answer = httpx.get(info["api"] + "/capabilities", timeout=2, trust_env=False)
                break
            except httpx.TransportError:
                time.sleep(0.3)
        assert answer is not None and answer.status_code == 200, proc.stderr.read() if proc.poll() is not None else "no answer"
        address = other_address()
        if address:
            with socket.socket() as probe:
                probe.settimeout(2)
                assert probe.connect_ex((address, port)) != 0, f"dashboard reachable on {address}"
    finally:
        proc.terminate()
        proc.wait(timeout=20)
