"""`asent dashboard`: run the existing dashboard (backend.main:app) on this machine only.

The address is fixed to 127.0.0.1 and there is deliberately no --host option: the dashboard has no
authentication, so it must not be reachable from other machines. Only the port can be chosen. With
--json one line {"url", "api", "ui_bundled", "data_dir"} is printed before serving, for editors.
"""
from __future__ import annotations

import argparse
import socket

from backend.config import ASSETS, DATA

HOST = "127.0.0.1"
DEFAULT_PORT = 8000


def port_type(text):
    try:
        port = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a port number: {text!r}") from None
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"port must be 1-65535, not {port}")
    return port


def port_free(port) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((HOST, port))
        except OSError:
            return False
    return True


def ui_bundled() -> bool:
    return (ASSETS / "frontend" / "dist" / "index.html").is_file()


def info(port) -> dict:
    return {"url": f"http://{HOST}:{port}/", "api": f"http://{HOST}:{port}/api", "ui_bundled": ui_bundled(), "data_dir": str(DATA)}


def serve(port):
    import uvicorn
    uvicorn.run("backend.main:app", host=HOST, port=port, log_level="info")
