import json
import os
import subprocess
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_TOP = Path(__file__).resolve().parents[2]
DEFAULT_TARGET_URL = "https://github.com/SheharyarAli-Dev/Threat-Repository"
DEFAULT_ALLOWLIST = "SheharyarAli-Dev/Threat-Repository"
DEFAULT_MODEL = "qwen2.5-coder:1.5b"
DEFAULT_IMAGE = "asent-sandbox-app"
LOCAL_OLLAMA = "http://127.0.0.1:11434"


def gateway_address():
    try:
        listing = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for entry in listing.splitlines():
        pieces = entry.split()
        if pieces[:1] == ["default"] and "via" in pieces:
            return pieces[pieces.index("via") + 1]
    return None


def responds(endpoint, wait=1.5):
    try:
        with urllib.request.urlopen(endpoint.rstrip("/") + "/api/tags", timeout=wait) as handle:
            json.loads(handle.read().decode("utf-8"))
        return True
    except (OSError, ValueError):
        return False


def pick_ollama_endpoint():
    configured = os.environ.get("OLLAMA_HOST")
    if configured:
        return configured if "://" in configured else "http://" + configured
    if responds(LOCAL_OLLAMA):
        return LOCAL_OLLAMA
    hop = gateway_address()
    if hop and responds("http://%s:11434" % hop):
        return "http://%s:11434" % hop
    return LOCAL_OLLAMA


@dataclass(frozen=True)
class SatraSettings:
    target_url: str
    target_source: str
    allowlist: tuple
    workspace: Path
    ollama_endpoint: str
    model_name: str
    sandbox_image: str
    repair_budget: int
    push_enabled: bool
    forge_token: str = field(default="", repr=False)


def load_settings():
    workspace = Path(os.environ.get("SATRA_WORKSPACE") or (PROJECT_TOP / ".satra_workspace")).resolve()
    allow = os.environ.get("SATRA_TARGET_ALLOWLIST") or DEFAULT_ALLOWLIST
    target = os.environ.get("SATRA_TARGET_REPO_URL") or DEFAULT_TARGET_URL
    return SatraSettings(
        target_url=target,
        target_source=os.environ.get("SATRA_TARGET_SOURCE") or target,
        allowlist=tuple(item.strip() for item in allow.split(",") if item.strip()),
        workspace=workspace,
        ollama_endpoint=pick_ollama_endpoint(),
        model_name=os.environ.get("SATRA_MODEL") or DEFAULT_MODEL,
        sandbox_image=os.environ.get("SATRA_SANDBOX_IMAGE") or DEFAULT_IMAGE,
        repair_budget=int(os.environ.get("SATRA_MAX_REPAIR_ATTEMPTS") or "3"),
        push_enabled=os.environ.get("SATRA_ALLOW_PUSH", "1") == "1",
        forge_token=os.environ.get("GITHUB_TOKEN", ""),
    )
