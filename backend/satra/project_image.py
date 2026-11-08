"""Per-project SATRA sandbox images for gate runs.

A gate run executes the project's trusted tests inside an image that holds the SATRA runner base
(docker/satra-runner.Dockerfile: CPython 3.12 + pytest) plus exactly the CAVR-approved wheels of
the BASE commit's dependencies.lock.json. The image is built with network access; the tests then
run in it with --network none, exactly like every other SATRA pytest run.
"""
from __future__ import annotations

import re
from pathlib import Path

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from backend.config import ROOT

RUNNER_IMAGE = "asent-satra-runner:local"
RUNNER_REQUIREMENTS = ROOT / "docker/satra-runner.requirements.txt"

NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RUNNER_LINE = re.compile(r"^(?P<name>\S+)==(?P<version>\S+) --hash=sha256:(?P<sha>[0-9a-f]{64})$")


def runner_pins(path=RUNNER_REQUIREMENTS) -> dict:
    """{canonical name: {"name", "version", "hashes"}} of the runner base, read from its requirements file.

    Every non-comment line must be `name==version --hash=sha256:<64 hex>`; anything else raises
    ValueError, so a runner that is not fully hash-pinned can never be used.
    """
    pins = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        match = _RUNNER_LINE.match(line.strip())
        if not match or not NAME.match(match["name"]):
            raise ValueError(f"runner requirement is not one exact, hash-pinned wheel: {line!r}")
        try:
            version = str(Version(match["version"]))
        except InvalidVersion:
            raise ValueError(f"runner requirement has an invalid version: {line!r}") from None
        entry = pins.setdefault(canonicalize_name(match["name"]), {"name": match["name"], "version": version, "hashes": []})
        if entry["version"] != version:
            raise ValueError(f"runner pins {match['name']} twice at different versions")
        entry["hashes"].append(match["sha"])
    return pins
