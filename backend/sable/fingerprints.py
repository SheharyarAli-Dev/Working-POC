"""Stable fingerprints for named Terraform file bundles."""
from __future__ import annotations

import hashlib
import json


def bundle_sha256(files: dict[str, str]) -> str:
    """Hash both relative file names and contents in a stable order."""
    canonical = json.dumps(
        [[path, files[path]] for path in sorted(files)],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
