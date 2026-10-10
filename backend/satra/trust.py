import hashlib
import json
from pathlib import Path

TRUST_DIR = Path(__file__).resolve().parent / "trusted"
MANIFEST_NAME = "trusted.manifest.json"
SKIPPED_PARTS = {"__pycache__", ".pytest_cache"}


def fingerprint_bytes(raw):
    return hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest()


def tracked_files(directory=TRUST_DIR):
    found = []
    for item in sorted(Path(directory).rglob("*")):
        if not item.is_file() or item.name == MANIFEST_NAME or item.suffix == ".pyc":
            continue
        if SKIPPED_PARTS & set(item.relative_to(directory).parts):
            continue
        found.append(item)
    return found


def compute_table(directory=TRUST_DIR):
    return {item.relative_to(directory).as_posix(): fingerprint_bytes(item.read_bytes()) for item in tracked_files(directory)}


def write_manifest(directory=TRUST_DIR):
    table = compute_table(directory)
    body = {"algorithm": "sha256-lf-normalized", "files": table}
    (Path(directory) / MANIFEST_NAME).write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
    return table


def verify_manifest(directory=TRUST_DIR):
    manifest_path = Path(directory) / MANIFEST_NAME
    if not manifest_path.is_file():
        return {"valid": False, "reason": "manifest missing", "mismatched": [], "missing": [], "unlisted": [], "files": {}}
    try:
        expected = json.loads(manifest_path.read_text())["files"]
    except (ValueError, KeyError):
        return {"valid": False, "reason": "manifest unreadable", "mismatched": [], "missing": [], "unlisted": [], "files": {}}
    actual = compute_table(directory)
    mismatched = sorted(name for name in expected if name in actual and actual[name] != expected[name])
    missing = sorted(name for name in expected if name not in actual)
    unlisted = sorted(name for name in actual if name not in expected)
    valid = not (mismatched or missing or unlisted)
    return {"valid": valid, "reason": "ok" if valid else "trusted assets differ from manifest", "mismatched": mismatched, "missing": missing, "unlisted": unlisted, "files": actual}


def read_policy(directory=TRUST_DIR):
    return json.loads((Path(directory) / "policy.json").read_text())


def read_requirements(directory=TRUST_DIR):
    return (Path(directory) / "SRS.md").read_text()
