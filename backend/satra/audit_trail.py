import hashlib
import json
import os
import time
from pathlib import Path


class AuditTamperError(Exception):
    pass


def canonical_digest(entry_dict: dict) -> str:
    """Computes SHA-256 over canonical, sorted-key JSON string excluding entry_hash itself."""
    payload = {k: v for k, v in entry_dict.items() if k != "entry_hash"}
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class AuditTrail:
    """
    Append-only, cryptographic hash-chained audit trail for SATRA gate decisions and recommits.
    Every entry includes:
    - entry_id (monotonically increasing)
    - timestamp (ISO-8601 UTC)
    - run_id (real run ID)
    - operator (human or gate identity)
    - action (e.g. APPROVE_AND_PUSH, LOCAL_BRANCH_CREATED, REJECT)
    - branch
    - commit_sha
    - details (evidence summaries, gate verdicts)
    - prev_hash (hash of prior entry, or '0'*64 for genesis)
    - entry_hash (SHA-256 of this entry's canonical content)
    """

    def __init__(self, log_path: Path):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def get_last_hash(self) -> str:
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return "0" * 64
        last_line = ""
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    last_line = stripped
        if not last_line:
            return "0" * 64
        entry = json.loads(last_line)
        return entry.get("entry_hash", "0" * 64)

    def get_count(self) -> int:
        if not self.log_path.exists():
            return 0
        count = 0
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    count += 1
        return count

    def append(self, run_id: str, operator: str, action: str, branch: str, commit_sha: str, details: dict = None) -> dict:
        entry_id = self.get_count()
        prev_hash = self.get_last_hash()
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        entry = {
            "entry_id": entry_id,
            "timestamp": timestamp,
            "run_id": run_id,
            "operator": operator,
            "action": action,
            "branch": branch,
            "commit_sha": commit_sha,
            "details": details or {},
            "prev_hash": prev_hash,
        }
        entry["entry_hash"] = canonical_digest(entry)

        # Open strictly in append mode ('a') with immediate flush and sync to disk
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())

        return entry

    def read_all(self) -> list:
        if not self.log_path.exists():
            return []
        entries = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    entries.append(json.loads(stripped))
        return entries

    def verify_chain(self) -> dict:
        """
        Verifies the cryptographic integrity of the entire audit chain.
        Returns {'valid': True, 'count': N} or {'valid': False, 'tampered_index': i, 'reason': msg}.
        """
        entries = self.read_all()
        if not entries:
            return {"valid": True, "count": 0, "reason": "Empty log"}

        expected_prev = "0" * 64
        for idx, entry in enumerate(entries):
            if entry.get("entry_id") != idx:
                return {
                    "valid": False,
                    "tampered_index": idx,
                    "reason": f"Entry ID discontinuity at index {idx}: expected {idx}, got {entry.get('entry_id')}"
                }
            if entry.get("prev_hash") != expected_prev:
                return {
                    "valid": False,
                    "tampered_index": idx,
                    "reason": f"Hash chain broken at index {idx}: expected prev_hash {expected_prev}, got {entry.get('prev_hash')}"
                }
            computed_hash = canonical_digest(entry)
            if entry.get("entry_hash") != computed_hash:
                return {
                    "valid": False,
                    "tampered_index": idx,
                    "reason": f"Content tampering detected at index {idx}: expected entry_hash {computed_hash}, got {entry.get('entry_hash')}"
                }
            expected_prev = entry.get("entry_hash")

        return {"valid": True, "count": len(entries), "last_hash": expected_prev}
