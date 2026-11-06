"""
SABLE SQLite Storage — obligations, runs, audit_log.
Schema mirrors the CAVR storage pattern for consistency.
"""
from __future__ import annotations
import datetime
import json
import sqlite3
from pathlib import Path
from backend.config import DATA


class SableStorage:
    def __init__(self):
        db_dir = Path(DATA) / "sable"
        db_dir.mkdir(parents=True, exist_ok=True)
        self.path = db_dir / "sable.db"
        self._init_db()

    def _conn(self):
        return sqlite3.connect(self.path, check_same_thread=False)

    def _init_db(self):
        with self._conn() as c:
            c.executescript("""
CREATE TABLE IF NOT EXISTS obligations (
    obligation_id   TEXT PRIMARY KEY,
    principal       TEXT NOT NULL,
    actions         TEXT NOT NULL,
    protected_asset TEXT NOT NULL,
    resource_scope  TEXT NOT NULL,
    authority_source TEXT NOT NULL,
    baseline_evidence TEXT NOT NULL,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    run_id          TEXT PRIMARY KEY,
    scenario_id     TEXT,
    obligation_id   TEXT,
    verdict         TEXT,
    decision_hash   TEXT,
    created_at      TEXT NOT NULL,
    completed_at    TEXT,
    evidence_json   TEXT,
    proof_json      TEXT,
    evidence_chain_json TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL,
    action          TEXT NOT NULL,
    user            TEXT NOT NULL,
    reason          TEXT,
    created_at      TEXT NOT NULL
);
""")
            run_columns = {row[1] for row in c.execute("PRAGMA table_info(runs)")}
            if "evidence_chain_json" not in run_columns:
                c.execute("ALTER TABLE runs ADD COLUMN evidence_chain_json TEXT")
        # Seed the default obligation
        self._seed_obligation()

    def _seed_obligation(self):
        with self._conn() as c:
            existing = c.execute(
                "SELECT 1 FROM obligations WHERE obligation_id=?",
                ("S3-APPROLE-CUSTOMERDATA",)
            ).fetchone()
            if not existing:
                c.execute("""
INSERT INTO obligations (obligation_id, principal, actions, protected_asset, resource_scope,
                         authority_source, baseline_evidence, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
""", (
                    "S3-APPROLE-CUSTOMERDATA",
                    "aws_iam_role.app",
                    json.dumps(["s3:GetObject", "s3:PutObject"]),
                    "aws_s3_bucket.customer_data",
                    "arn:aws:s3:::customer-data/*",
                    "explicit benchmark policy + Terraform IAM policy document",
                    "baseline passes independent predicate",
                    datetime.datetime.utcnow().isoformat()
                ))

    # ---------- Obligations ----------
    def get_obligations(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM obligations").fetchall()
        cols = ["obligation_id", "principal", "actions", "protected_asset",
                "resource_scope", "authority_source", "baseline_evidence", "created_at"]
        result = []
        for row in rows:
            d = dict(zip(cols, row))
            d["actions"] = json.loads(d["actions"])
            result.append(d)
        return result

    def get_obligation(self, obligation_id: str) -> dict | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM obligations WHERE obligation_id=?", (obligation_id,)
            ).fetchone()
        if not row:
            return None
        cols = ["obligation_id", "principal", "actions", "protected_asset",
                "resource_scope", "authority_source", "baseline_evidence", "created_at"]
        d = dict(zip(cols, row))
        d["actions"] = json.loads(d["actions"])
        return d

    # ---------- Runs ----------
    def record_run(self, run_id: str, scenario_id: str, obligation_id: str):
        with self._conn() as c:
            c.execute("""
INSERT OR IGNORE INTO runs (run_id, scenario_id, obligation_id, created_at)
VALUES (?, ?, ?, ?)
""", (run_id, scenario_id, obligation_id, datetime.datetime.utcnow().isoformat()))

    def complete_run(self, run_id: str, verdict: str, decision_hash: str,
                     evidence: dict, proof: dict, evidence_chain: list[dict] | None = None):
        with self._conn() as c:
            c.execute("""
UPDATE runs SET verdict=?, decision_hash=?, completed_at=?, evidence_json=?, proof_json=?, evidence_chain_json=?
WHERE run_id=?
""", (verdict, decision_hash, datetime.datetime.utcnow().isoformat(),
      json.dumps(evidence), json.dumps(proof), json.dumps(evidence_chain or []), run_id))

    def get_run(self, run_id: str) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if not row:
            return None
        cols = ["run_id", "scenario_id", "obligation_id", "verdict", "decision_hash",
                "created_at", "completed_at", "evidence_json", "proof_json", "evidence_chain_json"]
        d = dict(zip(cols, row))
        if d["evidence_json"]:
            d["evidence"] = json.loads(d["evidence_json"])
        if d["proof_json"]:
            d["proof"] = json.loads(d["proof_json"])
        if d["evidence_chain_json"]:
            d["evidence_chain"] = json.loads(d["evidence_chain_json"])
        return d

    def get_runs(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT run_id, scenario_id, verdict, created_at, completed_at FROM runs ORDER BY created_at DESC LIMIT 50"
            ).fetchall()
        cols = ["run_id", "scenario_id", "verdict", "created_at", "completed_at"]
        return [dict(zip(cols, r)) for r in rows]

    # ---------- Audit log ----------
    def record_audit(self, run_id: str, action: str, user: str, reason: str = ""):
        with self._conn() as c:
            c.execute("""
INSERT INTO audit_log (run_id, action, user, reason, created_at)
VALUES (?, ?, ?, ?, ?)
""", (run_id, action, user, reason, datetime.datetime.utcnow().isoformat()))

    def get_audit_log(self, run_id: str | None = None) -> list[dict]:
        with self._conn() as c:
            if run_id:
                rows = c.execute(
                    "SELECT * FROM audit_log WHERE run_id=? ORDER BY id DESC",
                    (run_id,)
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT * FROM audit_log ORDER BY id DESC LIMIT 100"
                ).fetchall()
        cols = ["id", "run_id", "action", "user", "reason", "created_at"]
        return [dict(zip(cols, r)) for r in rows]
