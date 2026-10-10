from __future__ import annotations
import datetime
import json
import sqlite3
from pathlib import Path
from backend.config import DATA

SEED_PACKAGES = [
    {
        "name": "requests",
        "version": "2.31.0",
        "sha256": "942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1",
        "source": "PyPI Verified",
        "status": "TRUSTED",
        "capabilities": "HTTP client, connection pooling, SSL verification",
        "added_at": "2026-01-15T10:00:00Z"
    },
    {
        "name": "urllib3",
        "version": "2.2.1",
        "sha256": "450b20ec29ceb9b12d18227b686d63428203d154407ef2d1ea21b2554e21a28a",
        "source": "PyPI Verified",
        "status": "TRUSTED",
        "capabilities": "HTTP connection pool, thread-safe request dispatch",
        "added_at": "2026-01-15T10:00:00Z"
    },
    {
        "name": "pydantic",
        "version": "2.7.1",
        "sha256": "71f46dc3cb71c4c1533c3a9f02a4bb49d01d14e0491823eb9cb94d7647ea37cb",
        "source": "PyPI Verified",
        "status": "TRUSTED",
        "capabilities": "Schema validation, runtime type enforcement",
        "added_at": "2026-01-20T14:22:00Z"
    },
    {
        "name": "fastapi",
        "version": "0.111.0",
        "sha256": "34b7f8c119e07897d21b7ce38290f62283cb7d2194cf21d9cf1e27a965743bdf",
        "source": "PyPI Verified",
        "status": "TRUSTED",
        "capabilities": "High-performance web API framework, OpenAPI generation",
        "added_at": "2026-02-01T09:15:00Z"
    },
    {
        "name": "pypdf",
        "version": "4.2.0",
        "sha256": "d8291a13fcba897b6a12b2389d36e2f182e0719e7a2b910ca31bdf74288b8941",
        "source": "PyPI Verified",
        "status": "TRUSTED",
        "capabilities": "PDF document extraction, text parsing, split & merge",
        "added_at": "2026-02-10T11:45:00Z"
    },
    {
        "name": "pytest",
        "version": "8.2.0",
        "sha256": "8e036df86a7d9b734641d4c97ea07c125df890b29ce4599a18d26458390bca2d",
        "source": "PyPI Verified",
        "status": "TRUSTED",
        "capabilities": "Test runner, contract assertion, fixture evaluation",
        "added_at": "2026-02-12T16:00:00Z"
    },
    {
        "name": "httpx",
        "version": "0.27.0",
        "sha256": "2f0a1c1d81b2e6587c5fb04b901a8848a60965c490897bcf94a8647e30d47d48",
        "source": "PyPI Verified",
        "status": "TRUSTED",
        "capabilities": "Async & sync HTTP transport, HTTP/2 support",
        "added_at": "2026-02-15T08:30:00Z"
    },
    {
        "name": "cryptography",
        "version": "42.0.7",
        "sha256": "b51296c7ea8211b6d2e8b0934cf15ab5a5e3bc821cf02a39c6396f8c7e42d765",
        "source": "PyPI Verified",
        "status": "TRUSTED",
        "capabilities": "Cryptographic recipes, HMAC, AES-GCM, certificates",
        "added_at": "2026-02-20T12:00:00Z"
    },
    {
        "name": "pyyaml",
        "version": "6.0.1",
        "sha256": "bf4f1b991480f4bfb0e87a894178965a46652a91f2f543697e7a4f90df24a912",
        "source": "PyPI Verified",
        "status": "TRUSTED",
        "capabilities": "Safe YAML parsing (SafeLoader), spec configuration",
        "added_at": "2026-02-22T15:10:00Z"
    },
    {
        "name": "colorama",
        "version": "0.4.6",
        "sha256": "086e58cf5e3c12660a9d01d618e47095d3069d5ff79471f0a929b04054791038",
        "source": "PyPI Verified",
        "status": "TRUSTED",
        "capabilities": "ANSI terminal escape sequence rendering",
        "added_at": "2026-03-01T10:05:00Z"
    },
    {
        "name": "rich",
        "version": "13.7.1",
        "sha256": "9c223c72b83c5e88691f165a3d7e5d8bf24c9657c9f8092a084ef7a36cb7d519",
        "source": "PyPI Verified",
        "status": "TRUSTED",
        "capabilities": "Terminal formatting, syntax highlighting, progress bars",
        "added_at": "2026-03-05T13:40:00Z"
    },
    {
        "name": "jinja2",
        "version": "3.1.4",
        "sha256": "4a3aee7ac9f61f3ea5e1f378267680374720d47972160250710d2449452bc73e",
        "source": "PyPI Verified",
        "status": "TRUSTED",
        "capabilities": "Fast, safe templating engine with sandboxed execution",
        "added_at": "2026-03-10T09:20:00Z"
    },
    {
        "name": "numpy",
        "version": "1.26.4",
        "sha256": "2d257a627a44f51e36780c117b447817eb48fb07d1746f3938abf0d0c3eb14ff",
        "source": "PyPI Verified",
        "status": "TRUSTED",
        "capabilities": "Multidimensional array computation and linear algebra",
        "added_at": "2026-03-12T11:00:00Z"
    }
]

class CavrStorage:
    def __init__(self, db_path: Path | str | None = None):
        if db_path is None:
            self.db_path = Path(DATA) / "asent.sqlite3"
        else:
            self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self.connect() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS trusted_packages(
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                source TEXT DEFAULT 'PyPI Verified',
                status TEXT DEFAULT 'TRUSTED',
                capabilities TEXT DEFAULT '',
                added_at TEXT,
                PRIMARY KEY(name, version)
            );

            CREATE TABLE IF NOT EXISTS quarantine_records(
                run_id TEXT PRIMARY KEY,
                package TEXT NOT NULL,
                version TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                quarantined_at TEXT NOT NULL,
                file_path TEXT,
                decision TEXT DEFAULT 'PENDING'
            );

            CREATE TABLE IF NOT EXISTS audit_log(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                package TEXT NOT NULL,
                action TEXT NOT NULL,
                user TEXT NOT NULL,
                reason TEXT,
                timestamp TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS verdict_cache(
                cache_key TEXT PRIMARY KEY,
                ecosystem TEXT NOT NULL,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                artifact_sha256 TEXT NOT NULL,
                subtree_digest TEXT NOT NULL,
                contract_digest TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                analyzer_version TEXT NOT NULL,
                status TEXT NOT NULL,
                verdict_json TEXT NOT NULL,
                stored_at TEXT NOT NULL,
                integrity TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS verdict_log(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recorded_at TEXT NOT NULL,
                source TEXT,
                requested TEXT,
                status TEXT NOT NULL,
                stage TEXT,
                rule TEXT,
                fast_gate_ms REAL NOT NULL,
                cache_hit INTEGER NOT NULL,
                escalated INTEGER NOT NULL,
                cache_lookup TEXT
            );
            """)

            # A database made before the cache lookup was logged gets the column; its old rows keep NULL.
            if "cache_lookup" not in {column[1] for column in conn.execute("PRAGMA table_info(verdict_log)")}:
                conn.execute("ALTER TABLE verdict_log ADD COLUMN cache_lookup TEXT")

            # Seed if table is empty
            count = conn.execute("SELECT COUNT(*) FROM trusted_packages").fetchone()[0]
            if count == 0:
                for pkg in SEED_PACKAGES:
                    conn.execute("""
                    INSERT OR IGNORE INTO trusted_packages(name, version, sha256, source, status, capabilities, added_at)
                    VALUES(?, ?, ?, ?, ?, ?, ?)
                    """, (
                        pkg["name"],
                        pkg["version"],
                        pkg["sha256"],
                        pkg["source"],
                        pkg["status"],
                        pkg["capabilities"],
                        pkg["added_at"]
                    ))
                conn.commit()

    def get_trusted_packages(self) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM trusted_packages ORDER BY name ASC").fetchall()
            return [dict(r) for r in rows]

    def get_trusted_package(self, name: str, version: str | None = None) -> dict | None:
        with self.connect() as conn:
            if version:
                row = conn.execute("SELECT * FROM trusted_packages WHERE LOWER(name)=LOWER(?) AND version=?", (name, version)).fetchone()
            else:
                row = conn.execute("SELECT * FROM trusted_packages WHERE LOWER(name)=LOWER(?) ORDER BY rowid DESC LIMIT 1", (name,)).fetchone()
            return dict(row) if row else None

    def add_trusted_package(self, name: str, version: str, sha256: str, source: str = "PyPI Verified", capabilities: str = "") -> dict:
        added_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute("""
            INSERT OR REPLACE INTO trusted_packages(name, version, sha256, source, status, capabilities, added_at)
            VALUES(?, ?, ?, ?, 'TRUSTED', ?, ?)
            """, (name, version, sha256, source, capabilities, added_at))
            conn.commit()
        return {"name": name, "version": version, "sha256": sha256, "source": source, "status": "TRUSTED", "added_at": added_at}

    def record_quarantine(self, run_id: str, package: str, version: str, sha256: str, file_path: str, status: str = "QUARANTINED") -> dict:
        quarantined_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute("""
            INSERT OR REPLACE INTO quarantine_records(run_id, package, version, sha256, status, quarantined_at, file_path, decision)
            VALUES(?, ?, ?, ?, ?, ?, ?, 'PENDING')
            """, (run_id, package, version, sha256, status, quarantined_at, str(file_path)))
            conn.commit()
        return {"run_id": run_id, "package": package, "version": version, "sha256": sha256, "status": status, "quarantined_at": quarantined_at}

    def update_quarantine_decision(self, run_id: str, decision: str):
        with self.connect() as conn:
            conn.execute("UPDATE quarantine_records SET decision=? WHERE run_id=?", (decision, run_id))
            conn.commit()

    def record_audit(self, run_id: str, package: str, action: str, user: str, reason: str) -> dict:
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.connect() as conn:
            cur = conn.execute("""
            INSERT INTO audit_log(run_id, package, action, user, reason, timestamp)
            VALUES(?, ?, ?, ?, ?, ?)
            """, (run_id, package, action, user, reason, timestamp))
            conn.commit()
            return {"id": cur.lastrowid, "run_id": run_id, "package": package, "action": action, "user": user, "reason": reason, "timestamp": timestamp}

    def get_audit_logs(self, limit: int = 50) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    # --- verdict cache (rows are built and checked by backend/cavr/verdict_cache.py) ---

    VERDICT_CACHE_COLUMNS = ("cache_key", "ecosystem", "name", "version", "artifact_sha256", "subtree_digest",
                             "contract_digest", "policy_version", "analyzer_version", "status", "verdict_json",
                             "stored_at", "integrity")

    def get_cached_verdict(self, cache_key: str) -> dict | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM verdict_cache WHERE cache_key=?", (cache_key,)).fetchone()
            return dict(row) if row else None

    def list_cached_verdicts(self, limit: int = 200) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM verdict_cache ORDER BY stored_at DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def put_cached_verdict(self, row: dict) -> None:
        columns = self.VERDICT_CACHE_COLUMNS
        with self.connect() as conn:
            conn.execute(f"INSERT OR REPLACE INTO verdict_cache({', '.join(columns)}) VALUES({', '.join('?' * len(columns))})",
                         tuple(row[column] for column in columns))
            conn.commit()

    # --- verdict log (one row per verify_request; the report's hit rate and latency come from it) ---

    def record_verdict(self, source, requested, status, stage, rule, fast_gate_ms: float, cache_hit: bool, escalated: bool,
                       cache_lookup: str | None = None) -> int:
        """`cache_lookup` is HIT, MISS or NOT_REACHED for the whole request (`pipeline.cache_lookup_of`)."""
        recorded_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.connect() as conn:
            cur = conn.execute("""
            INSERT INTO verdict_log(recorded_at, source, requested, status, stage, rule, fast_gate_ms, cache_hit, escalated,
                                    cache_lookup)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (recorded_at, source, requested, status, stage, rule, float(fast_gate_ms), int(bool(cache_hit)),
                  int(bool(escalated)), cache_lookup))
            conn.commit()
            return cur.lastrowid

    def get_verdict_log(self, limit: int | None = None) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM verdict_log ORDER BY id DESC" + (" LIMIT ?" if limit is not None else ""),
                                (limit,) if limit is not None else ()).fetchall()
            return [dict(r) for r in rows]
