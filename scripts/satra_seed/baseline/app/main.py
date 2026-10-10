import sqlite3
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

SEED_USERS = [
    (1, "alice", "user", "tok-alice"),
    (2, "bob", "user", "tok-bob"),
    (3, "admin", "admin", "tok-admin"),
]
SEED_INVOICES = [
    (1, 1, "alice consulting retainer", 120),
    (2, 2, "bob hosting renewal", 80),
]


class NewInvoice(BaseModel):
    description: str
    amount: int


def create_app(data_dir):
    data_dir = Path(data_dir)
    uploads_dir = data_dir / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)
    db_path = data_dir / "app.db"

    def connect():
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn

    conn = connect()
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, role TEXT, token TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS invoices (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER, description TEXT, amount INTEGER)")
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        conn.executemany("INSERT INTO users VALUES (?, ?, ?, ?)", SEED_USERS)
        conn.executemany("INSERT INTO invoices VALUES (?, ?, ?, ?)", SEED_INVOICES)
    conn.commit()
    conn.close()

    app = FastAPI()

    def current_user(authorization: str = Header(default=None)):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "authentication required")
        conn = connect()
        row = conn.execute("SELECT id, name, role FROM users WHERE token = ?", (authorization[7:],)).fetchone()
        conn.close()
        if row is None:
            raise HTTPException(401, "authentication required")
        return dict(row)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/invoices/{invoice_id}")
    def read_invoice(invoice_id: int, user=Depends(current_user)):
        conn = connect()
        row = conn.execute("SELECT id, owner_id, description, amount FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
        conn.close()
        if row is None:
            raise HTTPException(404, "not found")
        if user["role"] != "admin" and row["owner_id"] != user["id"]:
            raise HTTPException(403, "forbidden")
        return dict(row)

    @app.get("/invoices")
    def search_invoices(search: str = "", user=Depends(current_user)):
        conn = connect()
        rows = conn.execute(
            "SELECT id, owner_id, description, amount FROM invoices WHERE owner_id = ? AND description LIKE ?",
            (user["id"], "%" + search + "%"),
        ).fetchall()
        conn.close()
        return {"items": [dict(row) for row in rows]}

    @app.post("/invoices", status_code=201)
    def create_invoice(body: NewInvoice, user=Depends(current_user)):
        conn = connect()
        cursor = conn.execute(
            "INSERT INTO invoices (owner_id, description, amount) VALUES (?, ?, ?)",
            (user["id"], body.description, body.amount),
        )
        conn.commit()
        created = cursor.lastrowid
        conn.close()
        return {"id": created, "owner_id": user["id"], "description": body.description, "amount": body.amount}

    @app.get("/files/{name:path}")
    def read_file(name: str):
        root = uploads_dir.resolve()
        target = (root / name).resolve()
        if not target.is_relative_to(root):
            raise HTTPException(400, "invalid path")
        if not target.is_file():
            raise HTTPException(404, "not found")
        return PlainTextResponse(target.read_text())

    return app
