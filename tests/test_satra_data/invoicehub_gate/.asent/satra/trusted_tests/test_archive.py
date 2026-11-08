"""Trusted archive test: archival is admin-only and keeps the ownership boundary (FR-04, FR-07)."""
import sqlite3
import time

from fastapi.testclient import TestClient

from app.main import create_app


def test_archive_is_admin_only_and_keeps_ownership(tmp_path, bearer, upload):
    with TestClient(create_app(tmp_path, seed=True)) as c:
        alice, bob, admin = bearer(c, "alice"), bearer(c, "bob"), bearer(c, "admin")
        old, recent = upload(c, alice, "old.pdf"), upload(c, alice, "new.pdf")
        with sqlite3.connect(tmp_path / "invoicehub.sqlite3") as db:
            db.execute("UPDATE invoices SET created=? WHERE id=?", (time.time() - 91 * 86400, old))
        assert c.post("/admin/archive", headers=alice).status_code == 403
        assert c.post("/admin/archive").status_code == 401
        assert c.post("/admin/archive", headers=admin).json()["archived"] == 1
        assert c.get(f"/invoices/{old}", headers=alice).json()["archived"] == 1
        assert c.get(f"/invoices/{recent}", headers=alice).json()["archived"] == 0
        assert c.get(f"/invoices/{old}", headers=bob).status_code == 403
        assert c.delete(f"/invoices/{old}", headers=bob).status_code == 403
        assert c.delete(f"/invoices/{old}", headers=alice).status_code == 200
