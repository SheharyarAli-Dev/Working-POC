"""Shared helpers for the CAVR C3, pipeline and entry-point tests (plan steps 4-14). This file holds no tests.

Nothing here fakes a result: `build_wheel` writes a real zip file, and `FakeIndex` serves the real
bytes of that file together with a registry response whose digest is computed from those bytes.
A test that wants a mismatch has to change the bytes or the response itself.
"""
import base64
import hashlib
import json
import shutil
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from packaging.utils import canonicalize_name

from backend.cavr.pipeline import verify_request
from backend.cavr.pypi_client import FILES_HOST, TransportError, registry_url
from backend.cavr.storage import CavrStorage
from backend.orchestrator.hashing import digest

REPO = Path(__file__).resolve().parents[1]
PYPDF_WHEEL = REPO / "artifacts" / "pypdf-6.19.0-py3-none-any.whl"
PYPDF_SHA256 = "7e5d6e730e7dae87d560a2cee218b852f6498c8be61966f3cd02ead971e48d14"
PYPDF_REGISTRY = next((REPO / "advisories").glob("registry-*.json"))


def sha256_file(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def pypdf_registry_response() -> dict:
    """The recorded `pypi.org/pypi/pypdf/6.19.0/json` body (retrieved 2026-09-25)."""
    return json.loads(PYPDF_REGISTRY.read_text(encoding="utf-8"))["response"]


def build_wheel(directory, name, version, files=None, requires=(), tag="py3-none-any", metadata=None,
                top_level=None, extra_entries=None, record=True) -> Path:
    """Write a small real wheel and return its path.

    `files` maps archive paths to text or bytes. `metadata=None` writes a normal METADATA with
    one `Requires-Dist` per entry of `requires`; pass a string to write that text instead, or
    False to leave METADATA out. `extra_entries` are written after everything else.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    stem = name.replace("-", "_")
    dist_info = f"{stem}-{version}.dist-info"
    if files is None:
        files = {f"{stem}/__init__.py": f"VALUE = {version!r}\n"}
    entries = dict(files)
    if metadata is None:
        lines = ["Metadata-Version: 2.1", f"Name: {name}", f"Version: {version}"]
        lines += [f"Requires-Dist: {requirement}" for requirement in requires]
        metadata = "\n".join(lines) + "\n"
    if metadata is not False:
        entries[f"{dist_info}/METADATA"] = metadata
    entries[f"{dist_info}/WHEEL"] = f"Wheel-Version: 1.0\nGenerator: cavr-tests\nRoot-Is-Purelib: true\nTag: {tag}\n"
    if top_level is not None:
        entries[f"{dist_info}/top_level.txt"] = top_level
    entries = {path: data.encode() if isinstance(data, str) else data for path, data in entries.items()}
    if record:
        rows = []
        for path, data in entries.items():
            encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            rows.append(f"{path},sha256={encoded},{len(data)}")
        rows.append(f"{dist_info}/RECORD,,")
        entries[f"{dist_info}/RECORD"] = ("\n".join(rows) + "\n").encode()
    for path, data in (extra_entries or {}).items():
        entries[path] = data.encode() if isinstance(data, str) else data
    wheel = directory / f"{stem}-{version}-{tag}.whl"
    with zipfile.ZipFile(wheel, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, data in entries.items():
            info = zipfile.ZipInfo(path, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED  # a ZipInfo does not take the archive's default
            archive.writestr(info, data)
    return wheel


def file_entry(path, url=None, packagetype="bdist_wheel") -> dict:
    """One `urls` entry of a registry response, with the real digest and size of `path`."""
    path = Path(path)
    return {
        "filename": path.name,
        "packagetype": packagetype,
        "url": url or f"https://{FILES_HOST}/packages/test/{path.name}",
        "digests": {"sha256": sha256_file(path)},
        "size": path.stat().st_size,
        "yanked": False,
        "yanked_reason": None,
    }


def registry_response(name, version, entries) -> dict:
    return {"info": {"name": name, "version": version, "yanked": False, "yanked_reason": None},
            "urls": list(entries), "vulnerabilities": []}


class FakeIndex:
    """An injectable transport: a dict of URL -> bytes (served) or Exception (raised).

    `calls` lists every URL asked for, in order, so a test can assert that nothing was downloaded.
    """

    def __init__(self):
        self.routes = {}
        self.calls = []
        self.chunk_size = 4096

    def add(self, name, version, *wheels, response=None):
        """Register a release: its JSON and the bytes of every wheel file. Returns the response."""
        if response is None:
            response = registry_response(name, version, [file_entry(wheel) for wheel in wheels])
        self.routes[registry_url(canonicalize_name(name), version)] = json.dumps(response).encode()
        for entry, wheel in zip(response["urls"], wheels):
            self.routes[entry["url"]] = Path(wheel).read_bytes()
        return response

    def add_pypdf(self):
        return self.add("pypdf", "6.19.0", PYPDF_WHEEL, response=pypdf_registry_response())

    def downloads(self) -> list[str]:
        return [url for url in self.calls if FILES_HOST in url]

    def stream(self, url):
        self.calls.append(url)
        body = self.routes.get(url)
        if body is None:
            raise TransportError(f"HTTP 404 for {url}", status=404)
        if isinstance(body, Exception):
            raise body
        for start in range(0, len(body), self.chunk_size):
            yield body[start:start + self.chunk_size]


def write_osv_cache(cache_dir, name, version, vulns, age_days=0.0) -> Path:
    """Write an advisory answer in the exact format `OSV.query(live=True)` stores it.

    `vulns` is a list of OSV advisories: [] for "none known", a recorded response, or hand-written
    ones (give those an id starting with "SYNTH-").
    """
    query = {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
    body = {"vulns": list(vulns), "pages": [{"vulns": list(vulns)}]}
    value = {"query": query, "retrieved_at": (datetime.now(timezone.utc) - timedelta(days=age_days)).isoformat(),
             "source": "https://api.osv.dev/v1/query", "response": body, "response_sha256": digest(body)}
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / (digest(query) + ".json")
    path.write_text(json.dumps(value))
    return path


def synthetic_advisory(advisory_id, name, introduced="0", fixed=None) -> dict:
    """A hand-written OSV advisory for `name`, affected from `introduced` up to (not including) `fixed`."""
    assert advisory_id.startswith("SYNTH-")
    events = [{"introduced": introduced}] + ([{"fixed": fixed}] if fixed else [])
    return {"id": advisory_id, "summary": "synthetic test advisory",
            "affected": [{"package": {"name": name, "ecosystem": "PyPI"}, "ranges": [{"type": "ECOSYSTEM", "events": events}]}]}


# --- one project, one index, one cache: the world of the pipeline tests (steps 11-14) ---------------------

INVOICEHUB = REPO / "demo_project" / "InvoiceHub"
RECORDED_6_19_0 = json.loads((REPO / "tests" / "test_cavr_data" / "osv-pypdf-6.19.0.json").read_text())["response"].get("vulns", [])
POLICY = {
    "project_task_description": "Invoice PDF text extraction",
    "allowed_scopes": ["FILE_READ:invoice_documents", "FILE_WRITE:scratch_tmp", "PROCESS_EXEC:none", "NETWORK_CONNECT:none"],
    "approved_requirements": ["pypdf==6.19.0", "demo==1.0", "top==1.0", "helper==2.0", "native==1.0"],
    "denied_packages": [{"name": "reqeusts", "reason": "typosquat of requests"}],
}
UNGUARDED = "\n\ndef quick(path):\n    return PdfReader(path)\n"
CLEAN_DEMO = {"demo/__init__.py": "def run():\n    return 1\n"}
USES_DEMO = "import demo\n\n\ndef go():\n    return demo.run()\n"


class World:
    """One project directory, one package index, one cache database, one advisory cache."""

    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.project = tmp_path / "project"
        shutil.copytree(INVOICEHUB / "app", self.project / "app")
        for name in ("requirements.txt", "dependencies.lock.json"):
            shutil.copy(INVOICEHUB / name, self.project / name)
        self.index = FakeIndex()
        self.index.add_pypdf()
        self.store = CavrStorage(tmp_path / "cavr.sqlite3")
        self.osv_dir = tmp_path / "osv"
        self.advisories("pypdf", "6.19.0", RECORDED_6_19_0)
        self.policy = json.loads(json.dumps(POLICY))
        self.builds = 0

    def advisories(self, name, version, vulns):
        write_osv_cache(self.osv_dir, name, version, vulns)

    def add(self, name, version, files=None, requires=(), lock=True, **wheel_args):
        """Build a wheel, serve it, record "no advisories" for it and (by default) pin it in the lockfile."""
        self.builds += 1
        wheel = build_wheel(self.tmp_path / f"build{self.builds}", name, version, files=files, requires=requires, **wheel_args)
        self.index.add(name, version, wheel)
        self.advisories(name, version, [])
        if lock:
            path = self.project / "dependencies.lock.json"
            lockfile = json.loads(path.read_text())
            lockfile["packages"].append({"name": name, "version": version, "ecosystem": "PyPI"})
            path.write_text(json.dumps(lockfile))
        return wheel

    def write(self, relative, text):
        target = self.project / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def verify(self, request="pip install pypdf==6.19.0", **overrides):
        args = {"transport": self.index, "quarantine_dir": self.tmp_path / "quarantine", "advisory_cache_dir": self.osv_dir,
                "live_advisories": False}
        args.update(overrides)
        return verify_request(request, args.pop("project_dir", self.project), args.pop("policy", self.policy),
                              args.pop("store", self.store), **args)

    def cache_rows(self):
        with self.store.connect() as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM verdict_cache").fetchall()]
