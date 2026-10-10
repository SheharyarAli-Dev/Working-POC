"""C3a: fetch one PyPI release, download its wheel into quarantine and check the SHA-256.

`fetch_artifact(name, version, quarantine_dir)` answers OK, REJECTED or UNRESOLVED:

    INVALID_REQUEST          name or version is not usable (also: local versions) -> UNRESOLVED
    REGISTRY_UNAVAILABLE     network error, timeout, HTTP status other than 200   -> UNRESOLVED
    RELEASE_NOT_FOUND        the registry answers 404 for this name and version   -> UNRESOLVED
    REGISTRY_INVALID         the response is not the expected JSON, or describes
                             another name or version, or lists a broken wheel     -> UNRESOLVED
    YANKED                   release or chosen file is not marked `yanked: false`  -> UNRESOLVED
    NO_WHEEL                 the release has no wheel (for example sdist only)    -> UNRESOLVED
    NO_COMPATIBLE_WHEEL      wheels exist, none fits this interpreter             -> UNRESOLVED
    URL_NOT_ALLOWED          file URL is not https://files.pythonhosted.org/...   -> UNRESOLVED
    REGISTRY_DIGEST_MISSING  no well-formed sha256 for the file in the response    -> UNRESOLVED
    TOO_LARGE                declared or received size is over the cap            -> UNRESOLVED
    DOWNLOAD_FAILED          the file could not be downloaded or written          -> UNRESOLVED
    HASH_MISMATCH            SHA-256 of the file on disk != registry digest       -> REJECTED
    HASH_MATCH               SHA-256 of the file on disk == registry digest       -> OK

OK is returned from one place, after the bytes on disk have been hashed. The file is never
opened as a zip, imported or executed here. A REJECTED file is kept for evidence with
".rejected" added to its name, so that nothing later can pick it up as a wheel.

The HTTP transport is injectable: any object with `stream(url)` that yields the body as
chunks of bytes and raises `TransportError` on failure. Tests pass one that reads local files.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import tempfile
import time
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx
from packaging.tags import sys_tags
from packaging.utils import InvalidWheelFilename, canonicalize_name, parse_wheel_filename
from packaging.version import InvalidVersion, Version

REGISTRY_HOST = "pypi.org"
FILES_HOST = "files.pythonhosted.org"
MAX_REGISTRY_BYTES = 20 * 1024 * 1024
MAX_ARTIFACT_BYTES = 200 * 1024 * 1024
DEADLINE_SECONDS = 120
CHUNK_BYTES = 64 * 1024

NAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class TransportError(Exception):
    """The transport could not deliver the body. `status` is the HTTP status when there was one."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class HttpxTransport:
    """Plain HTTPS GET. Redirects are not followed; any status other than 200 is an error."""

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout

    def stream(self, url: str):
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=False) as client:
                with client.stream("GET", url) as response:
                    if response.status_code != 200:
                        raise TransportError(f"HTTP {response.status_code} for {url}", status=response.status_code)
                    yield from response.iter_bytes(CHUNK_BYTES)
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            raise TransportError(f"{type(exc).__name__}: {exc}") from exc


def registry_url(name: str, version: str) -> str:
    return f"https://{REGISTRY_HOST}/pypi/{quote(name, safe='')}/{quote(version, safe='')}/json"


def fetch_artifact(name, version, quarantine_dir, transport=None, max_bytes: int = MAX_ARTIFACT_BYTES,
                   deadline_seconds: float = DEADLINE_SECONDS, supported_tags=None) -> dict:
    """Download the wheel of `name==version` into `quarantine_dir` and compare its SHA-256.

    Every result has the same keys. `sha256` and `size` are those of the bytes written to
    disk; `path` is where they are. They stay None when nothing was downloaded.
    """
    fields = {"name": name if isinstance(name, str) else None, "version": version if isinstance(version, str) else None}

    def result(outcome, rule, reason, **more):
        return _result(outcome, rule, reason, **{**fields, **more})

    problem = request_problem(name, version)
    if problem:
        return result("UNRESOLVED", "INVALID_REQUEST", problem)
    name, version = canonicalize_name(name), version.strip()
    fields = {"name": name, "version": version, "registry_url": registry_url(name, version)}
    transport = transport or HttpxTransport()

    # 1. Release metadata from the registry.
    try:
        body = _read_capped(transport, fields["registry_url"], MAX_REGISTRY_BYTES, deadline_seconds)
    except _TooLarge:
        return result("UNRESOLVED", "REGISTRY_INVALID", f"registry response is larger than {MAX_REGISTRY_BYTES} bytes")
    except TransportError as exc:
        if exc.status == 404:
            return result("UNRESOLVED", "RELEASE_NOT_FOUND", f"PyPI has no release {name} {version}")
        return result("UNRESOLVED", "REGISTRY_UNAVAILABLE", f"cannot read the registry: {exc}")
    except OSError as exc:
        return result("UNRESOLVED", "REGISTRY_UNAVAILABLE", f"cannot read the registry: {exc}")
    release, problem = _parse_release(body, name, version)
    if problem:
        return result("UNRESOLVED", "REGISTRY_INVALID", problem)
    info, entries = release["info"], release["urls"]
    fields["files_listed"] = [entry.get("filename") for entry in entries]
    if info.get("yanked") is not False:
        return result("UNRESOLVED", "YANKED", f"release {name} {version} is yanked: {info.get('yanked_reason')}")

    # 2. Pick the wheel and check everything the registry says about it before downloading.
    entry, problem = select_wheel(entries, name, version, supported_tags)
    if problem:
        return result("UNRESOLVED", problem[0], problem[1])
    filename, url = entry["filename"], entry.get("url")
    fields.update(filename=filename, url=url if isinstance(url, str) else None,
                  upload_time=entry.get("upload_time_iso_8601"), requires_python=entry.get("requires_python"))
    if entry.get("yanked") is not False:
        return result("UNRESOLVED", "YANKED", f"file {filename} is yanked: {entry.get('yanked_reason')}")
    if not _allowed_file_url(url):
        return result("UNRESOLVED", "URL_NOT_ALLOWED", f"file URL is not on https://{FILES_HOST}: {url!r}")
    digests = entry.get("digests")
    expected = digests.get("sha256") if isinstance(digests, dict) else None
    expected = expected.lower() if isinstance(expected, str) else ""
    if not SHA256.match(expected):
        return result("UNRESOLVED", "REGISTRY_DIGEST_MISSING", f"registry gives no sha256 for {filename}")
    fields["registry_sha256"] = expected
    declared = entry.get("size")
    if isinstance(declared, bool) or not isinstance(declared, int) or declared < 0:
        return result("UNRESOLVED", "REGISTRY_INVALID", f"registry size of {filename} is not a whole number: {declared!r}")
    fields["registry_size"] = declared
    if declared > max_bytes:
        return result("UNRESOLVED", "TOO_LARGE", f"{filename} is {declared} bytes; the cap is {max_bytes}")

    # 3. Stream into quarantine, then hash what is on disk.
    quarantine_dir = Path(quarantine_dir)
    partial = None
    try:
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        handle, partial = tempfile.mkstemp(dir=quarantine_dir, prefix=filename + ".", suffix=".part")
        with os.fdopen(handle, "wb") as out:
            for chunk in _chunks(transport, url, max_bytes, deadline_seconds):
                out.write(chunk)
        actual, size = _sha256_of_file(partial)
        matches = actual == expected
        final = quarantine_dir / (filename if matches else filename + ".rejected")
        os.replace(partial, final)
        partial = None
    except _TooLarge:
        return result("UNRESOLVED", "TOO_LARGE", f"{filename} sent more than the cap of {max_bytes} bytes")
    except (TransportError, OSError) as exc:
        return result("UNRESOLVED", "DOWNLOAD_FAILED", f"cannot download {filename}: {exc}")
    finally:
        if partial is not None:
            Path(partial).unlink(missing_ok=True)

    fields.update(sha256=actual, size=size, path=str(final))
    if not matches:
        return result("REJECTED", "HASH_MISMATCH",
                      f"{filename}: SHA-256 of the downloaded file is {actual}, the registry says {expected}")
    return result("OK", "HASH_MATCH", f"{filename}: SHA-256 of the downloaded file equals the registry digest")


def select_wheel(entries: list[dict], name: str, version: str, supported_tags=None):
    """Choose the wheel to verify. Returns (entry, None) or (None, (rule, reason)).

    Every wheel entry must be named `{name}-{version}-...whl` with no directory part; one that
    is not makes the whole response invalid. Among the wheels whose tags this interpreter
    supports, the one pip would prefer (best-ranked tag) is taken; the filename breaks ties.
    """
    supported = list(supported_tags) if supported_tags is not None else list(sys_tags())
    rank = {tag: position for position, tag in enumerate(supported)}
    wheels = []
    for entry in entries:
        filename = entry.get("filename")
        if entry.get("packagetype") != "bdist_wheel" and not (isinstance(filename, str) and filename.endswith(".whl")):
            continue
        if not isinstance(filename, str) or "/" in filename or "\\" in filename:
            return None, ("REGISTRY_INVALID", f"wheel entry has an unusable filename: {filename!r}")
        try:
            wheel_name, wheel_version, _, tags = parse_wheel_filename(filename)
        except (InvalidWheelFilename, InvalidVersion) as exc:
            return None, ("REGISTRY_INVALID", f"wheel entry has an unusable filename: {exc}")
        if wheel_name != name or wheel_version != Version(version):
            return None, ("REGISTRY_INVALID", f"wheel {filename} is not a file of {name} {version}")
        wheels.append((min((rank[tag] for tag in tags if tag in rank), default=None), filename, entry))
    if not wheels:
        return None, ("NO_WHEEL", f"{name} {version} has no wheel on PyPI; source distributions are not verified")
    compatible = sorted((position, filename, entry) for position, filename, entry in wheels if position is not None)
    if not compatible:
        return None, ("NO_COMPATIBLE_WHEEL",
                      f"no wheel of {name} {version} fits this interpreter: {sorted(w[1] for w in wheels)}")
    return compatible[0][2], None


# --- internals ---------------------------------------------------------------

class _TooLarge(Exception):
    pass


def _result(outcome, rule, reason, name=None, version=None, registry_url=None, files_listed=None, filename=None,
            url=None, upload_time=None, requires_python=None, registry_sha256=None, registry_size=None,
            sha256=None, size=None, path=None) -> dict:
    return {"result": outcome, "rule": rule, "reason": reason, "ecosystem": "PyPI", "name": name, "version": version,
            "registry_url": registry_url, "files_listed": files_listed or [], "filename": filename, "url": url,
            "upload_time": upload_time, "requires_python": requires_python, "registry_sha256": registry_sha256,
            "registry_size": registry_size, "sha256": sha256, "size": size, "path": path}


def request_problem(name, version) -> str | None:
    if not isinstance(name, str) or not NAME.match(name):
        return f"not a package name: {name!r}"
    if not isinstance(version, str):
        return f"not a version: {version!r}"
    try:
        parsed = Version(version)
    except InvalidVersion:
        return f"not a version: {version!r}"
    if parsed.local is not None:
        return f"{version} is a local version; PyPI does not host local versions"
    return None


def _chunks(transport, url: str, max_bytes: int, deadline_seconds: float):
    """The body of `url` in chunks; stops with `_TooLarge` over the cap and `TransportError` over the deadline."""
    started = time.monotonic()
    stream = transport.stream(url)
    received = 0
    try:
        for chunk in stream:
            received += len(chunk)
            if received > max_bytes:
                raise _TooLarge()
            if time.monotonic() - started > deadline_seconds:
                raise TransportError(f"deadline of {deadline_seconds} seconds passed after {received} bytes")
            yield chunk
    finally:
        close = getattr(stream, "close", None)
        if close:
            close()


def _read_capped(transport, url: str, max_bytes: int, deadline_seconds: float) -> bytes:
    return b"".join(_chunks(transport, url, max_bytes, deadline_seconds))


def _parse_release(body: bytes, name: str, version: str):
    """(release, None) when the response describes exactly `name` `version`; otherwise (None, reason)."""
    try:
        release = json.loads(body.decode("utf-8"))
    except (ValueError, RecursionError) as exc:
        return None, f"registry response is not JSON: {exc}"
    if not isinstance(release, dict) or not isinstance(release.get("info"), dict) or not isinstance(release.get("urls"), list):
        return None, "registry response has no info object and urls list"
    if not all(isinstance(entry, dict) for entry in release["urls"]):
        return None, "registry response lists a file that is not an object"
    info = release["info"]
    if not isinstance(info.get("name"), str) or canonicalize_name(info["name"]) != name:
        return None, f"registry response is for another package: {info.get('name')!r}"
    try:
        same_version = isinstance(info.get("version"), str) and Version(info["version"]) == Version(version)
    except InvalidVersion:
        same_version = False
    if not same_version:
        return None, f"registry response is for another version: {info.get('version')!r}"
    return release, None


def _allowed_file_url(url) -> bool:
    if not isinstance(url, str):
        return False
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return parts.scheme == "https" and parts.netloc == FILES_HOST


def _sha256_of_file(path) -> tuple[str, int]:
    """SHA-256 and length of the file, read back from disk."""
    sha, size = hashlib.sha256(), 0
    with open(path, "rb") as source:
        while chunk := source.read(CHUNK_BYTES):
            sha.update(chunk)
            size += len(chunk)
    return sha.hexdigest(), size
