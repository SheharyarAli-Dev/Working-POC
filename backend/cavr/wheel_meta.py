"""C3b: read what a wheel says about itself, without unpacking or running it.

`read_wheel(path, expected_name, expected_version)` opens the wheel as a zip, checks every
entry before reading any, and returns OK, REJECTED or UNRESOLVED:

    NOT_A_WHEEL          not a readable zip, a damaged or encrypted entry, no WHEEL file -> UNRESOLVED
    ZIP_BUDGET           too many entries, too much uncompressed data, a zip-bomb
                         compression ratio, or an oversized metadata file                -> UNRESOLVED
    DUPLICATE_ENTRY      two entries with the same name (also when only case differs)    -> UNRESOLVED
    UNSAFE_PATH          an entry that is absolute, has `..`, a backslash or a drive,
                         or is a symbolic link                                           -> REJECTED
    METADATA_MISSING     no top-level `*.dist-info/METADATA`                             -> UNRESOLVED
    DIST_INFO_AMBIGUOUS  more than one top-level `*.dist-info` directory                 -> UNRESOLVED
    METADATA_INVALID     METADATA cannot be parsed, or a Requires-Dist line cannot       -> UNRESOLVED
    METADATA_MISMATCH    Name/Version differ from the dist-info directory or from
                         the name and version that were asked for                        -> REJECTED
    METADATA_READ        none of the above                                               -> OK

Nothing is extracted to disk. Only METADATA, WHEEL, RECORD and top_level.txt are read, each
with a size limit. Import names come from top_level.txt, else RECORD, else the entry names;
importable names found in the archive but not declared are listed in `undeclared_import_names`.
"""
from __future__ import annotations
import csv
import io
import re
import stat
import unicodedata
import zipfile
import zlib
from email.parser import HeaderParser
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

MAX_ENTRIES = 20_000
MAX_TOTAL_UNCOMPRESSED = 500 * 1024 * 1024
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_RATIO = 200
RATIO_FLOOR_BYTES = 10 * 1024 * 1024  # the ratio is only judged above this much uncompressed data

NAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
DRIVE = re.compile(r"^[A-Za-z]:")
NATIVE = re.compile(r"\.(so|pyd|dll|dylib)$|\.so(\.\d+)+$", re.IGNORECASE)
EXTENSION_MODULE = re.compile(r"\.(so|pyd)$", re.IGNORECASE)
ZIP_ERRORS = (zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error, OSError, EOFError, RuntimeError, NotImplementedError)


class WheelProblem(Exception):
    """Ends `read_wheel` with a result other than OK."""

    def __init__(self, outcome: str, rule: str, reason: str):
        super().__init__(reason)
        self.outcome, self.rule, self.reason = outcome, rule, reason


def read_wheel(path, expected_name=None, expected_version=None) -> dict:
    """Metadata of the wheel at `path`. Every result has the same keys.

    `expected_name` / `expected_version` are what was asked for; when given, a wheel whose
    METADATA says something else is REJECTED.
    """
    fields = {"path": str(path) if path is not None else None}
    try:
        with zipfile.ZipFile(Path(path)) as archive:
            _read(archive, fields, expected_name, expected_version)
    except WheelProblem as stop:
        return _result(stop.outcome, stop.rule, stop.reason, **fields)
    except ZIP_ERRORS + (TypeError, ValueError) as exc:
        return _result("UNRESOLVED", "NOT_A_WHEEL", f"cannot read the file as a wheel: {exc}", **fields)
    return _result("OK", "METADATA_READ", f"{fields['name']} {fields['version']}: metadata read", **fields)


def check_entries(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    """The entries of an open zip, after the budget and path checks. Raises `WheelProblem` on a problem.

    The sizes are the ones declared in the zip directory; `zipfile` never returns more than the
    declared size for an entry, so the budget also bounds what can be read afterwards.
    """
    infos = archive.infolist()
    if len(infos) > MAX_ENTRIES:
        raise WheelProblem("UNRESOLVED", "ZIP_BUDGET", f"{len(infos)} entries; the budget is {MAX_ENTRIES}")
    total = sum(info.file_size for info in infos)
    if total > MAX_TOTAL_UNCOMPRESSED:
        raise WheelProblem("UNRESOLVED", "ZIP_BUDGET", f"{total} uncompressed bytes; the budget is {MAX_TOTAL_UNCOMPRESSED}")
    compressed = sum(info.compress_size for info in infos)
    if total > RATIO_FLOOR_BYTES and total > MAX_RATIO * max(compressed, 1):
        raise WheelProblem("UNRESOLVED", "ZIP_BUDGET",
                    f"compression ratio {total // max(compressed, 1)}:1 is over the budget of {MAX_RATIO}:1")
    seen = set()
    for info in infos:
        name = info.filename
        if _unsafe_path(name):
            raise WheelProblem("REJECTED", "UNSAFE_PATH", f"entry would be written outside the install directory: {name!r}")
        if stat.S_ISLNK(info.external_attr >> 16):
            raise WheelProblem("REJECTED", "UNSAFE_PATH", f"entry is a symbolic link: {name!r}")
        if info.flag_bits & 0x1:
            raise WheelProblem("UNRESOLVED", "NOT_A_WHEEL", f"entry is encrypted: {name!r}")
        # The same name for a file system that ignores case or stores names in one Unicode form.
        folded = unicodedata.normalize("NFC", name).casefold()
        if folded in seen:
            raise WheelProblem("UNRESOLVED", "DUPLICATE_ENTRY", f"two entries are named {name!r} (ignoring case)")
        seen.add(folded)
    return infos


def read_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int | None = None) -> bytes:
    """The bytes of one checked entry, or `WheelProblem` when it is larger than `limit`."""
    limit = MAX_MEMBER_BYTES if limit is None else limit
    if info.file_size > limit:
        raise WheelProblem("UNRESOLVED", "ZIP_BUDGET", f"{info.filename} is {info.file_size} bytes; the budget is {limit}")
    return archive.read(info)


# --- internals ---------------------------------------------------------------

def _read(archive: zipfile.ZipFile, fields: dict, expected_name, expected_version) -> None:
    infos = check_entries(archive)
    by_name = {info.filename: info for info in infos}
    names = [info.filename for info in infos if not info.is_dir()]
    fields.update(entry_count=len(infos), total_uncompressed=sum(info.file_size for info in infos))

    dist_infos = sorted({name.split("/")[0] for name in by_name if "/" in name and name.split("/")[0].endswith(".dist-info")})
    if len(dist_infos) > 1:
        raise WheelProblem("UNRESOLVED", "DIST_INFO_AMBIGUOUS", f"more than one dist-info directory: {dist_infos}")
    if not dist_infos or f"{dist_infos[0]}/METADATA" not in by_name:
        raise WheelProblem("UNRESOLVED", "METADATA_MISSING", "the wheel has no top-level *.dist-info/METADATA")
    dist_info = fields["dist_info"] = dist_infos[0]

    # METADATA: name, version, dependencies.
    metadata = _headers(read_member(archive, by_name[f"{dist_info}/METADATA"]), "METADATA", "METADATA_INVALID")
    name, version = _single(metadata, "Name"), _single(metadata, "Version")
    if not NAME.fullmatch(name):
        raise WheelProblem("UNRESOLVED", "METADATA_INVALID", f"METADATA Name is not a package name: {name!r}")
    parsed_version = _version(version, "METADATA Version")
    fields.update(name=canonicalize_name(name), metadata_name=name, version=version,
                  requires_python=metadata.get("Requires-Python"),
                  provides_extra=sorted(metadata.get_all("Provides-Extra") or []))
    requires = [_requirement(line) for line in metadata.get_all("Requires-Dist") or []]

    # The same identity three times: the request, the dist-info directory, METADATA.
    stem_name, _, stem_version = dist_info[:-len(".dist-info")].rpartition("-")
    if canonicalize_name(stem_name) != fields["name"] or _version(stem_version, "dist-info version", "") != parsed_version:
        raise WheelProblem("REJECTED", "METADATA_MISMATCH",
                    f"METADATA says {name} {version} but its directory is {dist_info}")
    if expected_name is not None and canonicalize_name(str(expected_name)) != fields["name"]:
        raise WheelProblem("REJECTED", "METADATA_MISMATCH", f"asked for {expected_name}, the wheel's METADATA says {name}")
    if expected_version is not None and _version(str(expected_version), "expected version") != parsed_version:
        raise WheelProblem("REJECTED", "METADATA_MISMATCH",
                    f"asked for {fields['name']} {expected_version}, the wheel's METADATA says {version}")
    fields["requires_dist"] = requires

    # WHEEL: tags.
    if f"{dist_info}/WHEEL" not in by_name:
        raise WheelProblem("UNRESOLVED", "NOT_A_WHEEL", f"{dist_info}/WHEEL is missing")
    wheel = _headers(read_member(archive, by_name[f"{dist_info}/WHEEL"]), "WHEEL", "NOT_A_WHEEL")
    fields.update(wheel_tags=sorted(wheel.get_all("Tag") or []),
                  root_is_purelib=str(wheel.get("Root-Is-Purelib", "")).strip().lower() == "true")

    # Import names: declared (top_level.txt, else RECORD) and what the archive really holds.
    in_archive = _import_names(names)
    declared, source = in_archive, "archive"
    if f"{dist_info}/top_level.txt" in by_name:
        text = _text(read_member(archive, by_name[f"{dist_info}/top_level.txt"]), "top_level.txt")
        declared, source = sorted({line.strip() for line in text.splitlines() if line.strip().isidentifier()}), "top_level.txt"
    elif f"{dist_info}/RECORD" in by_name:
        text = _text(read_member(archive, by_name[f"{dist_info}/RECORD"]), "RECORD")
        try:
            listed = [row[0] for row in csv.reader(io.StringIO(text)) if row]
        except csv.Error as exc:
            raise WheelProblem("UNRESOLVED", "METADATA_INVALID", f"RECORD cannot be parsed: {exc}")
        declared, source = _import_names(listed), "RECORD"
    fields.update(import_names=declared, import_names_source=source,
                  undeclared_import_names=sorted(set(in_archive) - set(declared)),
                  native_files=sorted(name for name in names if NATIVE.search(name)),
                  pth_files=sorted(name for name in names if name.lower().endswith(".pth")))


def _result(outcome, rule, reason, path=None, name=None, metadata_name=None, version=None, requires_python=None,
            requires_dist=None, provides_extra=None, dist_info=None, entry_count=None, total_uncompressed=None,
            wheel_tags=None, root_is_purelib=None, import_names=None, import_names_source=None,
            undeclared_import_names=None, native_files=None, pth_files=None) -> dict:
    return {"result": outcome, "rule": rule, "reason": reason, "path": path, "name": name,
            "metadata_name": metadata_name, "version": version, "requires_python": requires_python,
            "requires_dist": requires_dist or [], "provides_extra": provides_extra or [], "dist_info": dist_info,
            "entry_count": entry_count, "total_uncompressed": total_uncompressed, "wheel_tags": wheel_tags or [],
            "root_is_purelib": root_is_purelib, "import_names": import_names or [],
            "import_names_source": import_names_source, "undeclared_import_names": undeclared_import_names or [],
            "native_files": native_files or [], "pth_files": pth_files or []}


def _unsafe_path(name: str) -> bool:
    if not name or name.startswith("/") or "\\" in name or "\0" in name or DRIVE.match(name):
        return True
    parts = (name[:-1] if name.endswith("/") else name).split("/")
    return any(part in ("", ".", "..") for part in parts)


def _text(data: bytes, what: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WheelProblem("UNRESOLVED", "METADATA_INVALID", f"{what} is not UTF-8: {exc}")


def _headers(data: bytes, what: str, rule: str):
    """The header block of METADATA or WHEEL (RFC 822 style; it ends at the first blank line)."""
    try:
        message = HeaderParser().parsestr(data.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise WheelProblem("UNRESOLVED", rule, f"{what} is not UTF-8: {exc}")
    if message.defects:
        # The parser stops reading headers at a line that is not one, so later fields would be silently lost.
        raise WheelProblem("UNRESOLVED", rule, f"{what} has a malformed header block: "
                           + ", ".join(type(defect).__name__ for defect in message.defects))
    return message


def _single(metadata, field: str) -> str:
    values = metadata.get_all(field) or []
    if len(values) != 1 or not str(values[0]).strip():
        raise WheelProblem("UNRESOLVED", "METADATA_INVALID", f"METADATA must have exactly one {field}; found {len(values)}")
    return str(values[0]).strip()


def _version(text: str, what: str, rule: str = "METADATA_INVALID"):
    """A parsed version; `WheelProblem` when it is not one. With `rule=""` an unparseable version is returned as None."""
    try:
        return Version(text)
    except InvalidVersion:
        if not rule:
            return None
        raise WheelProblem("UNRESOLVED", rule, f"{what} is not a version: {text!r}")


def _requirement(line: str) -> dict:
    try:
        requirement = Requirement(str(line))
    except InvalidRequirement as exc:
        raise WheelProblem("UNRESOLVED", "METADATA_INVALID", f"Requires-Dist cannot be parsed: {line!r} ({str(exc).splitlines()[0]})")
    if requirement.url:
        raise WheelProblem("UNRESOLVED", "METADATA_INVALID", f"Requires-Dist points at a URL, which is not verified: {line!r}")
    return {"raw": str(line).strip(), "name": requirement.name, "canonical_name": canonicalize_name(requirement.name),
            "specifier": str(requirement.specifier), "marker": str(requirement.marker) if requirement.marker else None,
            "extras": sorted(requirement.extras)}


def _import_names(paths: list[str]) -> list[str]:
    """Top-level importable names among archive paths: packages, `.py` modules and extension modules."""
    found = set()
    for path in paths:
        parts = path.split("/")
        if parts[0].endswith(".data"):
            if len(parts) < 3 or parts[1] not in ("purelib", "platlib"):
                continue
            parts = parts[2:]
        if parts[0].endswith(".dist-info"):
            continue
        top = parts[0]
        if len(parts) == 1:
            if not (top.endswith(".py") or EXTENSION_MODULE.search(top)):
                continue
            top = top.split(".")[0]
        if top.isidentifier():
            found.add(top)
    return sorted(found)
