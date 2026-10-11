"""C1 capture: turn a `pip install ...` command into a structured capture record.

Nothing here downloads, installs or executes anything. The module only reads the command
and the requirements/constraints files it names, and writes down what was asked for.

A capture record is a plain dict:

    source        "pip_command"
    command       the command as a list of tokens
    action        the pip subcommand ("install"), or None when there is none
    options       recognised options that do not change what is installed, as [name, value]
    requirements  named requirements that were asked for (see `parse_requirement`)
    constraints   named requirements that came from `-c` files
    unsupported   forms CAVR does not verify in M1: URLs, VCS, local paths, -e, custom indexes
    errors        things that could not be read at all: malformed lines, missing files
    files         every requirements/constraints file that was read, with the SHA-256 of its bytes
    complete      True only when `unsupported` and `errors` are both empty

`complete` is the fail-closed switch: a later stage must not treat a record as fully
captured unless it is True. An unpinned requirement (`a>=1`) is still a complete capture;
refusing it is the requirement gate's job (C2), not the capture's.

Limits on `-r` / `-c` files: only files inside the directory the command ran in are read
(a file outside it, or one given as a URL, is recorded as unsupported), only regular files
are opened, and at most `MAX_REQUIREMENTS_FILES` files are read for one command.

A password inside a URL (`https://user:password@host/...`) is replaced by `***` in everything
the record keeps (`redact`), because the record is printed, logged and shown on the dashboard.
"""
from __future__ import annotations

import hashlib
import re
import shlex
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

MAX_REQUIREMENTS_FILE_BYTES = 1_000_000
MAX_REQUIREMENTS_FILES = 100

PIP_PROGRAM = re.compile(r"^pip(\d+(\.\d+)?)?(\.exe)?$", re.IGNORECASE)
PYTHON_PROGRAM = re.compile(r"^(python(\d+(\.\d+)?)?|py)(\.exe)?$", re.IGNORECASE)
VCS_PREFIX = re.compile(r"^(git|hg|svn|bzr)\+", re.IGNORECASE)
COMMENT = re.compile(r"(^|\s+)#.*$")
URL_CREDENTIALS = re.compile(r"(?<=://)[^/\s@]*@")
HASH_VALUE = re.compile(r"^(sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96}|sha512:[0-9a-f]{128})$")
ARCHIVE_SUFFIXES = (".whl", ".zip", ".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tbz", ".tar.xz", ".txz")

SHORT_OPTIONS = {
    "-r": "--requirement", "-c": "--constraint", "-e": "--editable", "-i": "--index-url",
    "-f": "--find-links", "-t": "--target", "-C": "--config-settings", "-U": "--upgrade",
    "-I": "--ignore-installed", "-q": "--quiet", "-v": "--verbose", "-h": "--help", "-V": "--version",
}

# Options that take no value and do not change which artifact is installed.
FLAG_OPTIONS = {
    "--upgrade", "--ignore-installed", "--quiet", "--verbose", "--help", "--version", "--user",
    "--no-deps", "--pre", "--force-reinstall", "--no-cache-dir", "--disable-pip-version-check",
    "--no-input", "--require-hashes", "--dry-run", "--no-build-isolation", "--ignore-requires-python",
    "--compile", "--no-compile", "--no-warn-script-location", "--no-warn-conflicts", "--prefer-binary",
    "--break-system-packages", "--isolated", "--no-color", "--no-python-version-warning",
    "--use-pep517", "--no-use-pep517", "--check-build-dependencies", "--no-clean",
    "--require-virtualenv", "--debug",
}

# Options that take a value. `--requirement`, `--constraint` and `--hash` get special handling.
VALUE_OPTIONS = {
    "--requirement", "--constraint", "--hash", "--target", "--config-settings", "--log", "--proxy",
    "--retries", "--timeout", "--exists-action", "--cache-dir", "--cert", "--client-cert", "--root",
    "--prefix", "--src", "--upgrade-strategy", "--progress-bar", "--root-user-action", "--report",
    "--global-option", "--only-binary", "--use-feature", "--use-deprecated", "--python",
    "--keyring-provider", "--platform", "--python-version", "--implementation", "--abi",
}

# Options that make pip take the package from somewhere CAVR does not verify: name -> (takes a value, reason).
UNSUPPORTED_OPTIONS = {
    "--editable": (True, "editable install from a local path or VCS"),
    "--index-url": (True, "custom index"),
    "--extra-index-url": (True, "custom index"),
    "--find-links": (True, "custom index (find-links)"),
    "--trusted-host": (True, "custom index (trusted host)"),
    "--no-index": (False, "custom index (--no-index)"),
    "--no-binary": (True, "source build requested (--no-binary); only wheels are verified"),
}


def parse_pip_command(command, cwd=".") -> dict:
    """Capture one pip command. `command` is a string or a list of tokens; `cwd` is where it ran."""
    record = new_record("pip_command")
    if isinstance(command, str):
        try:
            argv = shlex.split(command)
        except ValueError as exc:
            record["command"] = [redact(command)]
            _note(record, "errors", command, f"cannot split the command: {exc}", "command")
            return _finish(record)
    elif isinstance(command, (list, tuple)):
        argv = [str(token) for token in command]
    else:
        _note(record, "errors", repr(command)[:200], "the command must be a string or a list of tokens", "command")
        return _finish(record)
    record["command"] = [redact(token) for token in argv]

    arguments = _pip_arguments(argv)
    if arguments is None:
        _note(record, "errors", " ".join(argv), "not a pip command", "command")
        return _finish(record)

    items = _split_options(arguments)
    position = next((i for i, item in enumerate(items) if item[0] == "arg"), None)
    if position is not None:
        record["action"] = items[position][2]
        del items[position]
    if record["action"] != "install":
        _note(record, "unsupported", " ".join(argv),
              f"pip {record['action'] or '(no subcommand)'} is not captured, only pip install", "command")
        return _finish(record)

    _apply(record, items, "command", Path(cwd), "requirements", (), Path(cwd).resolve())
    if not (record["requirements"] or record["unsupported"] or record["errors"]):
        _note(record, "errors", " ".join(argv), "no requirement given", "command")
    return _finish(record)


def parse_requirement(text: str, origin: str = "command") -> dict:
    """Classify one requirement string.

    Returns a dict whose `kind` is "requirement", "unsupported" or "error". A requirement has
    name, canonical_name, specifier, version, pinned, extras, marker, hashes, raw and origin.
    `pinned` is True only for exactly one `==` clause without a wildcard; `version` is that
    version as written, otherwise None.
    """
    raw = text.strip()

    def other(kind, reason):
        return {"kind": kind, "raw": redact(raw), "reason": reason, "origin": origin}

    if not raw:
        return other("error", "malformed requirement: empty")
    if VCS_PREFIX.match(raw):
        return other("unsupported", "VCS requirement")
    if "://" in raw:
        return other("unsupported", "direct URL requirement")
    head = raw.split(";")[0].strip()
    if raw.startswith((".", "/", "~")) or "/" in head or "\\" in head or head.lower().endswith(ARCHIVE_SUFFIXES):
        return other("unsupported", "local path requirement")
    try:
        req = Requirement(raw)
    except InvalidRequirement as exc:
        return other("error", "malformed requirement: " + str(exc).splitlines()[0])
    if req.url:
        return other("unsupported", "direct URL requirement")

    clauses = list(req.specifier)
    pinned = len(clauses) == 1 and clauses[0].operator == "==" and not clauses[0].version.endswith(".*")
    return {
        "kind": "requirement",
        "name": req.name,
        "canonical_name": canonicalize_name(req.name),
        "specifier": str(req.specifier),
        "version": clauses[0].version if pinned else None,
        "pinned": pinned,
        "extras": sorted(req.extras),
        "marker": str(req.marker) if req.marker else None,
        "hashes": [],
        "raw": raw,
        "origin": origin,
    }


def parse_requirements_text(text: str, source: str = "requirements.txt") -> list[dict]:
    """Classify every line of a requirements file. Reads no other file.

    Each entry has a `kind`: "requirement", "unsupported" or "error" as in `parse_requirement`,
    "include" for `-r`/`-c` lines (with `path` and `constraint`), or "option" for a recognised
    option line that does not change what is installed. `origin` is "<source>:<line number>".
    """
    entries: list[dict] = []
    for number, line in _logical_lines(text):
        origin = f"{source}:{number}"

        def other(kind, reason):
            return {"kind": kind, "raw": redact(line), "reason": reason, "origin": origin}

        words = line.split()
        first_option = next((i for i, word in enumerate(words) if word.startswith("-")), len(words))
        try:
            items = _split_options(shlex.split(" ".join(words[first_option:])))
        except ValueError as exc:
            entries.append(other("error", f"malformed line: {exc}"))
            continue

        if first_option == 0:
            entries.extend(_option_line_entries(items, line, origin))
            continue

        # A requirement, optionally followed by --hash options.
        entry = parse_requirement(" ".join(words[:first_option]), origin)
        if entry["kind"] == "requirement":
            for kind, name, value, _raw in items:
                if kind != "option" or name != "--hash":
                    entry = other("error", "malformed line: only --hash may follow a requirement")
                    break
                if not HASH_VALUE.match(value):
                    entry = other("error", f"malformed line: bad --hash value {value!r}")
                    break
                entry["hashes"].append(value)
        entries.append(entry)
    return entries


# --- internals ---------------------------------------------------------------

def new_record(source: str) -> dict:
    return {"source": source, "command": [], "action": None, "options": [], "requirements": [],
            "constraints": [], "unsupported": [], "errors": [], "files": [], "complete": False}


def redact(text):
    """`text` with the user and password of every URL in it replaced by `***` (None stays None)."""
    return URL_CREDENTIALS.sub("***@", text) if isinstance(text, str) else text


def _note(record: dict, key: str, raw: str, reason: str, origin: str) -> None:
    record[key].append({"raw": redact(raw), "reason": redact(reason), "origin": origin})


def _finish(record: dict) -> dict:
    """Report conflicting pins, then set `complete`."""
    for error in conflicting_requirements(record["requirements"]):
        record["errors"].append(error)
    record["complete"] = not record["unsupported"] and not record["errors"]
    return record


def conflicting_requirements(requirements: list[dict], fields: tuple = ("specifier",)) -> list[dict]:
    """One error per requirement that is asked for twice with different `fields`.

    Two entries are the same requirement when the canonical name and the marker are equal, so
    `a==1; python_version<"3.8"` next to `a==2; python_version>="3.8"` is not a conflict.
    """
    seen: dict[tuple, dict] = {}
    reported: set[tuple] = set()
    errors: list[dict] = []
    for req in requirements:
        key = (req["canonical_name"], req["marker"])
        first = seen.setdefault(key, req)
        if key not in reported and any(first[field] != req[field] for field in fields):
            reported.add(key)
            errors.append({"raw": f"{first['raw']}, {req['raw']}",
                           "reason": f"conflicting requirements for {req['canonical_name']}",
                           "origin": f"{first['origin']}, {req['origin']}"})
    return errors


def _pip_arguments(argv: list[str]):
    """The tokens after `pip` or `python -m pip`, or None when this is not a pip command."""
    if not argv:
        return None
    program = re.split(r"[\\/]", argv[0])[-1]
    if PIP_PROGRAM.match(program):
        return argv[1:]
    if PYTHON_PROGRAM.match(program):
        for i in range(1, len(argv) - 1):
            if argv[i] == "-m":
                return argv[i + 2:] if argv[i + 1] == "pip" else None
            if not argv[i].startswith("-"):
                return None  # a script or a value came before -m
    return None


def _split_options(tokens: list[str]) -> list[tuple]:
    """Split tokens into (kind, name, value, raw) items.

    kind is "arg" (a positional; value holds it), "option" (name is the long spelling),
    "unknown" (an option not in the tables above) or "missing" (a value option at the end
    with no value). An unknown option is never guessed at: we cannot know whether the next
    token is its value, so the caller records it as unsupported.
    """
    items: list[tuple] = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        i += 1
        if token == "--":
            items.extend(("arg", None, rest, rest) for rest in tokens[i:])
            break
        if not token.startswith("-") or token == "-":
            items.append(("arg", None, token, token))
            continue

        if token.startswith("--"):
            name, equals, attached = token.partition("=")
            attached = attached if equals else None
        else:
            name = SHORT_OPTIONS.get(token[:2], token[:2])
            attached = token[2:] or None
            if attached is not None and not _takes_value(name):
                # A cluster of short flags such as -qU or -vv.
                cluster = [SHORT_OPTIONS.get("-" + letter) for letter in token[1:]]
                if all(long in FLAG_OPTIONS for long in cluster):
                    items.extend(("option", long, None, token) for long in cluster)
                else:
                    items.append(("unknown", token, None, token))
                continue

        if _takes_value(name):
            raw = token
            if attached is None:
                if i >= len(tokens):
                    items.append(("missing", name, None, token))
                    continue
                attached = tokens[i]
                raw = f"{token} {attached}"
                i += 1
            items.append(("option", name, attached, raw))
        elif (name in FLAG_OPTIONS or name in UNSUPPORTED_OPTIONS) and attached is None:
            items.append(("option", name, None, token))
        else:
            items.append(("unknown", token, None, token))
    return items


def _takes_value(name: str) -> bool:
    return name in VALUE_OPTIONS or UNSUPPORTED_OPTIONS.get(name, (False,))[0]


def _apply(record: dict, items: list[tuple], origin: str, base_dir: Path, target: str, stack: tuple, root: Path) -> None:
    """Put command-line items into the record. `target` is "requirements" or "constraints"."""
    for kind, name, value, raw in items:
        if kind == "arg":
            _add(record, parse_requirement(value, origin), target)
        elif kind == "unknown":
            _note(record, "unsupported", raw, "unknown option", origin)
        elif kind == "missing":
            _note(record, "errors", raw, f"option {name} needs a value", origin)
        elif name == "--requirement":
            _read_file(record, base_dir, value, target, origin, raw, stack, root)
        elif name == "--constraint":
            _read_file(record, base_dir, value, "constraints", origin, raw, stack, root)
        elif name == "--hash":
            _note(record, "errors", raw, "--hash is only valid after a requirement in a requirements file", origin)
        elif name in UNSUPPORTED_OPTIONS:
            _note(record, "unsupported", raw, UNSUPPORTED_OPTIONS[name][1], origin)
        else:
            record["options"].append([name, redact(value)])


def _add(record: dict, entry: dict, target: str) -> None:
    """File one classified entry under requirements/constraints, unsupported or errors."""
    kind = entry.pop("kind")
    if kind == "requirement":
        record[target].append(entry)
    elif kind == "unsupported":
        record["unsupported"].append(entry)
    else:
        record["errors"].append(entry)


def _option_line_entries(items: list[tuple], line: str, origin: str) -> list[dict]:
    """Entries for a requirements-file line that starts with an option."""
    entries: list[dict] = []
    for kind, name, value, raw in items:
        raw = redact(raw)
        if kind == "arg":
            return [{"kind": "error", "raw": redact(line), "reason": "malformed line: text after an option", "origin": origin}]
        if kind == "unknown":
            entries.append({"kind": "unsupported", "raw": raw, "reason": "unknown option", "origin": origin})
        elif kind == "missing":
            entries.append({"kind": "error", "raw": raw, "reason": f"option {name} needs a value", "origin": origin})
        elif name in ("--requirement", "--constraint"):
            entries.append({"kind": "include", "path": value, "constraint": name == "--constraint",
                            "raw": raw, "origin": origin})
        elif name == "--hash":
            entries.append({"kind": "error", "raw": raw, "reason": "malformed line: --hash without a requirement",
                            "origin": origin})
        elif name in UNSUPPORTED_OPTIONS:
            entries.append({"kind": "unsupported", "raw": raw, "reason": UNSUPPORTED_OPTIONS[name][1],
                            "origin": origin})
        else:
            entries.append({"kind": "option", "name": name, "value": redact(value), "raw": raw, "origin": origin})
    return entries


def _read_file(record: dict, base_dir: Path, value: str, target: str, origin: str, raw: str, stack: tuple,
               root: Path) -> None:
    """Read the requirements/constraints file `value` (relative to `base_dir`) and everything it includes.

    `stack` holds the files currently being read, so a file that includes itself (directly
    or through another file) is reported once instead of looping forever. `root` is the
    directory the command ran in: a file outside it is not opened, so `-r /some/secret/file`
    cannot copy that file's lines into the record.
    """
    if "://" in value:
        _note(record, "unsupported", raw, "requirements file given as a URL", origin)
        return
    path = (base_dir / value).resolve()
    if path != root and root not in path.parents:
        _note(record, "unsupported", raw, f"requirements file outside the project directory {root}", origin)
        return
    if path in stack:
        _note(record, "errors", raw, f"requirements file includes itself: {path}", origin)
        return
    if len(record["files"]) >= MAX_REQUIREMENTS_FILES:
        _note(record, "errors", raw, f"more than {MAX_REQUIREMENTS_FILES} requirements files in one command", origin)
        return
    data, text, problem = read_requirements_bytes(path)
    if problem:
        _note(record, "errors", raw, problem, origin)
        return

    record["files"].append({"path": str(path), "role": target, "sha256": hashlib.sha256(data).hexdigest(),
                            "included_from": origin})
    for entry in parse_requirements_text(text, str(path)):
        if entry["kind"] == "include":
            nested_target = "constraints" if entry["constraint"] else target
            _read_file(record, path.parent, entry["path"], nested_target, entry["origin"], entry["raw"],
                       stack + (path,), root)
        elif entry["kind"] == "option":
            record["options"].append([entry["name"], entry["value"]])
        else:
            _add(record, entry, target)


def read_requirements_bytes(path: Path):
    """Read a requirements file. Returns (bytes, text, None), or (None, None, reason) if it cannot be used."""
    path = Path(path)
    if path.exists() and not path.is_file():
        # A directory, FIFO or device: opening a FIFO would wait for a writer forever.
        return None, None, f"cannot read {path}: not a regular file"
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_REQUIREMENTS_FILE_BYTES + 1)
    except OSError as exc:
        return None, None, f"cannot read {path}: {exc.strerror or exc}"
    if len(data) > MAX_REQUIREMENTS_FILE_BYTES:
        return None, None, f"{path} is larger than {MAX_REQUIREMENTS_FILE_BYTES} bytes"
    try:
        return data, data.decode("utf-8-sig"), None
    except UnicodeDecodeError:
        return None, None, f"{path} is not UTF-8 text"


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """(line number, text) pairs: backslash continuations joined, comments and blank lines dropped."""
    lines: list[tuple[int, str]] = []
    buffer, start = "", None
    for number, physical in enumerate(text.splitlines() + [""], 1):
        if start is None:
            start = number
        if physical.endswith("\\"):
            buffer += physical[:-1]
            continue
        cleaned = COMMENT.sub("", buffer + physical).strip()
        if cleaned:
            lines.append((start, cleaned))
        buffer, start = "", None
    return lines
