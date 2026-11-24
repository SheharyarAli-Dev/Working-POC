"""Run specs for the trigger frontier, with per-run canaries (PR 11 of docs/cavr-m2-plan.md). Pure; fail closed.

`synthesize(entry)` turns a frontier entry's activation (`trigger_frontier`) into one run spec; `canary_spec()` is the
spec with canaries and no trigger (the run every trigger run is compared with). A spec says what the imports step of
one sandbox run sees:

    env         the trigger's variables and the canary variables (the imports step only; the install step gets none)
    faketime    a clock for libfaketime (Q7): `LD_PRELOAD` + `FAKETIME="@YYYY-MM-DD hh:mm:ss"`, with
                FAKETIME_DONT_FAKE_MONOTONIC=1 and FAKETIME_DISABLE_SHM=1 (measured 2026-11-23: without it libfaketime
                creates a POSIX semaphore in /dev/shm, FILE_WRITE events the package did not cause). No capability and
                no seccomp change is needed (measured: the clock reads the spec's time, only code loads are added).
    files       files and directories under the sandbox HOME (/tmp/home), written by `sandbox_spec` to a host
                directory that is mounted read-only there
    hostname    `docker run --hostname`
    argv        `sys.argv` of the imports step (default ["-c"], what `python -c` has)
    canaries    every canary of the run: {id, kind (file / env), where (path / variable), value}

Canaries (sandbox rule 7): in every spec, each with a new random value (`secrets`): ~/.aws/credentials (key id and
secret), ~/.env (API_KEY), ~/.netrc (password), ~/.ssh/id_ed25519 (key body), and the variables AWS_ACCESS_KEY_ID,
AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, PYPI_TOKEN. A file a trigger needs gets a canary as its content. A trigger that
sets a canary variable wins: that variable is then not a canary (the package knows its value).

`canary_forms(value)` are the (kind, bytes) pairs the event normaliser looks for: the value ("verbatim"), its hex
("hex", lower and upper) and its base64 at each of the three alignments ("base64", only whole groups that depend on the
value alone).

Refused (no spec, the entry stays residual): an unsimulable entry; a variable the sandbox fixes (PATH, HOME, LANG,
TMPDIR, PYTHON*, LD_*, FAKETIME*, PIP_*); a file outside HOME or on a canary path; an invalid hostname; a clock
outside 1971-2099; a NUL in any value.
"""
from __future__ import annotations

import base64
import datetime as dt
import platform
import posixpath
import re
import secrets as _secrets

from backend.cavr.sandbox_exec import HOSTNAME
from backend.cavr.trigger_frontier import CANARY_ENV_SHAPES, CANARY_FILES, HOME, RESERVED_ENV, SANDBOX

VERSION = "cavr-env-synthesis/1"
DEFAULT_HOSTNAME = SANDBOX["hostname"]
DEFAULT_ARGV = list(SANDBOX["argv"])
LIBFAKETIME = {"x86_64": "/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1",
               "aarch64": "/usr/lib/aarch64-linux-gnu/faketime/libfaketime.so.1"}
FAKETIME_FIXED = {"FAKETIME_DONT_FAKE_MONOTONIC": "1", "FAKETIME_DISABLE_SHM": "1"}
CANARY_ENV = tuple(CANARY_ENV_SHAPES)  # the frontier's baseline has the same names, in the same shapes (tested)
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
MIN_FORM = 12  # a base64 form shorter than this is not looked for


def _hex(rng, n):
    return rng.token_hex(n)


def canaries(rng=_secrets):
    """(files {path: {kind, content, canaries}}, env {var: value}, registry [{id, kind, where, value}])."""
    access, secret = "AKIA" + _hex(rng, 8).upper(), _hex(rng, 20)
    api, password, body = _hex(rng, 16), _hex(rng, 16), _hex(rng, 32)
    aws, env_file, netrc, ssh = CANARY_FILES
    files = {
        aws: {"kind": "file", "canaries": ["file:aws-access-key", "file:aws-secret-key"],
              "content": f"[default]\naws_access_key_id = {access}\naws_secret_access_key = {secret}\n"},
        env_file: {"kind": "file", "canaries": ["file:env-api-key"], "content": f"API_KEY={api}\n"},
        netrc: {"kind": "file", "canaries": ["file:netrc-password"],
                "content": f"machine pypi.cavr.invalid login cavr password {password}\n"},
        ssh: {"kind": "file", "canaries": ["file:ssh-key"],
              "content": f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n"},
    }
    registry = [{"id": "file:aws-access-key", "kind": "file", "where": aws, "value": access},
                {"id": "file:aws-secret-key", "kind": "file", "where": aws, "value": secret},
                {"id": "file:env-api-key", "kind": "file", "where": env_file, "value": api},
                {"id": "file:netrc-password", "kind": "file", "where": netrc, "value": password},
                {"id": "file:ssh-key", "kind": "file", "where": ssh, "value": body}]
    env = {"AWS_ACCESS_KEY_ID": "AKIA" + _hex(rng, 8).upper(), "AWS_SECRET_ACCESS_KEY": _hex(rng, 20),
           "GITHUB_TOKEN": "ghp_" + _hex(rng, 18), "PYPI_TOKEN": "pypi-" + _hex(rng, 16)}
    registry += [{"id": f"env:{name}", "kind": "env", "where": name, "value": value} for name, value in env.items()]
    return files, env, registry


def canary_spec(rng=_secrets) -> dict:
    files, env, registry = canaries(rng)
    return _spec("spec-canaries", None, None, files, env, registry, None, DEFAULT_HOSTNAME, DEFAULT_ARGV)


def synthesize(entry, rng=_secrets) -> dict:
    """{ok: True, spec} or {ok: False, rule, reason}. Never raises."""
    try:
        return _synthesize(entry, rng)
    except Exception as exc:
        return _refused("SPEC_REFUSED", f"the spec cannot be built: {type(exc).__name__}: {exc}")


def _synthesize(entry, rng):
    if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
        return _refused("SPEC_REFUSED", "not a frontier entry")
    if entry.get("simulable") is not True or not isinstance(entry.get("activation"), dict):
        return _refused("TRIGGER_UNSIMULABLE", f"the trigger cannot be simulated: {entry.get('unsimulable_reason')}")
    activation = entry["activation"]
    files, env, registry = canaries(rng)
    for name, value in (activation.get("env") or {}).items():
        if not (isinstance(name, str) and ENV_NAME.fullmatch(name)) or RESERVED_ENV.match(name):
            return _refused("SPEC_REFUSED", f"the variable {name!r} is fixed by the sandbox and cannot be set")
        if not isinstance(value, str) or "\0" in value:
            return _refused("SPEC_REFUSED", f"the value of {name} cannot be passed")
        if name in env:  # the trigger's value wins; the package knows it, so it is no canary any more
            registry = [item for item in registry if item["id"] != f"env:{name}"]
        env[name] = value
    for path, kind in (activation.get("files") or {}).items():
        normal = posixpath.normpath(path) if isinstance(path, str) else ""
        if normal != path or not normal.startswith(HOME + "/") or kind not in ("file", "dir"):
            return _refused("SPEC_REFUSED", f"{path!r} is not a file or directory CAVR can create under {HOME}")
        if normal in files:  # a canary file: already there as a file, cannot also be a directory
            if kind == "file":
                continue
            return _refused("SPEC_REFUSED", f"{path} is a canary file, not a directory")
        if any(other.startswith(normal + "/") for other in files):  # a parent of a canary file: already a directory
            if kind == "dir":
                continue
            return _refused("SPEC_REFUSED", f"{path} is a directory of the canary files, not a file")
        if any(normal.startswith(other + "/") for other in files):
            return _refused("SPEC_REFUSED", f"{path} would be inside the canary file {next(o for o in files if normal.startswith(o + '/'))}")
        if kind == "dir":
            files[normal] = {"kind": "dir", "canaries": [], "content": None}
        else:
            value = _hex(rng, 16)
            ident = f"file:trigger:{normal[len(HOME) + 1:]}"
            files[normal] = {"kind": "file", "canaries": [ident], "content": f"cavr-canary {value}\n"}
            registry.append({"id": ident, "kind": "file", "where": normal, "value": value})
    clock = activation.get("time")
    if clock is not None:
        try:
            moment = dt.datetime.fromisoformat(clock)
        except (TypeError, ValueError):
            return _refused("SPEC_REFUSED", f"{clock!r} is not a time")
        if not dt.datetime(1971, 1, 1) <= moment.replace(tzinfo=None) < dt.datetime(2100, 1, 1):
            return _refused("SPEC_REFUSED", f"{clock} is outside the clock libfaketime is given (1971-2099)")
        clock = moment.replace(tzinfo=None, microsecond=0).isoformat(sep=" ")
    hostname = activation.get("hostname") or DEFAULT_HOSTNAME
    if not (isinstance(hostname, str) and HOSTNAME.fullmatch(hostname)):
        return _refused("SPEC_REFUSED", f"{hostname!r} is not a valid hostname")
    argv = activation.get("argv") or DEFAULT_ARGV
    if not (isinstance(argv, list) and argv and all(isinstance(a, str) and "\0" not in a for a in argv)):
        return _refused("SPEC_REFUSED", "argv cannot be passed")
    spec = _spec(f"spec-{entry['id']}", entry["id"], activation, files, env, registry, clock, hostname, list(argv))
    return {"ok": True, "rule": "SPEC_BUILT", "reason": f"a run spec for trigger {entry['id']}", "spec": spec}


def _spec(ident, entry_id, activation, files, env, registry, clock, hostname, argv) -> dict:
    return {"version": VERSION, "id": ident, "entry_id": entry_id, "activation": activation,
            "env": dict(sorted(env.items())), "faketime": clock, "files": dict(sorted(files.items())),
            "hostname": hostname, "argv": argv, "canaries": registry}


def _refused(rule, reason) -> dict:
    return {"ok": False, "rule": rule, "reason": reason, "spec": None}


def step_env(spec, machine=None) -> dict:
    """The imports step's variables: the spec's env, and libfaketime's when the spec has a clock."""
    env = dict(spec.get("env") or {})
    if spec.get("faketime"):
        machine = machine or platform.machine()
        if machine not in LIBFAKETIME:
            raise ValueError(f"no libfaketime path for {machine}")
        env.update({"LD_PRELOAD": LIBFAKETIME[machine], "FAKETIME": "@" + spec["faketime"], **FAKETIME_FIXED})
    return env


def canary_forms(value: str) -> list[tuple[str, bytes]]:
    """(kind, bytes) pairs that show the canary: verbatim, hex, and base64 at the three alignments; no form twice."""
    raw = value.encode()
    forms = [("verbatim", raw), ("hex", raw.hex().encode()), ("hex", raw.hex().upper().encode())]
    for shift in range(3):
        encoded = base64.b64encode(b"\0" * shift + raw)
        start = (0, 2, 3)[shift]  # characters that depend on the padding bytes
        end = ((shift + len(raw)) // 3) * 4  # only whole groups: a partial one depends on what follows
        form = encoded[start:end]
        if len(form) >= MIN_FORM:
            forms.append(("base64", form))
    seen, out = set(), []
    for kind, form in forms:  # the hex of digits has no letters: its upper and lower forms are the same bytes
        if form not in seen:
            seen.add(form)
            out.append((kind, form))
    return out
