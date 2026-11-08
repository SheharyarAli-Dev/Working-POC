"""Per-project SATRA sandbox images for gate runs.

A gate run executes the project's trusted tests inside an image that holds the SATRA runner base
(docker/satra-runner.Dockerfile: CPython 3.12 + pytest) plus exactly the CAVR-approved wheels of
the BASE commit's dependencies.lock.json. The image is built with network access; the tests then
run in it with --network none, exactly like every other SATRA pytest run.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace

from packaging.utils import InvalidWheelFilename, canonicalize_name, parse_wheel_filename
from packaging.version import InvalidVersion, Version

from backend.cavr.capture import read_requirements_bytes
from backend.cavr.gate_adapter import _unsupported as unsupported_manifests
from backend.cavr.manifest_parser import read_manifest
from backend.cavr.pipeline import LOCKFILE_NAME
from backend.cavr.requirement_gate import evaluate_requirement, lockfile_problems
from backend.config import ROOT
from backend.orchestrator.hashing import files as project_files

RUNNER_IMAGE = "asent-satra-runner:local"
RUNNER_REQUIREMENTS = ROOT / "docker/satra-runner.requirements.txt"
PROJECT_REPOSITORY = "asent-satra-project"
# Bump when the generated Dockerfile or requirements format changes: images built by older code
# then get a different key and are never reused.
BUILDER_VERSION = "1"
LABEL_PREFIX = "org.asent.satra."
LABEL_KEY = LABEL_PREFIX + "key"
BUILD_TIMEOUT = 900
PROBE_TIMEOUT = 60
PIP_FLAGS = "--no-cache-dir --disable-pip-version-check --require-hashes --no-deps --only-binary :all:"
PROBE = ("import json, platform; from packaging import tags; "
         "print(json.dumps({'python': platform.python_version(), 'tags': [str(t) for t in tags.sys_tags()]}))")

NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RUNNER_LINE = re.compile(r"^(?P<name>\S+)==(?P<version>\S+) --hash=sha256:(?P<sha>[0-9a-f]{64})$")


def runner_pins(path=RUNNER_REQUIREMENTS) -> dict:
    """{canonical name: {"name", "version", "hashes"}} of the runner base, read from its requirements file.

    Every non-comment line must be `name==version --hash=sha256:<64 hex>`; anything else raises
    ValueError, so a runner that is not fully hash-pinned can never be used.
    """
    pins = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        match = _RUNNER_LINE.match(line.strip())
        if not match or not NAME.match(match["name"]):
            raise ValueError(f"runner requirement is not one exact, hash-pinned wheel: {line!r}")
        try:
            version = str(Version(match["version"]))
        except InvalidVersion:
            raise ValueError(f"runner requirement has an invalid version: {line!r}") from None
        entry = pins.setdefault(canonicalize_name(match["name"]), {"name": match["name"], "version": version, "hashes": []})
        if entry["version"] != version:
            raise ValueError(f"runner pins {match['name']} twice at different versions")
        entry["hashes"].append(match["sha"])
    return pins


def _refuse(reason, **fields):
    return {"status": "INCONCLUSIVE", "reason": reason, "requirements_text": None, "lockfile_sha256": None,
            "packages": [], "provided_by_runner": [], "decisions": [], **fields}


def _wheel_name(entry):
    """The wheel filename of a lock entry: `filename`, else the last part of `artifact`."""
    name = entry.get("filename")
    if name is None and isinstance(entry.get("artifact"), str):
        name = entry["artifact"].replace("\\", "/").rsplit("/", 1)[-1]
    return name if isinstance(name, str) else None


def _entry_problem(entry):
    """Why a lockfile entry cannot be installed by hash as a wheel, or None."""
    shown = f"{entry.get('name')!r} {entry.get('version')!r}"
    if str(entry.get("ecosystem", "")).lower() != "pypi":
        return f"lockfile entry {shown} is not a PyPI package (ecosystem {entry.get('ecosystem')!r})"
    if not isinstance(entry.get("name"), str) or not NAME.match(entry["name"]):
        return f"lockfile entry has an invalid name: {entry.get('name')!r}"
    try:
        Version(entry["version"])
    except (InvalidVersion, TypeError, KeyError):
        return f"lockfile entry {shown} has an invalid version"
    if not isinstance(entry.get("sha256"), str) or not SHA256.match(entry["sha256"]):
        return f"lockfile entry {shown} has no sha256 of 64 lowercase hex digits"
    wheel = _wheel_name(entry)
    if wheel is None or not wheel.endswith(".whl"):
        return f"lockfile entry {shown} names no wheel file ({wheel!r}); only wheels are installed"
    try:
        wheel_name, wheel_version, _, _ = parse_wheel_filename(wheel)
    except (InvalidWheelFilename, InvalidVersion):
        return f"lockfile entry {shown} names an invalid wheel file {wheel!r}"
    if wheel_name != canonicalize_name(entry["name"]) or wheel_version != Version(entry["version"]):
        return f"lockfile entry {shown}: wheel file {wheel!r} does not match its name and version"
    return None


def install_plan(base_dir, config, supported_tags) -> dict:
    """What a gate image for this base commit installs, or why there can be no image.

    `base_dir` is the exported BASE commit, `config` the frozen base `.asent/` (ConfigResult) and
    `supported_tags` the wheel tags the runner's interpreter accepts (strings, from
    `packaging.tags.sys_tags()` inside the runner). Nothing is read from the head commit.

    READY only when every requirement in the base requirements files and every lockfile entry is
    PERMITTED by CAVR's requirement gate, every entry is a hash-pinned PyPI wheel, no package
    clashes with the runner, and every package has a wheel the runner can install. Otherwise
    INCONCLUSIVE with the reason. `requirements_text` is written here line by line from validated
    fields (`name==version --hash=sha256:...`), never copied from the lockfile.
    """
    base_dir = Path(base_dir)
    cavr = config.module("CAVR") if config is not None and config.valid else None
    policy = config.documents.get("cavr_policy") if cavr is not None and cavr.enabled else None
    if cavr is None or not cavr.enabled or policy is None:
        return _refuse("CAVR is not enabled with a usable policy in the base .asent/ config, so no dependency is approved")

    names = set(project_files(base_dir))
    view = SimpleNamespace(manifest=names, read=lambda p: (base_dir / p).read_text(encoding="utf-8"))
    unsupported = unsupported_manifests(view)
    if unsupported:
        return _refuse("dependency manifest CAVR cannot verify in the base commit: " + ", ".join(unsupported))

    lock_path = base_dir / LOCKFILE_NAME
    if LOCKFILE_NAME not in names or not lock_path.is_file():
        return _refuse(f"no {LOCKFILE_NAME} in the base commit; SATRA installs only locked, CAVR-approved wheels")
    raw = lock_path.read_bytes()
    lock_sha = hashlib.sha256(raw).hexdigest()
    try:
        lockfile = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        return _refuse(f"{LOCKFILE_NAME} in the base commit is not UTF-8 JSON: {exc}", lockfile_sha256=lock_sha)
    problems = lockfile_problems(lockfile)
    if problems:
        return _refuse(f"{LOCKFILE_NAME} in the base commit is not usable: {problems[0]}", lockfile_sha256=lock_sha)

    groups = {}
    for entry in lockfile["packages"]:
        problem = _entry_problem(entry)
        if problem:
            return _refuse(problem, lockfile_sha256=lock_sha)
        key = canonicalize_name(entry["name"])
        version = str(Version(entry["version"]))
        group = groups.setdefault(key, {"name": key, "version": version, "hashes": set(), "wheels": set()})
        if group["version"] != version:
            return _refuse(f"{LOCKFILE_NAME} locks two versions of {key} ({group['version']}, {version})",
                           lockfile_sha256=lock_sha)
        group["hashes"].add(entry["sha256"])
        group["wheels"].add(_wheel_name(entry))

    decisions = []

    def permitted(requirement, origin):
        decision = evaluate_requirement(requirement, policy, lockfile)
        decisions.append({"origin": origin, "requested": decision.get("requested"), "result": decision["result"],
                          "rule": decision["rule"], "reason": decision["reason"]})
        return decision["result"] == "PERMITTED"

    for name in cavr.requirements_files:
        if name not in names:
            return _refuse(f"configured requirements file {name} is not in the base commit", lockfile_sha256=lock_sha)
        _, text, problem = read_requirements_bytes(base_dir / name)
        if problem:
            return _refuse(f"{name}: {problem}", lockfile_sha256=lock_sha)
        manifest = read_manifest(text, name)
        odd = manifest["options"] + manifest["unsupported"] + manifest["errors"]
        if odd:
            return _refuse(f"{name} in the base commit has an option or line SATRA does not install from: {odd[0]!r}",
                           lockfile_sha256=lock_sha)
        for requirement in manifest["requirements"]:
            if not permitted(requirement, name):
                last = decisions[-1]
                return _refuse(f"{name}: {last['requested']} is not permitted by CAVR ({last['rule']}: {last['reason']})",
                               lockfile_sha256=lock_sha, decisions=decisions)

    for key in sorted(groups):
        if not permitted(f"{key}=={groups[key]['version']}", LOCKFILE_NAME):
            last = decisions[-1]
            return _refuse(f"{LOCKFILE_NAME}: {key}=={groups[key]['version']} is not permitted by CAVR "
                           f"({last['rule']}: {last['reason']})", lockfile_sha256=lock_sha, decisions=decisions)

    runner, provided = runner_pins(), []
    for key in sorted(set(groups) & set(runner)):
        pin, group = runner[key], groups.pop(key)
        if group["version"] != pin["version"]:
            return _refuse(f"{LOCKFILE_NAME} pins {key}=={group['version']} but the SATRA runner needs {key}=={pin['version']} "
                           "for pytest; one environment cannot hold both", lockfile_sha256=lock_sha, decisions=decisions)
        if not group["hashes"] & set(pin["hashes"]):
            return _refuse(f"{LOCKFILE_NAME} pins {key}=={group['version']} with a different file than the SATRA runner's wheel "
                           f"(runner sha256 {pin['hashes'][0]})", lockfile_sha256=lock_sha, decisions=decisions)
        provided.append({"name": key, "version": group["version"]})

    supported = frozenset(supported_tags or ())
    if not supported:
        return _refuse("the runner's supported wheel tags are unknown, so wheel compatibility cannot be checked",
                       lockfile_sha256=lock_sha, decisions=decisions)
    for key in sorted(groups):
        group = groups[key]
        if not any({str(t) for t in parse_wheel_filename(w)[3]} & supported for w in group["wheels"]):
            return _refuse(f"{key}=={group['version']}: no wheel in {LOCKFILE_NAME} fits the runner's Python and platform "
                           f"({', '.join(sorted(group['wheels']))})", lockfile_sha256=lock_sha, decisions=decisions)

    lines = [f"{key}=={groups[key]['version']} " + " ".join(f"--hash=sha256:{h}" for h in sorted(groups[key]["hashes"]))
             for key in sorted(groups)]
    packages = [{"name": key, "version": groups[key]["version"], "sha256": sorted(groups[key]["hashes"])} for key in sorted(groups)]
    return {"status": "READY", "reason": f"{len(packages)} CAVR-approved wheel(s) from the base {LOCKFILE_NAME}",
            "requirements_text": "".join(line + "\n" for line in lines), "lockfile_sha256": lock_sha, "packages": packages,
            "provided_by_runner": provided, "decisions": decisions}


# --- build or reuse -------------------------------------------------------------------------------

def _run(cmd, timeout):
    """The only place this module runs the container engine (tests replace it)."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def image_key(lockfile_sha256, runner_id, python_version, requirements_text) -> str:
    """Content address of a gate image: base lockfile bytes, runner image ID, runner Python version,
    plus the generated requirements and BUILDER_VERSION (both derived, included so that a change in
    this code can never reuse an image built from different instructions)."""
    material = {"builder": BUILDER_VERSION, "lockfile_sha256": lockfile_sha256, "runner_image_id": runner_id,
                "python": python_version, "requirements_sha256": hashlib.sha256(requirements_text.encode()).hexdigest()}
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


def _inspect(engine, image):
    try:
        done = _run([engine, "image", "inspect", image], PROBE_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    try:
        found = json.loads(done.stdout)
    except ValueError:
        return None
    return found[0] if isinstance(found, list) and found and isinstance(found[0], dict) else None


def _labels(info):
    return ((info or {}).get("Config") or {}).get("Labels") or {}


def _layers(info):
    return ((info or {}).get("RootFS") or {}).get("Layers") or []


def runner_identity(engine):
    """({"image_id", "layers", "python", "tags"}, None) of the local runner image, or (None, reason).

    The Python version and wheel tags come from the runner's own interpreter, run with no network."""
    info = _inspect(engine, RUNNER_IMAGE)
    if info is None or not isinstance(info.get("Id"), str):
        return None, f"SATRA runner image {RUNNER_IMAGE} is not available; build it with scripts/satra_build_sandbox.sh"
    try:
        done = _run([engine, "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                     "--security-opt", "no-new-privileges", RUNNER_IMAGE, "python", "-c", PROBE], PROBE_TIMEOUT)
        probe = json.loads(done.stdout) if done.returncode == 0 else None
    except (OSError, subprocess.SubprocessError, ValueError):
        probe = None
    if not (isinstance(probe, dict) and isinstance(probe.get("python"), str) and isinstance(probe.get("tags"), list)
            and probe["tags"] and all(isinstance(t, str) for t in probe["tags"])):
        return None, f"SATRA runner image {RUNNER_IMAGE} did not report its Python version and wheel tags"
    return {"image_id": info["Id"], "layers": _layers(info), "python": probe["python"], "tags": probe["tags"]}, None


def _dockerfile(requirements_text):
    lines = [f"FROM {RUNNER_IMAGE}"]
    if requirements_text:
        lines += ["COPY requirements.txt /opt/asent/project-requirements.txt",
                  f"RUN python -m pip install {PIP_FLAGS} -r /opt/asent/project-requirements.txt"]
    return "\n".join(lines) + "\n"


def prepare(base_dir, config, engine) -> dict:
    """The gate image for this base commit: reused when an image with the same key label exists,
    otherwise built FROM the runner with the install plan's requirements. INCONCLUSIVE when the runner
    is missing, the plan refuses, the build fails or times out, or the result is not what was asked for.

    Only the build has network access (the engine's default build network); nothing of the project
    is in the build context, which holds exactly a Dockerfile and requirements.txt."""
    identity, problem = runner_identity(engine)
    if identity is None:
        return _refuse(problem)
    plan = install_plan(base_dir, config, identity["tags"])
    runner = {"image": RUNNER_IMAGE, "image_id": identity["image_id"], "python": identity["python"]}
    if plan["status"] != "READY":
        return {**plan, "runner": runner}
    text = plan["requirements_text"]
    key = image_key(plan["lockfile_sha256"], identity["image_id"], identity["python"], text)
    tag = f"{PROJECT_REPOSITORY}:{key}"
    labels = {LABEL_KEY: key, LABEL_PREFIX + "lockfile_sha256": plan["lockfile_sha256"],
              LABEL_PREFIX + "runner_image_id": identity["image_id"], LABEL_PREFIX + "python": identity["python"],
              LABEL_PREFIX + "builder": BUILDER_VERSION}
    evidence = {**plan, "runner": runner, "key": key, "image": tag, "labels": labels,
                "requirements_sha256": hashlib.sha256(text.encode()).hexdigest()}

    def built_right(info):
        found = _labels(info)
        layers = _layers(info)
        return (all(found.get(name) == value for name, value in labels.items())
                and layers[:len(identity["layers"])] == identity["layers"] and len(identity["layers"]) > 0)

    existing = _inspect(engine, tag)
    if existing is not None and built_right(existing):
        return {**evidence, "reused": True, "reason": plan["reason"] + "; cached image reused (key label matches)"}

    with tempfile.TemporaryDirectory(prefix="asent-satra-image-") as context:
        context = Path(context)
        (context / "Dockerfile").write_text(_dockerfile(text), encoding="utf-8")
        (context / "requirements.txt").write_text(text, encoding="utf-8")
        cmd = [engine, "build", "-t", tag]
        for name, value in labels.items():
            cmd += ["--label", f"{name}={value}"]
        cmd += ["-f", str(context / "Dockerfile"), str(context)]
        try:
            done = _run(cmd, BUILD_TIMEOUT)
        except subprocess.TimeoutExpired:
            return {**evidence, "status": "INCONCLUSIVE", "requirements_text": None, "reused": False,
                    "reason": f"gate image build timed out after {BUILD_TIMEOUT} s", "build_log_tail": ""}
        except OSError as exc:
            return {**evidence, "status": "INCONCLUSIVE", "requirements_text": None, "reused": False,
                    "reason": f"gate image build could not start: {exc}", "build_log_tail": ""}
    tail = ((done.stdout or "") + (done.stderr or ""))[-4000:]
    if done.returncode != 0:
        return {**evidence, "status": "INCONCLUSIVE", "requirements_text": None, "reused": False, "build_log_tail": tail,
                "reason": f"gate image build failed (exit {done.returncode}); pip refuses wheels that are missing, "
                          "do not fit this Python/platform, or do not match the lockfile hashes"}
    if not built_right(_inspect(engine, tag)):
        return {**evidence, "status": "INCONCLUSIVE", "requirements_text": None, "reused": False, "build_log_tail": tail,
                "reason": "built gate image does not carry the expected labels on top of the SATRA runner layers"}
    return {**evidence, "reused": False, "build_log_tail": tail, "reason": plan["reason"] + "; image built"}
