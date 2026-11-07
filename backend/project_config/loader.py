"""Load and check a project's `.asent/` folder. Every outcome is a `ConfigResult`; nothing raises.

`load(asent_dir)` answers one question: may this folder be used as the authority for a gate
decision? It may only when `valid` is true. Otherwise `problems` names every reason, each as
"<CODE>: <detail>", and the gate's decision is REVIEW (fail closed).

    ASENT_CONFIG_MISSING        no .asent/ directory, or no config.json in it
    ASENT_CONFIG_UNSAFE         .asent/ or anything in it is a symlink or not a regular file
    ASENT_CONFIG_BUDGET         more than 200 files or more than 1 MiB in .asent/
    ASENT_CONFIG_JSON           config.json is not UTF-8 JSON, or repeats a key
    ASENT_CONFIG_SCHEMA         config.json does not match schema.AsentConfig
    ASENT_CONFIG_STARTER        "_starter": true, an `asent init` output nobody has reviewed
    ASENT_CONFIG_FILE_MISSING   an enabled module names a file or directory that is not there
    ASENT_CONFIG_POLICY         CAVR policy unreadable or refused by requirement_gate / capability_contract
    ASENT_CONFIG_CONTRACT       SATRA contract does not match schema.SatraContract
    ASENT_CONFIG_OBLIGATIONS    SABLE obligations do not match schema.SableObligations

A module without a section is not a problem here: whether it applies depends on the project's
files, which the gate checks later. A disabled module's files are not read.

`digest` is the SHA-256 of {relative path: SHA-256 of the raw bytes} over every file in the
folder. It is computed even for an invalid config (so the gate can tell whether head changed
`.asent/`), and is None only when the folder is missing, unsafe or over budget.
"""
from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from backend.cavr.capability_contract import capability_policy_problem
from backend.cavr.requirement_gate import policy_problems
from backend.orchestrator.hashing import digest as canonical_digest
from backend.project_config.schema import MODULE_NAMES, AsentConfig, SableObligations, SatraContract

MAX_FILES = 200
MAX_BYTES = 1024 * 1024
CONFIG_NAME = "config.json"


@dataclass(frozen=True)
class ConfigResult:
    path: str
    valid: bool
    problems: tuple = ()
    config: AsentConfig | None = None
    digest: str | None = None
    files: dict = field(default_factory=dict)       # relative path -> sha256 of the raw bytes
    documents: dict = field(default_factory=dict)   # parsed module documents of enabled modules

    def module(self, name: str):
        return getattr(self.config.modules, name) if self.config is not None else None

    def module_state(self, name: str) -> str:
        """"enabled", "disabled" or "absent" (no section, or no usable config at all)."""
        section = self.module(name)
        return "absent" if section is None else "enabled" if section.enabled else "disabled"

    def disabled_reason(self, name: str):
        section = self.module(name)
        return section.reason if section is not None and not section.enabled else None


class _JsonError(ValueError):
    pass


def _no_duplicates(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise _JsonError(f"key {key!r} appears more than once")
        seen[key] = value
    return seen


def _parse_json(raw: bytes):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except UnicodeDecodeError as exc:
        raise _JsonError(f"not UTF-8: {exc}") from exc
    except RecursionError as exc:
        raise _JsonError("JSON nested too deeply") from exc
    except _JsonError:
        raise
    except ValueError as exc:
        raise _JsonError(f"not JSON: {exc}") from exc


def _schema_problems(code: str, label: str, exc: ValidationError) -> list[str]:
    out = []
    for error in exc.errors():
        where = ".".join(str(part) for part in error["loc"]) or "(document)"
        out.append(f"{code}: {label}: {where}: {error['msg']}")
    return out


def _scan(root: Path):
    """({relative path: sha256}, problems). Never follows a symlink and never reads past the budget."""
    if root.is_symlink():
        return None, [f"ASENT_CONFIG_UNSAFE: {root.name} is a symlink"]
    if not root.is_dir():
        return None, [f"ASENT_CONFIG_MISSING: no {root.name}/ directory at {root}"]
    found, problems, total = {}, [], 0
    for base, dirs, names in os.walk(root, followlinks=False):
        base_path = Path(base)
        for name in sorted(dirs):
            if (base_path / name).is_symlink():
                problems.append(f"ASENT_CONFIG_UNSAFE: {(base_path / name).relative_to(root).as_posix()} is a symlinked directory")
        dirs[:] = sorted(d for d in dirs if not (base_path / d).is_symlink())
        for name in sorted(names):
            path = base_path / name
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                problems.append(f"ASENT_CONFIG_UNSAFE: {relative} is a symlink")
                continue
            if not stat.S_ISREG(info.st_mode):
                problems.append(f"ASENT_CONFIG_UNSAFE: {relative} is not a regular file")
                continue
            total += info.st_size
            if len(found) >= MAX_FILES or total > MAX_BYTES:
                return None, problems + [f"ASENT_CONFIG_BUDGET: more than {MAX_FILES} files or {MAX_BYTES} bytes in {root.name}/"]
            found[relative] = canonical_digest(path.read_bytes())
    if problems:
        return None, problems
    return found, []


def tree_digest(asent_dir) -> str | None:
    """Digest of the folder's files, or None when it is missing, unsafe or over budget."""
    files, problems = _scan(Path(asent_dir))
    return None if problems else canonical_digest({"files": files})


def load(asent_dir) -> ConfigResult:
    root = Path(asent_dir)
    files, problems = _scan(root)
    if problems:
        return ConfigResult(path=str(root), valid=False, problems=tuple(problems))
    tree = canonical_digest({"files": files})

    def done(problems, config=None, documents=None):
        return ConfigResult(path=str(root), valid=not problems, problems=tuple(problems), config=config,
                            digest=tree, files=files, documents=documents or {})

    if CONFIG_NAME not in files:
        return done([f"ASENT_CONFIG_MISSING: no {CONFIG_NAME} in {root.name}/"])
    try:
        raw = _parse_json((root / CONFIG_NAME).read_bytes())
    except _JsonError as exc:
        return done([f"ASENT_CONFIG_JSON: {CONFIG_NAME}: {exc}"])
    try:
        config = AsentConfig.model_validate(raw)
    except ValidationError as exc:
        return done(_schema_problems("ASENT_CONFIG_SCHEMA", CONFIG_NAME, exc))

    problems, documents = [], {}
    if config.starter:
        problems.append('ASENT_CONFIG_STARTER: written by `asent init` and not reviewed; '
                        'review every file in .asent/, then remove "_starter"')

    def read(relative: str, code: str):
        """Parsed JSON of an .asent/ file, or None after recording why it cannot be used."""
        if relative not in files:
            problems.append(f"ASENT_CONFIG_FILE_MISSING: {relative} is named in {CONFIG_NAME} but is not in .asent/")
            return None
        try:
            return _parse_json((root / relative).read_bytes())
        except _JsonError as exc:
            problems.append(f"{code}: {relative}: {exc}")
            return None

    cavr = config.modules.CAVR
    if cavr is not None and cavr.enabled:
        policy = read(cavr.policy, "ASENT_CONFIG_POLICY")
        if policy is not None:
            found = list(policy_problems(policy))
            capability = capability_policy_problem(policy)
            if capability:
                found.append(capability)
            description = policy.get("project_task_description") if isinstance(policy, dict) else None
            if not isinstance(description, str) or not description.strip():
                found.append("project_task_description must be non-empty text (it selects the threat-repository capability rules)")
            problems.extend(f"ASENT_CONFIG_POLICY: {cavr.policy}: {problem}" for problem in found)
            if not found:
                documents["cavr_policy"] = policy

    satra = config.modules.SATRA
    if satra is not None and satra.enabled:
        contract = read(satra.contract, "ASENT_CONFIG_CONTRACT")
        if contract is not None:
            try:
                documents["satra_contract"] = SatraContract.model_validate(contract).model_dump()
            except ValidationError as exc:
                problems.extend(_schema_problems("ASENT_CONFIG_CONTRACT", satra.contract, exc))
        prefix = satra.trusted_tests + "/"
        tests = sorted(name[len(prefix):] for name in files if name.startswith(prefix))
        if not any(Path(name).name.startswith("test_") and name.endswith(".py") for name in tests):
            problems.append(f"ASENT_CONFIG_FILE_MISSING: {satra.trusted_tests}/ has no test_*.py file")
        else:
            documents["satra_trusted_tests"] = tests
        if satra.pytest_ini is not None and satra.pytest_ini not in files:
            problems.append(f"ASENT_CONFIG_FILE_MISSING: {satra.pytest_ini} is named in {CONFIG_NAME} but is not in .asent/")

    sable = config.modules.SABLE
    if sable is not None and sable.enabled:
        obligations = read(sable.obligations, "ASENT_CONFIG_OBLIGATIONS")
        if obligations is not None:
            try:
                documents["sable_obligations"] = SableObligations.model_validate(obligations).model_dump()
            except ValidationError as exc:
                problems.extend(_schema_problems("ASENT_CONFIG_OBLIGATIONS", sable.obligations, exc))

    return done(problems, config, documents)


__all__ = ["ConfigResult", "MODULE_NAMES", "load", "tree_digest", "MAX_FILES", "MAX_BYTES"]
