"""`asent init`: write a starter `.asent/` for a project. The starter is refused until a person reviews it.

What can be read from the project is filled in; what cannot is left disabled with a reason:

- CAVR: enabled when the project root has `requirements*.txt` files. Every exact pin
  (`name==version`, extras and markers dropped) becomes an approved requirement; every other line
  is listed in `not_copied` and is not approved. `allowed_scopes` is empty (every capability denied)
  and the task description is a TODO the reviewer must replace.
- SATRA: always disabled. Its contract, trusted tests and counterfactual target say what the
  application must guarantee; they cannot be inferred from the code.
- SABLE: always disabled; the directories holding `.tf` files are filled in, the obligations
  (which principal may do what on which asset) cannot be inferred.

`config.json` carries `"_starter": true`, so `load()` reports ASENT_CONFIG_STARTER and the gate
decides REVIEW until the reviewer removes it. An existing `.asent/` is never overwritten unless
`force`; a symlinked `.asent` is refused even with `force`, so nothing outside the project is deleted.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

SKIP_DIRS = {".git", ".asent", ".venv", "venv", "node_modules", "__pycache__", ".terraform", ".tox", ".mypy_cache",
             ".pytest_cache", "dist", "build"}
SATRA_REASON = ("starter: SATRA needs a security contract, trusted tests and a counterfactual target written for this "
                "project (docs/asent-config.md); they cannot be inferred from the code")
SABLE_REASON = ("starter: SABLE needs obligations (which principal may do what on which asset) written for this "
                "project in sable/obligations.json; they cannot be inferred from the Terraform")

README = """# ASENT configuration (starter written by `asent init`)

ASENT reads this folder from the BASE commit of every change it gates. Until it is reviewed,
the gate decides REVIEW for every change.

Review before use:

1. `cavr/policy.json`: replace `project_task_description`; check every `approved_requirements`
   entry (copied from exact pins); add `denied_packages`; grant `allowed_scopes` only if needed.
2. SATRA is disabled. To enable it, write `satra/contract.json` and `satra/trusted_tests/`.
3. SABLE is disabled. To enable it, write `sable/obligations.json`.
4. Remove `"_starter": true` from `config.json`.

Schema and rules: docs/asent-config.md in the ASENT repository.
"""


def _walk(root: Path):
    for base, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith(".") and not (Path(base) / d).is_symlink())
        yield Path(base), names


def detect(root: Path) -> dict:
    """What `init` can see: root requirements files, Python outside tests/, directories with `.tf` files."""
    requirements = sorted(p.name for p in root.glob("requirements*.txt") if p.is_file() and not p.is_symlink())
    python, terraform = False, set()
    for base, names in _walk(root):
        relative = base.relative_to(root)
        top = relative.parts[0] if relative.parts else ""
        for name in names:
            if name.endswith(".py") and top not in ("tests", "test"):
                python = True
            if name.endswith(".tf"):
                terraform.add(relative.as_posix())
    return {"requirements_files": requirements, "python": python, "terraform_dirs": sorted(terraform)}


def _pins(root: Path, files: list[str]):
    approved, not_copied = set(), []
    for name in files:
        for raw in (root / name).read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.split(" #", 1)[0].strip()
            if not line or line.startswith("#"):
                continue
            try:
                requirement = Requirement(line)
            except InvalidRequirement:
                not_copied.append(line)
                continue
            specs = list(requirement.specifier)
            if requirement.url or len(specs) != 1 or specs[0].operator != "==" or "*" in specs[0].version:
                not_copied.append(line)
                continue
            approved.add(f"{canonicalize_name(requirement.name)}=={specs[0].version}")
    return sorted(approved), not_copied


def init_project(repository, force: bool = False) -> dict:
    """Write the starter; return {"asent_dir", "files", "detected", "not_copied"}."""
    root = Path(repository)
    if not root.is_dir():
        raise ValueError(f"not a project directory: {root}")
    target = root / ".asent"
    if target.is_symlink():
        raise ValueError(f"{target} is a symlink; refusing to write or delete through it")
    if target.exists():
        if not force:
            raise FileExistsError(f"{target} already exists; review it, or pass --force to replace it")
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()

    found = detect(root)
    approved, not_copied = _pins(root, found["requirements_files"])
    modules = {
        "CAVR": ({"enabled": True, "policy": "cavr/policy.json", "requirements_files": found["requirements_files"], "verify": "all"}
                 if found["requirements_files"] else
                 {"enabled": False, "reason": "starter: no requirements*.txt at the project root"}),
        "SATRA": {"enabled": False, "reason": SATRA_REASON},
        "SABLE": ({"enabled": False, "reason": SABLE_REASON, "terraform_dirs": found["terraform_dirs"]}
                  if found["terraform_dirs"] else {"enabled": False, "reason": SABLE_REASON}),
    }
    config = {"_starter": True, "schema_version": 1, "project": {"name": (root.resolve().name or "project")[:100]},
              "modules": modules}
    policy = {"project_task_description": "TODO: describe in one sentence what this project does",
              "allowed_scopes": [], "approved_requirements": approved, "denied_packages": []}

    files = {"config.json": config, "cavr/policy.json": policy, "README.md": README}
    for relative, body in files.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body if isinstance(body, str) else json.dumps(body, indent=2) + "\n", encoding="utf-8")
    return {"asent_dir": str(target), "files": [f".asent/{name}" for name in files], "detected": found, "not_copied": not_copied}
