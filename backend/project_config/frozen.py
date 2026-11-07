"""A run's own copy of its base `.asent/`, and the view of it the analyzers already understand.

`freeze(source, home, required)` is called once, when a run is created. It copies the source's
`.asent/` into `<home>/asent/` (only after `load` found it safe to read), or, when there is nothing
safe to copy, writes `<home>/asent.status.json` with the problems. The run's baseline is
`<home>/baseline`, so `frozen_config(baseline)` finds the same config again for every
ContextService of that run, including ones built later or by tests. The copy never changes after
creation: later edits to the source cannot change the authority of a running analysis.

`required=False` (server runs of a plain repository): no `.asent/` means no config, and the
legacy `policy.json` of the project is used as before. `required=True` (gate runs): no `.asent/`
is ASENT_CONFIG_MISSING, which the gate turns into REVIEW.

`policy_from_config` maps a valid config onto the policy keys the analyzers read today
(`dependencies`, `ownership`, `infrastructure`); an invalid config maps to `{}`.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from backend.project_config.loader import ConfigResult, load

FROZEN_DIR = "asent"
STATUS_FILE = "asent.status.json"
NOT_ASSESSED = "not assessed (disabled by base config)"


def freeze(source, home, required: bool) -> ConfigResult | None:
    source_dir, home = Path(source) / ".asent", Path(home)
    if not required and not (source_dir.exists() or source_dir.is_symlink()):
        return None
    found = load(source_dir)
    if found.digest is None:  # missing, unsafe or over budget: nothing is copied
        (home / STATUS_FILE).write_text(json.dumps({"source": str(source_dir), "problems": list(found.problems)}, indent=2))
        return found
    target = home / FROZEN_DIR
    target.mkdir(parents=True)
    for relative in found.files:
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_dir / relative, destination, follow_symlinks=False)
    frozen = load(target)
    if frozen.digest != found.digest:
        # The source changed while it was copied; the copy is not the config that was checked.
        shutil.rmtree(target)
        problem = "ASENT_CONFIG_UNSAFE: .asent/ changed while it was being copied"
        (home / STATUS_FILE).write_text(json.dumps({"source": str(source_dir), "problems": [problem]}, indent=2))
        return ConfigResult(path=str(source_dir), valid=False, problems=(problem,))
    return frozen


def frozen_config(baseline) -> ConfigResult | None:
    home = Path(baseline).parent
    if (home / FROZEN_DIR).is_dir():
        return load(home / FROZEN_DIR)
    status = home / STATUS_FILE
    if status.is_file():
        data = json.loads(status.read_text())
        return ConfigResult(path=data.get("source", str(status)), valid=False, problems=tuple(data.get("problems") or ["ASENT_CONFIG_MISSING"]))
    return None


def policy_from_config(result: ConfigResult | None):
    """The legacy policy dict the analyzers read, built only from the base config."""
    if result is None:
        return None
    if not result.valid:
        return {}
    documents, out = result.documents, {"application": result.config.project.name}
    if "cavr_policy" in documents and isinstance(documents["cavr_policy"].get("dependencies"), dict):
        out["dependencies"] = documents["cavr_policy"]["dependencies"]
    contract = documents.get("satra_contract")
    if contract:
        ownership = {key: contract[key] for key in ("subject", "action", "resource", "state_effect") if contract.get(key) is not None}
        ownership.update(expected_status=contract["expected_status"], authority=contract["authority_sources"][0])
        out["ownership"] = ownership
    obligations = (documents.get("sable_obligations") or {}).get("obligations")
    if obligations:
        out["infrastructure"] = {key: value for key, value in obligations[0].items() if key != "id"}
        out["infrastructure_obligations"] = obligations
    return out
