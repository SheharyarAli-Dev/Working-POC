"""The LOCAL-lab demo scenarios are retired (Step M2-18 of the CAVR report notes, Maryam 2026-11-24, demo option A).

`cavr_canary` and `cross_module` ran a vendored `.py` "lab" package through the old host / harness sandbox
(`backend/cavr/sandbox.py`). They are replaced by real wheels judged by the CAVR sandbox (docs/cavr-demo.md, "M2 demo:
real wheels"). No file that is still in use may name them; dated records of what happened before keep their text.
"""
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
NAMES = re.compile(r"\b(?:cross_module|cavr_canary)\b")
# Dated records: they describe runs and decisions made before the retirement and are not rewritten.
HISTORICAL = (
    "docs/report-notes/",           # step-by-step report notes (append-only history)
    "docs/cavr-m2-plan.md",         # the plan's decision log records the retirement itself
    "docs/satra/harness-isolation.md",  # SATRA's record of a 2026-11 run (another owner's document)
    "reports/",                     # committed evidence and reports of earlier runs (Final-1 runbook, pytest.xml, ...)
    "tests/test_cavr_retired_scenarios.py",
)


def tracked_files():
    out = subprocess.run(["git", "ls-files", "-z"], cwd=REPO, capture_output=True, check=True).stdout
    return [name for name in out.decode().split("\0") if name]


def test_no_file_in_use_names_a_retired_scenario():
    found = []
    for name in tracked_files():
        if name.startswith(HISTORICAL):
            continue
        try:
            text = (REPO / name).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary files (wheels, images) carry no scenario names
        found += [f"{name}:{number}" for number, line in enumerate(text.splitlines(), 1) if NAMES.search(line)]
    assert found == []


def test_the_scenario_catalog_has_no_retired_entry():
    import json
    catalog = json.loads((REPO / "scenarios" / "catalog.json").read_text())
    items = catalog if isinstance(catalog, list) else catalog.get("scenarios", [])
    assert {"cavr_canary", "cross_module"}.isdisjoint({item["id"] for item in items})


def test_the_historical_list_names_only_paths_that_exist():
    tracked = tracked_files()
    for prefix in HISTORICAL:
        assert any(name.startswith(prefix) for name in tracked), prefix
