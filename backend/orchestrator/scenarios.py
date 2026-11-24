"""Applies named, controlled module changes inside an isolated run candidate."""
import json
import shutil
from pathlib import Path
from backend.config import ASSETS
from backend.orchestrator.hashing import copy_tree
from backend.satra.counterfactuals import mutate_ownership

def catalog():
    # The catalog supplies scenario names, labels, and expected outcomes for controlled runs.
    return json.loads((ASSETS/'scenarios/catalog.json').read_text())

def scenario_project(item):
    # The fixture project a scenario starts from (demo layer only; gate runs never call this).
    return ASSETS/item.get('project','demo_project/InvoiceHub')

def apply_scenario(path,scenario):
    # Fixtures mutate only the isolated candidate workspace created for this run.
    path=Path(path)
    if scenario=='satra_weak':(path/'tests/test_security.py').write_text((ASSETS/'scenarios/satra/weak_test.py').read_text())
    elif scenario=='satra_bypass':mutate_ownership(path)
    elif scenario.startswith('sable_'):
        case=scenario.removeprefix('sable_');folder=ASSETS/'scenarios/sable'/case
        if not folder.is_dir():raise ValueError('Unknown infrastructure scenario')
        shutil.rmtree(path/'infra');copy_tree(folder,path/'infra')
        with (path/'plan.md').open('a') as f:f.write('\nAdd archival for invoices older than 90 days and refactor storage into a reusable Terraform module. Preserve the active invoice security boundary.\n')
    elif scenario!='safe':raise ValueError('Unknown scenario')

