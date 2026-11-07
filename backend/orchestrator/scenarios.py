"""Applies named, controlled module changes inside an isolated run candidate."""
import json
import shutil
from pathlib import Path
from backend.config import ROOT
from backend.orchestrator.hashing import digest,copy_tree
from backend.satra.counterfactuals import mutate_ownership

def catalog():
    # The catalog supplies scenario names, labels, and expected outcomes for controlled runs.
    return json.loads((ROOT/'scenarios/catalog.json').read_text())

def apply_scenario(path,scenario):
    # Fixtures mutate only the isolated candidate workspace created for this run.
    path=Path(path)
    if scenario=='satra_weak':(path/'tests/test_security.py').write_text((ROOT/'scenarios/satra/weak_test.py').read_text())
    elif scenario=='satra_bypass':mutate_ownership(path)
    elif scenario.startswith('sable_'):
        case=scenario.removeprefix('sable_');folder=ROOT/'scenarios/sable'/case
        if not folder.is_dir():raise ValueError('Unknown infrastructure scenario')
        shutil.rmtree(path/'infra');copy_tree(folder,path/'infra')
        with (path/'plan.md').open('a') as f:f.write('\nAdd archival for invoices older than 90 days and refactor storage into a reusable Terraform module. Preserve the active invoice security boundary.\n')
    elif scenario in ('cavr_canary','cross_module'):
        vendor=path/'vendor';vendor.mkdir(exist_ok=True);(vendor/'__init__.py').write_text('')
        src=ROOT/'scenarios/cavr_controlled/invoice_pdf_lab.py';shutil.copyfile(src,vendor/src.name)
        (path/'app/pdf_adapter.py').write_text('from vendor.invoice_pdf_lab import extract_invoice_text\n')
        lock=json.loads((path/'dependencies.lock.json').read_text())
        lock['packages'].append({'name':'invoice-pdf-lab','version':'1.0.0','ecosystem':'LOCAL','artifact':'vendor/invoice_pdf_lab.py','sha256':digest(src.read_bytes()),'classification':'CONTROLLED REPRODUCTION'})
        lock['edges'].append({'source':'invoice-pdf-lab','target':'pypdf'})
        (path/'dependencies.lock.json').write_text(json.dumps(lock,indent=2))
    elif scenario!='safe':raise ValueError('Unknown scenario')


def replace_lab(root):
    # Model a reviewed local replacement and update its lock entry and dependency edge together.
    root=Path(root);lock=json.loads((root/'dependencies.lock.json').read_text())
    if not any(n['name']=='invoice-pdf-lab' for n in lock['packages']):return []
    src=ROOT/'scenarios/cavr_controlled/invoice_pdf_safe.py';vendor=root/'vendor';vendor.mkdir(exist_ok=True)
    shutil.copyfile(src,vendor/src.name);(vendor/'invoice_pdf_lab.py').unlink(missing_ok=True)
    (root/'app/pdf_adapter.py').write_text('from vendor.invoice_pdf_safe import extract_invoice_text\n')
    lock['packages']=[n for n in lock['packages'] if n['name']!='invoice-pdf-lab']+[{'name':'invoice-pdf-safe','version':'1.0.0','ecosystem':'LOCAL','artifact':'vendor/invoice_pdf_safe.py','sha256':digest(src.read_bytes()),'classification':'local reviewed replacement'}]
    lock['edges']=[{'source':'invoice-pdf-safe','target':'pypdf'}]
    (root/'dependencies.lock.json').write_text(json.dumps(lock,indent=2))
    return ['dependencies.lock.json','app/pdf_adapter.py','vendor/invoice_pdf_lab.py','vendor/invoice_pdf_safe.py']
