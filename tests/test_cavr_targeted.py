import json

from backend.cavr.ast_scan import rule_scan as scan
from backend.orchestrator.context_service import ContextService

# The lab tests (legacy causal graph, rank_repairs, the LOCAL-lab counterfactual runs) were deleted with the lab
# (CAVR report notes Step M2-18); `scan` is the rule scan that moved unchanged into ast_scan.


def test_safe_adapter_import_attribution_and_unrelated_import(tmp_path):
    from backend.config import ROOT
    from backend.orchestrator.hashing import copy_tree
    project=tmp_path/'project';copy_tree(ROOT/'demo_project'/'InvoiceHub',project)
    (project/'app'/'pdf_adapter.py').write_text('from vendor.invoice_pdf_safe import extract_invoice_text as extract\n\ndef run(data): return extract(data)\n')
    (project/'app'/'unrelated.py').write_text('import unrelated_vendor\ndef run(): return unrelated_vendor.go()\n')
    lock=json.loads((project/'dependencies.lock.json').read_text())
    lock['packages'].append({'name':'invoice-pdf-safe','version':'1.0.0','ecosystem':'LOCAL','artifact':'vendor/invoice_pdf_safe.py','sha256':'0'*64})
    (project/'dependencies.lock.json').write_text(json.dumps(lock))
    ctx=ContextService(project,project)
    attrs=ctx.dependency_context()['dependency_attributions']
    assert any(a['package']=='invoice-pdf-safe' and a['imported_name']=='extract_invoice_text' and a['import_evidence']['module']=='vendor.invoice_pdf_safe' and a['call_site']['file']=='app/pdf_adapter.py' for a in attrs)
    assert not any(a['package']=='invoice-pdf-safe' and a['call_site']['file']=='app/unrelated.py' for a in attrs)


def test_trigger_scanner_records_supported_if_else_file_and_unknown_helper():
    src='''import os\nfrom pathlib import Path\ndef f():\n if os.getenv("CAVR_CANARY_AWS_SECRET"):\n  open("canary.txt").read()\n else:\n  socket.create_connection(("host", 80))\n if Path("feature.flag").exists():\n  subprocess.Popen(["x"])\n if helper():\n  requests.get("https://example.invalid")\n'''
    result=scan({'x.py':src});records=result['triggers']
    assert any(t['trigger_type']==['environment-variable'] and t['activation_known'] for t in records)
    assert any(t['reachability'].endswith('else-branch containment') and t['reachable_sinks'][0]['sink']=='socket.create_connection' for t in records)
    file_trigger=next(t for t in records if 'file-existence' in t['trigger_type'])
    assert file_trigger['supported_activation'] and file_trigger['inputs']==["Path('feature.flag')"]
    unknown=next(t for t in records if 'helper()' in t['predicate'])
    assert not unknown['supported_activation'] and unknown['unsupported_reason']
