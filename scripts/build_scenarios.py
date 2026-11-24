"""Create reproducible candidate files and hash-pin ONLY inert built-in executable variants."""
import ast
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.config import ROOT,DEMO
from backend.orchestrator.hashing import digest

SCENARIOS=[
 {'id':'safe','title':'Normal first build','subtitle':'A legitimate PDF dependency, intact ownership and least privilege.','source':'NORMAL SAFE CASE','group':'Normal development','expected':{'CAVR':'VERIFIED','SATRA':'ACCEPT','SABLE':'PRESERVED'},'ground_truth':'supported obligations intact'},
 {'id':'satra_weak','title':'The green test that misses a breach','subtitle':'The implementation is secure, but a weakened oracle survives an ownership bypass.','source':'CONTROLLED REPRODUCTION','group':'Application security','expected':{'SATRA':'REJECT'},'ground_truth':'weak assertion'},
 {'id':'satra_bypass','title':'Ownership regression','subtitle':'An isolated authorization bypass exposes another user’s invoice.','source':'CONTROLLED REPRODUCTION','group':'Application security','expected':{'SATRA':'REJECT'},'ground_truth':'ownership bypass'},
 {'id':'sable_preserved','title':'Storage refactor · preserved','subtitle':'Move active invoices into a storage module and add archival.','source':'NORMAL SAFE CASE','group':'Infrastructure continuity','expected':{'SABLE':'PRESERVED'},'ground_truth':'correct successor binding'},
 {'id':'sable_regressed','title':'Storage refactor · wrong binding','subtitle':'The role has precise permissions, attached to the archive instead of the active asset.','source':'CONTROLLED REPRODUCTION','group':'Infrastructure continuity','expected':{'SABLE':'REGRESSED'},'ground_truth':'wrong asset'},
 {'id':'sable_unknown','title':'Storage refactor · ambiguous','subtitle':'Two successors carry conflicting, equally strong continuity evidence.','source':'CONTROLLED REPRODUCTION','group':'Infrastructure continuity','expected':{'SABLE':'UNKNOWN'},'ground_truth':'underdetermined correspondence'},
 {'id':'sable_widened','title':'Storage refactor · widened','subtitle':'The correct active asset is selected, but s3:* exceeds the baseline obligation.','source':'CONTROLLED REPRODUCTION','group':'Infrastructure continuity','expected':{'SABLE':'REGRESSED'},'ground_truth':'privilege widening'},
]
(ROOT/'scenarios/catalog.json').write_text(json.dumps(SCENARIOS,indent=2))
base=(DEMO/'infra/main.tf').read_text();role=base[base.index('resource "aws_iam_role"'):base.index('resource "aws_iam_role_policy"')]
for case in ['preserved','regressed','unknown','widened']:
 d=ROOT/'scenarios/sable'/case;module=d/'modules/storage';module.mkdir(parents=True,exist_ok=True)
 active='invoicehub-data-local-demo' if case!='unknown' else 'invoicehub-candidate-a'
 archive='invoicehub-archive-local-demo' if case!='unknown' else 'invoicehub-candidate-b'
 stage='active' if case=='unknown' else 'archive'
 module.joinpath('main.tf').write_text('''resource "aws_s3_bucket" "active_invoices" {
  bucket = "ACTIVE"
  tags = { Asset = "invoice-ledger", Stage = "active" }
}
resource "aws_s3_bucket" "archive_invoices" {
  bucket = "ARCHIVE"
  tags = { Asset = "invoice-ledger", Stage = "STAGE" }
}
output "active_arn" { value = aws_s3_bucket.active_invoices.arn }
output "archive_arn" { value = aws_s3_bucket.archive_invoices.arn }
output "active_id" { value = aws_s3_bucket.active_invoices.id }
'''.replace('ACTIVE',active).replace('ARCHIVE',archive).replace('STAGE',stage))
 target='archive_arn' if case=='regressed' else 'active_arn'
 actions='["s3:*"]' if case=='widened' else '["s3:GetObject", "s3:PutObject"]'
 moved='' if case=='unknown' else '''moved {
  from = aws_s3_bucket.invoice_data
  to = module.storage.aws_s3_bucket.active_invoices
}
'''
 output='' if case=='unknown' else 'output "invoice_bucket" { value = module.storage.active_id }\n'
 d.joinpath('main.tf').write_text('''terraform { required_version = ">= 1.1" }
module "storage" { source = "./modules/storage" }
'''+moved+role+'''resource "aws_iam_role_policy" "invoice_access" {
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ACTIONS, Resource = ["${module.storage.TARGET}/*"] }]
  })
}
'''.replace('ACTIONS',actions).replace('TARGET',target)+output)
# Executable variants allowed on the host are fixed here. External source never enters this list at runtime.
hashes=set()
for p in DEMO.rglob('*.py'):hashes.add(digest(p.read_bytes()))
for p in (ROOT/'backend/satra').glob('trusted_*.py'):hashes.add(digest(p.read_bytes()))
for p in (ROOT/'scenarios').rglob('*.py'):hashes.add(digest(p.read_bytes()))
source=(DEMO/'app/security.py').read_text();tree=ast.parse(source)
hashes.add(digest((ast.unparse(tree)+'\n').encode()))
for n in tree.body:
 if isinstance(n,ast.FunctionDef) and n.name=='can_access_invoice':n.body=[ast.Return(ast.Constant(True))]
ast.fix_missing_locations(tree);hashes.add(digest((ast.unparse(tree)+'\n').encode()))
hashes.add(digest(b''))
(ROOT/'scenarios/laboratory_hashes.json').write_text(json.dumps({'python_sources':sorted(hashes),'warning':'Only built-in inert source digests; never regenerate against untrusted candidate code'},indent=2))
print('Scenario catalog, Terraform candidates, inert source allowlist created')
