"""Builds the candidate context, module inputs, and hashes used by the shared workflow."""
import ast
import json
from pathlib import Path
from backend.orchestrator.hashing import manifest,digest
from backend.orchestrator.event_router import route
from backend.threat_repo.repository import seeds
from backend.threat_repo.versioning import MODULE_CATEGORIES,module_digest

class ContextService:
    def __init__(self,path,baseline,knowledge=None):
        # Cache a manifest and load the documents and rule snapshot used throughout one analysis.
        self.path=Path(path);self.baseline=Path(baseline)
        self.manifest=manifest(path)
        self.srs=self.read('SRS.md')
        self.plan=self.read('plan.md')
        self.policy=json.loads(self.read('policy.json') or '{}')
        records=seeds() if knowledge is None else knowledge['records']
        self.knowledge=knowledge or {'version':'BUNDLED-SEED','digest':digest(records),'records':records,'module_digests':{m:module_digest(records,m) for m in MODULE_CATEGORIES}}
    def read(self,p):
        # Missing optional project documents are represented as empty content.
        f=self.path/p;return f.read_text() if f.is_file() else ''
    def inputs(self,module):
        # Bind evidence to relevant candidate files plus that module's baseline and rule versions.
        selected={k:v for k,v in self.manifest.items() if module in route([k])}
        # Baseline is an authority input for differential and lineage analyses.
        base=manifest(self.baseline)
        selected['@baseline']=digest({k:v for k,v in base.items() if module in route([k])})
        selected['@knowledge']=self.knowledge['module_digests'][module]
        return selected
    def input_hash(self,module):return digest(self.inputs(module))
    def applicability(self):
        # Run only analyzers whose supported input surfaces exist in this candidate.
        out=[]
        if any(k in self.manifest for k in ['dependencies.lock.json','requirements.txt','package.json','pyproject.toml']):out.append('CAVR')
        if any(k.endswith('.py') and not k.startswith('tests/') for k in self.manifest):out.append('SATRA')
        if any(k.endswith('.tf') for k in self.manifest):out.append('SABLE')
        return out
    def dependency_context(self):
        # Collect bounded AST-level imports and call sites for CAVR dependency attribution.
        imports=[];calls=[];errors=[];attributions=[]
        lock=json.loads(self.read('dependencies.lock.json') or '{"packages":[]}')
        package_names={p['name'].lower().replace('_','-'):p for p in lock.get('packages',[])}
        import_roots={}
        # Supported distribution-to-import aliases. This is a deliberately
        # bounded name map, not package discovery or dataflow analysis.
        aliases={'invoice-pdf-safe':('vendor.invoice_pdf_safe',),
                 'invoice-pdf-lab':('vendor.invoice_pdf_lab',),
                 'pypdf':('pypdf',)}
        for package in package_names.values():
            name=package['name'].lower().replace('_','-')
            roots=aliases.get(name,(name.replace('-','_'),))
            for root in roots: import_roots.setdefault(root,[]).append(package)
        for p in self.manifest:
            if not p.startswith('app/') or not p.endswith('.py'):continue
            try:tree=ast.parse(self.read(p))
            except SyntaxError as e:errors.append({'file':p,'error':str(e)});continue
            aliases={};alias_symbols={}
            for n in ast.walk(tree):
                if isinstance(n,ast.ImportFrom):
                    imports.append({'file':p,'line':n.lineno,'module':n.module,'names':[a.name for a in n.names]})
                    for a in n.names: aliases[a.asname or a.name]=(n.module or '');alias_symbols[a.asname or a.name]=a.name
                elif isinstance(n,ast.Import):
                    for a in n.names:
                        imports.append({'file':p,'line':n.lineno,'module':a.name,'names':[a.name]});aliases[a.asname or a.name.split('.')[0]]=a.name;alias_symbols[a.asname or a.name.split('.')[0]]=a.name.rsplit('.',1)[-1]
            for n in ast.walk(tree):
                if not isinstance(n,ast.Call):continue
                expr=ast.unparse(n.func);root=expr.split('.')[0];mod=aliases.get(root,root)
                call={'file':p,'line':n.lineno,'expression':expr,'imported_module':mod}
                calls.append(call)
                dist=next(iter(import_roots.get(mod,[])),None)
                if dist:
                    purpose='PDF text extraction' if mod=='pypdf' or expr in ('PdfReader','extract_invoice_text') else 'application dependency use'
                    imported=next((x for x in imports if x['file']==p and x['module']==mod and x['line']<=n.lineno),None)
                    attributions.append({'package':dist['name'],'version':dist.get('version'),'imported_module':mod,'imported_name':alias_symbols.get(root,expr.split('.')[-1]),'import_evidence':imported,'call_site':call,'purpose':purpose,'method':'AST import alias + call-site root match','scope':'syntactic attribution; no general dataflow'})
        return {'imports':imports,'call_sites':calls,'dependency_attributions':attributions,'parse_errors':errors,'srs_digest':digest(self.srs),'plan_digest':digest(self.plan)}
