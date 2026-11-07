"""Builds the candidate context, module inputs, and hashes used by the shared workflow."""
import ast
import json
from pathlib import Path
from backend.orchestrator.hashing import manifest,digest
from backend.orchestrator.event_router import route
from backend.threat_repo.repository import seeds
from backend.threat_repo.versioning import MODULE_CATEGORIES,module_digest
from backend.project_config.frozen import NOT_ASSESSED,frozen_config,policy_from_config

MODULES=('CAVR','SATRA','SABLE')
CAVR_MANIFESTS=['dependencies.lock.json','requirements.txt','package.json','pyproject.toml']

class ContextService:
    def __init__(self,path,baseline,knowledge=None,gate=False):
        # Cache a manifest and load the documents and rule snapshot used throughout one analysis.
        self.path=Path(path);self.baseline=Path(baseline);self.gate=gate
        self.manifest=manifest(path)
        self.srs=self.read('SRS.md')
        self.plan=self.read('plan.md')
        # Authority: the run's frozen base .asent/ when it has one (always in a gate run, where a
        # missing one is an invalid config); the candidate's policy.json only for plain server runs.
        self.config=frozen_config(self.baseline)
        if self.config is None and gate:
            from backend.project_config.loader import ConfigResult
            self.config=ConfigResult(path=str(self.baseline),valid=False,problems=('ASENT_CONFIG_MISSING: gate run without a frozen base config',))
        self.policy=policy_from_config(self.config) if self.config is not None else json.loads(self.read('policy.json') or '{}')
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
        if self.config is not None:selected['@config']=self.config.digest or digest(list(self.config.problems))
        return selected
    def input_hash(self,module):return digest(self.inputs(module))
    def surfaces(self):
        # Modules whose supported input surfaces exist in this candidate.
        out=[];cavr=self.config.module('CAVR') if self.config is not None and self.config.valid else None
        if any(k in self.manifest for k in CAVR_MANIFESTS+(cavr.requirements_files if cavr else [])):out.append('CAVR')
        if any(k.endswith('.py') and not k.startswith('tests/') for k in self.manifest):out.append('SATRA')
        if any(k.endswith('.tf') for k in self.manifest):out.append('SABLE')
        return out
    def applicability(self):
        # Run only analyzers whose inputs exist and that the base config enables. An invalid config runs nothing.
        found=self.surfaces()
        if self.config is None:return found
        if not self.config.valid:return []
        return [m for m in found if self.config.module_state(m)=='enabled']
    def coverage(self):
        # Per module: are its inputs present, what does the base config say, and was it assessed.
        found=set(self.surfaces());applicable=set(self.applicability());out={}
        for m in MODULES:
            state='legacy' if self.config is None else 'invalid' if not self.config.valid else self.config.module_state(m)
            entry={'inputs_present':m in found,'state':state,'assessed':m in applicable,'label':'assessed','reason':None}
            if state=='disabled':entry.update(label=NOT_ASSESSED,reason=self.config.disabled_reason(m))
            elif state=='invalid':entry.update(label='not assessed (base config invalid)',reason='; '.join(self.config.problems))
            elif m not in found:entry.update(label='not applicable (no inputs in this project)')
            elif state=='absent':entry.update(label='not assessed (applies but not configured in base config)',reason='no section in base .asent/config.json')
            out[m]=entry
        return out
    def config_reasons(self):
        # Reasons that keep the decision from ACCEPT whatever the module evidence says.
        if self.config is None:return []
        if not self.config.valid:return ['ASENT config: '+p for p in self.config.problems]
        found=self.surfaces()
        return [f'{m}: applies but is not configured in base .asent/config.json' for m in MODULES if m in found and self.config.module_state(m)=='absent']
    def dependency_context(self):
        # Collect bounded AST-level imports and call sites for CAVR dependency attribution.
        imports=[];calls=[];errors=[];attributions=[]
        lock=json.loads(self.read('dependencies.lock.json') or '{"packages":[]}')
        package_names={p['name'].lower().replace('_','-'):p for p in lock.get('packages',[])}
        import_roots={}
        # Distribution-to-import aliases come from the base config (`cavr.import_aliases`); without
        # one the import name is the distribution name. A bounded name map, not package discovery.
        cavr=self.config.module('CAVR') if self.config is not None and self.config.valid else None
        aliases={k.lower().replace('_','-'):tuple(v) for k,v in (cavr.import_aliases if cavr else {}).items()}
        source_dirs=tuple(d.rstrip('/')+'/' for d in cavr.source_dirs) if cavr and cavr.source_dirs else ('',) if cavr else ('app/',)
        for package in package_names.values():
            name=package['name'].lower().replace('_','-')
            artifact=str(package.get('artifact') or '')
            # A LOCAL source artifact is imported by its own path (vendor/x.py -> vendor.x); a registry
            # package by its configured alias, else by its name.
            local=(artifact[:-3].replace('/','.'),) if package.get('ecosystem')=='LOCAL' and artifact.endswith('.py') and not artifact.startswith(('/','..')) else None
            roots=aliases.get(name) or local or (name.replace('-','_'),)
            for root in roots: import_roots.setdefault(root,[]).append(package)
        for p in self.manifest:
            if not p.startswith(source_dirs) or not p.endswith('.py'):continue
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
