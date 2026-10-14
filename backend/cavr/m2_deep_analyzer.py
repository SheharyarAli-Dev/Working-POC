"""M2 only: the sandbox-based dependency analysis that the orchestrator used before plan step 14.

Not on the orchestrator path. Since step 14 `analyzer.analyze` delegates every dependency
decision to `pipeline.verify_request` (M1) and imports nothing from this file. This file keeps
the counterfactual sandbox runs (`sandbox.run_counterfactual`), the runtime contract check
(`policy.verify_runtime`), the older contract (`capability_contract.infer`) and the older
cache (`Store.cache_get` / `cache_put`) reachable for the M2 deep-analysis work and for
`tests/test_modules.py::test_controlled_dormant_execution`. The code below is unchanged.
"""
import json
import time
from pathlib import Path
from packaging.requirements import Requirement
from backend.config import ROOT
from backend.orchestrator.hashing import digest
from backend.integrations.registry_adapter import read_artifact
from backend.integrations.osv_adapter import OSV
from backend.cavr.capability_contract import infer
from backend.cavr.fast_gate import disabled_jbig2_sinks
from backend.cavr.trigger_discovery import scan
from backend.cavr.sandbox import run_counterfactual
from backend.cavr.policy import verify_runtime
from backend.cavr.causal_graph import build
from backend.threat_repo.source_sink_rules import correlate
from backend.threat_repo.package_records import packages,vulnerabilities
from backend.threat_repo.repository import active,seeds


def analyze(context,store,outdir,emit):
    start=time.perf_counter();nodes=[];uncertain=[];statuses=[]
    lock_file=context.path/'dependencies.lock.json'
    if not lock_file.exists():return 'UNRESOLVED',{'reason':'Exact artifact lock required; arbitrary resolver output is not a trust proof','nodes':[]},['Dependency artifacts unresolved']
    lock=json.loads(lock_file.read_text());locked=lock.get('packages',[]);names={n['name'].lower().replace('_','-') for n in locked}
    if not locked:return 'UNRESOLVED',{'reason':'Empty dependency lock','nodes':[]},['No dependency artifacts resolved']
    declared=[]
    for line in context.read('requirements.txt').splitlines():
        if line.strip() and not line.startswith('#'):
            try:declared.append(Requirement(line))
            except Exception:uncertain.append('Unsupported requirement syntax: '+line)
    for req in declared:
        matching=[n for n in locked if n['name'].lower().replace('_','-')==req.name.lower().replace('_','-')]
        if not matching or not any(n['version'] in req.specifier for n in matching):uncertain.append('Manifest/lock mismatch: '+str(req))
    policy=context.policy.get('dependencies',{});allowed=policy.get('allowed',[])
    for node in locked:
        t=time.perf_counter();record={**node,'cache_hit':False};status='VERIFIED';notes=[]
        emit('dependency.intercepted',{'package':node['name'],'version':node['version'],'source':'exact candidate lock; no host installation'})
        if node.get('ecosystem','PyPI') not in ('PyPI','LOCAL'):
            nodes.append({**record,'status':'UNRESOLVED','reason':'Unsupported dependency ecosystem'});statuses.append('UNRESOLVED');continue
        if node['name'] not in allowed:
            nodes.append({**record,'status':'REJECTED','reason':'Not permitted by registered project policy'});statuses.append('REJECTED');continue
        try:artifact=read_artifact(node,context.path)
        except Exception as e:
            nodes.append({**record,'status':'UNRESOLVED','reason':str(e)});statuses.append('UNRESOLVED');continue
        contract=infer(context,node);static=scan(artifact['sources'],context.knowledge)
        active_rules={r['id']:r for c in ('behaviors','triggers') for r in active(context.knowledge,c)}
        for required in (r for r in seeds() if r['category'] in ('behaviors','triggers')):
            current=active_rules.get(required['id'])
            key_field='python_sinks' if required['category']=='behaviors' else 'match_calls'
            if not current or not set(required['data'].get(key_field,[])).issubset(current['data'].get(key_field,[])):notes.append('Required rule coverage unavailable: '+required['id'])
        package_matches=packages(context.knowledge,node)
        known_vulns,range_unknown=vulnerabilities(context.knowledge,node)
        if range_unknown:notes.append('Unsupported advisory version ranges: '+', '.join(range_unknown))
        if known_vulns:status='REJECTED'
        if contract['confidence']=='insufficient':notes.append('Capability contract lacks task/call-site authority')
        for reqtext in artifact['metadata'].get('requires_dist',[]):
            try:
                req=Requirement(reqtext)
                if req.marker and not req.marker.evaluate({'extra':''}):continue
                matches=[n for n in locked if n['name'].lower().replace('_','-')==req.name.lower().replace('_','-')]
                if not matches or not any(n['version'] in req.specifier for n in matches):notes.append('Unresolved transitive dependency: '+str(req))
            except Exception:notes.append('Unparsed transitive requirement: '+reqtext)
        local=node.get('ecosystem')=='LOCAL'
        advisory={'available':True,'mode':'NOT APPLICABLE: local unregistered source','vulnerabilities':[]} if local else OSV().query(node['name'],node['version'],live=policy.get('require_live_osv',False),max_age_days=policy.get('advisory_max_age_days',30))
        if not advisory['available']:notes.append('Known-vulnerability evidence unavailable')
        if advisory.get('vulnerabilities'):status='REJECTED'
        key=digest({'artifact':artifact['sha256'],'subtree':lock,'contract':contract['digest'],'policy':context.policy,'advisory':advisory.get('response_sha256',advisory.get('mode')),'analyzer':'1.0.0','package':node['name'],'version':node['version'],'threat_module_digest':context.knowledge['module_digests']['CAVR']})
        previous=store.cache_get(key)
        fast_ms=(time.perf_counter()-t)*1000
        if previous and previous.get('status')=='VERIFIED' and not notes and status=='VERIFIED':
            record={**previous,'cache_hit':True,'fast_gate_ms':fast_ms,'deep_analysis_ms':0,'cache_key':key}
            emit('cavr.cache_hit',{'package':node['name'],'cache_key':key});nodes.append(record);statuses.append(record['status']);continue
        emit('cavr.fast_gate',{'package':node['name'],'cache':'MISS','duration_ms':fast_ms,'artifact_hash':artifact['sha256']})
        for trigger in static['triggers']:emit('cavr.trigger_found',trigger)
        if static['parse_errors']:notes.append('Python source parse incomplete')
        runtime=None;violations=[];deep_ms=0
        if static['triggers']:
            deep=time.perf_counter()
            if artifact['path'].endswith('.py'):
                runtime=run_counterfactual(artifact['path'],context.path/'fixtures/invoice.pdf',Path(outdir)/node['name'],emit)
                if runtime['available']:
                    for r in runtime['runs']:violations+=verify_runtime(contract,r['events'],r['facts'].get('receiver_payloads'))
                    by_mode={r['mode']:r for r in runtime['runs']}
                    if set(by_mode)>={'normal','counterfactual'}:
                        normal,cf=by_mode['normal']['facts'],by_mode['counterfactual']['facts']
                        runtime['fixture_comparison']={'functional_equivalent':normal.get('functional_text')==cf.get('functional_text'),'normal_canary_received':normal.get('canary_received'),'counterfactual_canary_received':cf.get('canary_received'),'deterministic_expectation_met':normal.get('canary_received') is False and cf.get('canary_received') is True and normal.get('functional_text')==cf.get('functional_text')}
                        if not runtime['fixture_comparison']['deterministic_expectation_met']:
                            notes.append('Controlled fixture did not demonstrate expected normal/counterfactual distinction')
                    if violations:status='REJECTED'
                else:notes.append(runtime.get('reason','Deep execution unavailable or failed'))
            else:notes.append('High-risk wheel requires an explicit bounded activation entry point')
            if any(not t['supported'] for t in static['triggers']):notes.append('Unexercised high-risk predicates remain')
            deep_ms=(time.perf_counter()-deep)*1000
        elif static['sinks']:
            disabled=disabled_jbig2_sinks(artifact,context)
            uncovered=[x for x in static['sinks'] if not (x['file']=='pypdf/filters.py' and x['line'] in disabled)]
            static['disabled_optional_sinks']=[x for x in static['sinks'] if x not in uncovered]
            static['guard_evidence']='All PdfReader call sites are enclosed by apply_configuration(jbig2dec_binary=None); decoder methods exit before subprocess execution' if disabled else None
            if uncovered:notes.append('Sensitive sinks require a supported activation entry point')
        if notes and status!='REJECTED':status='UNRESOLVED'
        ev=[e for r in (runtime or {}).get('runs',[]) for e in r.get('events',[])]
        payloads=[p for r in (runtime or {}).get('runs',[]) for p in r.get('facts',{}).get('receiver_payloads',[])]
        record.update({'threat_matches':package_matches,'known_vulnerabilities':known_vulns,'threat_correlations':correlate(context.knowledge,ev,payloads,contract),'threat_repo_version':context.knowledge['version'],'status':status,'metadata':artifact['metadata'],'contract':contract,'dependency_use':context.dependency_context(),'static':static,'osv':advisory,'runtime':runtime,'violations':violations,'causal_graph':build(node['name'],static['triggers'],ev,payloads),'fast_gate_ms':round(fast_ms,2),'deep_analysis_ms':round(deep_ms,2),'cache_key':key,'reason':'Contract and selected static/advisory checks satisfied' if status=='VERIFIED' else '; '.join(notes) or ('Affected by an enabled advisory' if known_vulns or advisory.get('vulnerabilities') else 'Observed behavior violates task capability contract'),'uncertainty':notes,'escalation_reason':'Security-sensitive predicate reaches sensitive sink' if static['triggers'] else 'No supported high-risk trigger found; no deep run required'})
        if status=='VERIFIED':store.cache_put(key,record)
        nodes.append(record);statuses.append(status);uncertain+=notes
    status='REJECTED' if 'REJECTED' in statuses else 'UNRESOLVED' if 'UNRESOLVED' in statuses or uncertain else 'VERIFIED'
    return status,{'nodes':nodes,'dependency_tree':{'nodes':[{'id':n['name'],'version':n['version']} for n in locked],'edges':lock.get('edges',[])},'reason':'; '.join(uncertain) if uncertain else ('One or more dependencies violate the capability contract' if status=='REJECTED' else 'All locked dependency nodes verified within the declared model'),'total_ms':round((time.perf_counter()-start)*1000,2)},uncertain+['Selected Python source/capability model; does not prove arbitrary package safety']
