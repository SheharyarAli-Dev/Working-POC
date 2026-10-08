from __future__ import annotations
import json
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor,as_completed
from pathlib import Path
from backend.config import DATA,ROOT
from backend.db.storage import Store
from backend.orchestrator.run_context import RunContext,Evidence
from backend.orchestrator.hashing import digest,manifest,snapshot,changed,copy_tree,files
from backend.orchestrator.context_service import ContextService
from backend.orchestrator.workspace_manager import WorkspaceManager
from backend.orchestrator.evidence_bus import EvidenceBus
from backend.orchestrator.event_router import route
from backend.orchestrator.invalidation import invalidate_changed
from backend.orchestrator.final_gate import decide
from backend.orchestrator.scenarios import catalog,apply_scenario,replace_lab
from backend.integrations.git_adapter import git,diff
from backend.integrations.agent_adapter import WorkspaceWatchAdapter,parse_dependency_command
from backend.cavr import analyzer as cavr
from backend.cavr.sandbox import run_counterfactual
from backend.cavr.policy import verify_runtime
from backend.satra import analyzer as satra
from backend.sable import analyzer as sable
from backend.satra.repair import propose
from backend.cavr.repair import rank_repairs
from backend.threat_repo.repository import ThreatRepository
from backend.threat_repo.provenance import explanation

class Service:
    def __init__(self,root=DATA):
        self.root=Path(root).resolve();self.store=Store(self.root);self.workspaces=WorkspaceManager(self.root/'workspaces')
        self.locks={};self.guard=threading.Lock();self.watchers={};self.stop=threading.Event()
        self.knowledge_guard=threading.RLock();self.threats=ThreatRepository(self.root/'threat-repository.sqlite3')
        # A restarted process must never show an interrupted RUNNING run as completed.
        for body in self.store.runs(limit=None):
            if body['lifecycle'] in ('ANALYZING','REPAIRING'):
                r=RunContext(**body);r.lifecycle='INTERRUPTED';r.final_decision='REVIEW';r.reasons=['Backend restarted; rerun required'];self.store.save_run(r)
    def create(self,scenario='safe',source=None,srs=None,plan=None,policy=None,mode='manual',agent_metadata=None):
        item=next((s for s in catalog() if s['id']==scenario),None)
        if not item:raise ValueError('Unknown scenario')
        if source:
            source=Path(source).expanduser().resolve()
            if not source.is_dir():raise ValueError('Repository directory does not exist')
        label='LIVE WORKSPACE RUN' if source and mode=='watch' else 'PUBLISHED / RESEARCH CASE' if source and mode=='research' else ('MANUAL WORKSPACE' if source else item['source'])
        run=RunContext(scenario=scenario,title=item['title'],mode=mode,evidence_source=label,agent_metadata=agent_metadata or {})
        candidate=self.workspaces.create(run,source)
        if not source:apply_scenario(candidate,scenario)
        if srs is not None:(candidate/'SRS.md').write_text(srs)
        if plan is not None:(candidate/'plan.md').write_text(plan)
        if policy is not None:(candidate/'policy.json').write_text(json.dumps(policy,indent=2))
        run.candidate_snapshot=snapshot(candidate)
        self.store.save_run(run);bus=EvidenceBus(self.store,run)
        bus.emit('run.created',{'scenario':scenario,'source':label,'baseline_commit':run.baseline_commit,'candidate_workspace':str(candidate)})
        self.store.experiment({'experiment_id':run.run_id,'scenario':scenario,'srs_hash':digest((candidate/'SRS.md').read_text()) if (candidate/'SRS.md').exists() else None,'agent_metadata':run.agent_metadata,'candidate_hash':run.candidate_snapshot,'baseline_commit':run.baseline_commit,'evidence_source':label,'ground_truth':item.get('ground_truth') if not source else None,'expected_module_applicability':ContextService(candidate,run.baseline_workspace,self.threats.snapshot()).applicability(),'package_hashes':[{k:n.get(k) for k in ('name','version','sha256','ecosystem')} for n in json.loads((candidate/'dependencies.lock.json').read_text()).get('packages',[])] if (candidate/'dependencies.lock.json').exists() else [],'recorded_trace':run.agent_metadata.get('recorded_trace')})
        return run
    def start(self,rid,auto_repair=False):
        thread=threading.Thread(target=self.analyze,args=(rid,auto_repair),daemon=True);thread.start();return thread
    def _module(self,module,context,run,bus,label='analysis'):
        started=time.perf_counter();out=self.root/'evidence'/run.run_id/(str(run.revision)+'-'+label+'-'+module)
        bus.emit('module.started',{'module':module,'candidate_snapshot':run.candidate_snapshot,'input_hash':context.input_hash(module)})
        try:
            if module=='CAVR':status,details,uncertainty=cavr.analyze(context,self.store,out,bus.emit)
            elif module=='SATRA':status,details,uncertainty=satra.analyze(context,out,bus.emit)
            else:status,details,uncertainty=sable.analyze(context,bus.emit)
        except Exception as e:
            status={'CAVR':'UNRESOLVED','SATRA':'INCONCLUSIVE','SABLE':'UNKNOWN'}[module];details={'reason':type(e).__name__+': '+str(e)};uncertainty=['Analyzer could not finish']
        details['knowledge']=explanation(context.knowledge,module)
        return Evidence(run_id=run.run_id,analyzer=module,threat_repo_version=context.knowledge['version'],threat_repo_digest=context.knowledge['digest'],threat_module_digest=context.knowledge['module_digests'][module],candidate_snapshot=run.candidate_snapshot,input_hash=context.input_hash(module),status=status,blocking=status in ('REJECTED','REJECT','REGRESSED'),residual_uncertainty=uncertainty,affected_files=[k for k in context.inputs(module) if not k.startswith('@')],evidence_refs=[str(out)],details=details,duration_ms=round((time.perf_counter()-started)*1000,2))
    def analyze(self,rid,auto_repair=False):
        with self.guard:lock=self.locks.setdefault(rid,threading.Lock())
        if not lock.acquire(blocking=False):return
        try:
            run=self.store.run(rid);bus=EvidenceBus(self.store,run)
            for attempt in range(3):
                run.revision+=1;run.lifecycle='ANALYZING';run.final_decision='REVIEW';run.clean_commit=None;run.clean_workspace=None;run.error=None
                run.reasons=['Candidate frozen; waiting for current evidence'];self.store.save_run(run)
                bus.emit('final_gate.changed',{'decision':'REVIEW','reasons':run.reasons})
                frozen,sha=self.workspaces.freeze(run);run.candidate_snapshot=sha;context=ContextService(frozen,run.baseline_workspace,self.threats.snapshot())
                run.threat_repo_version=context.knowledge['version'];run.threat_repo_digest=context.knowledge['digest']
                run.srs_digest=digest(context.srs);run.approved_plan_digest=digest(context.plan);run.policy_digest=digest(context.policy)
                run.applicable=context.applicability();paths=changed(manifest(run.baseline_workspace),context.manifest);run.changed_surfaces=route(paths)
                delta=diff(run.candidate_workspace,run.baseline_commit)
                bus.emit('workspace.snapshot',{'hash':sha,'revision':run.revision,'files':len(context.manifest),'baseline_commit':run.baseline_commit,'git_diff':delta[:40000]})
                bus.emit('file.changed',{'paths':paths,'routing':run.changed_surfaces})
                invalid=invalidate_changed(self.store,run,context,bus.emit)
                previous=self.store.evidence(rid);todo=[]
                for m in run.applicable:
                    valid=[e for e in previous if e['analyzer']==m and not e['stale'] and e['integrity_valid'] and e['input_hash']==context.input_hash(m)]
                    if valid:
                        old=valid[-1];data={k:v for k,v in old.items() if k in Evidence.model_fields and k not in ('evidence_id','created_at')}
                        data.update(candidate_snapshot=sha,reused_from=old['evidence_id'],duration_ms=0)
                        reused=Evidence(**data);bus.publish(reused)
                        bus.emit('evidence.revalidated',{'module':m,'reused_from':old['evidence_id'],'new_snapshot':sha,'reason':'Relevant module inputs are byte-identical'})
                    else:
                        todo.append(m)
                        if m in invalid:bus.emit('module.rerun',{'module':m,'reason':'Relevant inputs changed'})
                self.store.save_run(run)
                with ThreadPoolExecutor(max_workers=3) as pool:
                    futures={pool.submit(self._module,m,context,run,bus):m for m in todo}
                    for f in as_completed(futures):bus.publish(f.result());self.store.save_run(run)
                if snapshot(run.candidate_workspace)!=sha:
                    bus.emit('workspace.concurrent_change',{'reason':'Live candidate changed during analysis; capture again'})
                    if attempt<2:continue
                    run.final_decision='REVIEW';run.reasons=['Workspace kept changing; freeze and rerun'];break
                with self.knowledge_guard:
                    current_knowledge=self.threats.snapshot()
                    changed_knowledge=[m for m in run.applicable if current_knowledge['module_digests'][m]!=context.knowledge['module_digests'][m]]
                    if changed_knowledge:
                        bus.emit('threat_repo.concurrent_change',{'modules':changed_knowledge,'old_version':context.knowledge['version'],'new_version':current_knowledge['version']})
                        if attempt<2:continue
                        for e in self.store.evidence(rid):
                            if e['analyzer'] in changed_knowledge:self.store.invalidate(e['evidence_id'])
                        run.final_decision='REVIEW';run.reasons=['Threat knowledge changed during analysis; rerun required'];break
                    decision,reasons,states=decide(run.applicable,self.store.evidence(rid),sha,{m:context.input_hash(m) for m in run.applicable})
                    run.final_decision=decision;run.reasons=reasons
                    bus.emit('final_gate.changed',{'decision':decision,'reasons':reasons,'statuses':states,'snapshot':sha});self.store.save_run(run)
                    if decision=='ACCEPT':
                        commit=self.workspaces.reconstruct(run);bus.emit('commit.accepted',{'commit':commit,'snapshot':sha,'workspace':run.clean_workspace,'reconstruction':'fresh Git clone + exact verified files; no sandbox promoted'})
                        run.lifecycle='COMPLETE';self.store.save_run(run)
                if auto_repair and attempt==0 and decision in ('BLOCK','REVIEW'):
                    if self._repair(run,context,bus):continue
                break
            with self.knowledge_guard:
                stored=self.store.run(rid)
                if stored.final_decision=='REVIEW' and run.final_decision=='ACCEPT':run=stored
                run.lifecycle='COMPLETE';self.store.save_run(run)
            report=self.report(rid);folder=self.root/'evidence'/rid;folder.mkdir(exist_ok=True);(folder/'assurance.json').write_text(json.dumps(report,indent=2))
        except Exception as e:
            run=self.store.run(rid);run.lifecycle='ERROR';run.final_decision='REVIEW';run.reasons=['Run could not complete'];run.error=type(e).__name__+': '+str(e);self.store.save_run(run);self.store.event(rid,'run.error',{'reason':run.error})
        finally:lock.release()
    def _repair(self,run,context,bus):
        current={e['analyzer']:e for e in self.store.evidence(run.run_id) if not e['stale']}
        needs=[m for m in ('CAVR','SATRA') if current.get(m,{}).get('status') in ('REJECTED','REJECT')]
        if not needs:return False
        branch=Path(run.candidate_workspace).parent/('repair-'+str(run.revision))
        git(run.baseline_workspace,'worktree','add','-b','repair-'+run.run_id+'-'+str(run.revision),str(branch),run.baseline_commit)
        for p in files(branch):(branch/p).unlink()
        copy_tree(context.path,branch);changed_files=[]
        run.lifecycle='REPAIRING';self.store.save_run(run)
        if 'CAVR' in needs:
            old=next((n for n in current['CAVR']['details'].get('nodes',[]) if n['name']=='invoice-pdf-lab'),None)
            if old:
                # The repository represents exactly one supported migration.
                # Prepare it only in the isolated proposal worktree.
                proposal_changes=replace_lab(branch)
                if proposal_changes:
                    lock=json.loads((branch/'dependencies.lock.json').read_text())
                    candidate=next((x for x in lock['packages'] if x['name']=='invoice-pdf-safe'),None)
                    artifact=Path(candidate['artifact']) if candidate else None
                    identity_ok=bool(candidate and artifact and (branch/artifact).is_file() and digest((branch/artifact).read_bytes())==candidate.get('sha256') and candidate.get('sha256')==digest((ROOT/'scenarios/cavr_controlled/invoice_pdf_safe.py').read_bytes()))
                    changed_files+=proposal_changes
                    bus.emit('cavr.repair_candidate_checked',{'candidate_id':'local-safe-adapter-v1','artifact_identity_valid':identity_ok,'artifact':candidate,'proposal_snapshot':snapshot(branch)})
        if 'SATRA' in needs:
            changed_files+=propose(branch,current['SATRA']);bus.emit('satra.repair_attempt',{'branch':str(branch),'files':changed_files,'source':'bounded deterministic template'})
        if not changed_files:return False
        # Verify all affected application/dependency obligations in isolated proposal before promotion.
        proposal=ContextService(branch,run.baseline_workspace,context.knowledge);results={}
        for m in ('CAVR','SATRA'):
            if m in proposal.applicability():
                proposal_run=run.model_copy(update={'candidate_snapshot':snapshot(branch)})
                results[m]=self._module(m,proposal,proposal_run,bus,'repair-verification')
        functional_ok=False;security_ok=False;fixture_check=None
        if 'CAVR' in needs and artifact_ok:
            candidate_src=branch/'vendor'/'invoice_pdf_safe.py'
            fixture_check=run_counterfactual(candidate_src,branch/'fixtures'/'invoice.pdf',self.root/'evidence'/run.run_id/(str(run.revision)+'-repair-functional'),bus.emit)
            runs=fixture_check.get('runs',[])
            outputs=[r.get('facts',{}).get('functional_text') for r in runs]
            functional_ok=bool(fixture_check.get('available') and len(outputs)==2 and outputs[0] is not None and outputs[0]==outputs[1])
            cnode=next((n for n in results['CAVR'].details.get('nodes',[]) if n.get('name')=='invoice-pdf-safe'),None) if 'CAVR' in results else None
            # Security acceptance uses actual observed events and the inferred
            # capability contract; absence of runtime data is not a pass.
            violations=[]
            if cnode and runs:
                for rr in runs:violations.extend(verify_runtime(cnode.get('contract',{}),rr.get('events',[]),rr.get('facts',{}).get('receiver_payloads')))
            security_ok=bool(cnode and runs and not violations and all(not rr.get('facts',{}).get('canary_received') for rr in runs))
            bus.emit('repair.functional_security_check',{'functional_verified':functional_ok,'security_verified':security_ok,'fixture_result':fixture_check,'violations':violations})
        artifact_ok=any(x['kind']=='cavr.repair_candidate_checked' and x['data'].get('artifact_identity_valid') for x in self.store.events(run.run_id))
        repair_candidates=[{'name':'invoice-pdf-safe','version':'1.0.0','level':3,'api_slice':'extract_invoice_text(bytes) -> str','files_changed':len(set(changed_files)),'candidate_id':'local-safe-adapter-v1'}]
        verified_candidate_ids=['local-safe-adapter-v1'] if artifact_ok and functional_ok and security_ok else []
        ranked=rank_repairs(next((n for n in current.get('CAVR',{}).get('details',{}).get('nodes',[]) if n['name']=='invoice-pdf-lab'),{'name':'invoice-pdf-lab','version':'1.0.0'}),repair_candidates,verified_candidate_ids=verified_candidate_ids) if 'CAVR' in needs else []
        verified=(('CAVR' not in needs) or bool(ranked)) and all(e.status in ('VERIFIED','ACCEPT') for e in results.values())
        bus.emit('repair.ranking',{'selected':ranked[0]['candidate_id'] if ranked else None,'verified_only':True,'verification':{'artifact':artifact_ok,'functional':functional_ok,'security':security_ok}})
        bus.emit('repair.differential_verification',{'before':{m:current[m]['status'] for m in current},'after':{m:e.status for m,e in results.items()},'verified':verified,'changed_files':sorted(set(changed_files)),'evidence':{m:e.model_dump(mode='json') for m,e in results.items()}})
        if not verified:return False
        # Copy only the proposed source state; discard verifier temp workspaces.
        for p in files(run.candidate_workspace):(Path(run.candidate_workspace)/p).unlink()
        copy_tree(branch,run.candidate_workspace)
        bus.emit('repair.applied',{'changed_files':sorted(set(changed_files)),'new_snapshot':snapshot(run.candidate_workspace),'note':'Promotion to candidate only; final trust still awaits fresh applicable evidence'})
        return True
    def revise(self,rid,scenario):
        run=self.store.run(rid)
        if run.lifecycle in ('ANALYZING','REPAIRING'):raise ValueError('Wait for the active snapshot to finish')
        apply_scenario(run.candidate_workspace,scenario)
        run.final_decision='REVIEW';run.clean_commit=None;run.reasons=['Candidate revised; re-verification pending'];self.store.save_run(run)
        self.store.event(rid,'candidate.revised',{'scenario':scenario});return run
    def report(self,rid):
        run=self.current_run(rid);evidence=self.store.evidence(rid)
        events=self.store.events(rid)
        unresolved=[x['data'] for x in events if x['kind'] in ('module.rerun','cavr.monitor_fallback')]
        unresolved.extend(t for e in evidence if e['analyzer']=='CAVR' for n in e.get('details',{}).get('nodes',[]) for t in n.get('static',{}).get('triggers',[]) if not t.get('activation_known'))
        cavr_nodes=[n for e in evidence if e['analyzer']=='CAVR' for n in e.get('details',{}).get('nodes',[])]
        return {'schema':'asent.assurance.v1','run':run.model_dump(mode='json'),'project_candidate_snapshot':run.candidate_snapshot,'evidence':evidence,'evidence_state':[{'evidence_id':e['evidence_id'],'module':e['analyzer'],'snapshot':e['candidate_snapshot'],'stale':e['stale'],'integrity_valid':e['integrity_valid']} for e in evidence],'obligations_evaluated':[{'module':e['analyzer'],'status':e['status'],'candidate_snapshot':e['candidate_snapshot'],'input_hash':e['input_hash'],'stale':e['stale']} for e in evidence],'capability_obligations':[{'package':n.get('name'),'required':n.get('contract',{}).get('required',[]),'denied':n.get('contract',{}).get('denied',[]),'confidence':n.get('contract',{}).get('confidence'),'authority':n.get('contract',{}).get('authority')} for n in cavr_nodes],'dependency_use_attributions':[a for n in cavr_nodes for a in n.get('dependency_use',{}).get('dependency_attributions',[])],'discovered_triggers':[t for n in cavr_nodes for t in n.get('static',{}).get('triggers',[])],'triggered_conditions':[x['data'] for x in events if x['kind']=='cavr.trigger_found'],'exercised_conditions':[x['data'] for x in events if x['kind']=='cavr.counterfactual_started'],'unresolved_conditions':unresolved,'artifact_identifiers':[{'package':n.get('name'),'version':n.get('version'),'sha256':n.get('sha256'),'artifact':n.get('artifact'),'snapshot':e['candidate_snapshot']} for e in evidence if e['analyzer']=='CAVR' for n in e.get('details',{}).get('nodes',[])],'execution_modes':[r.get('execution_modes',r.get('execution_mode')) for n in cavr_nodes if (r:=n.get('runtime'))],'observed_security_events':[ev for n in cavr_nodes for ev in (n.get('runtime') or {}).get('runs',[]) for ev in ev.get('events',[]) if ev.get('type') in ('SECRET_ACCESS','NETWORK_CONNECT')],'causal_evidence':[n.get('causal_graph') for n in cavr_nodes if n.get('causal_graph')],'repair_outcomes':[{'kind':x['kind'],'data':x['data']} for x in events if x['kind'].startswith(('repair.','cavr.repair_'))],'verification_result':run.final_decision,'residual_uncertainty':[u for e in evidence for u in e.get('residual_uncertainty',[])],'threat_repository':{k:v for k,v in self.threats.snapshot().items() if k!='records'},'chain_valid':self.store.verify_chain(rid),'event_count':len(events),'bounded_claim':'Applicable supported obligations only. Source labels distinguish controlled demonstrations from observed agent events. No benchmark superiority or universal safety claim.'}
    def watch(self,rid,source=None):
        if rid in self.watchers:return
        run=self.store.run(rid);path=Path(source or run.candidate_workspace).resolve();adapter=WorkspaceWatchAdapter(path)
        def loop():
            while not self.stop.wait(1.5):
                try:
                    events=adapter.poll()
                    if not events:continue
                    for ev in events:self.store.event(rid,'file.changed',ev)
                    # External repository is copied; never changed by ASENT.
                    if path!=Path(run.candidate_workspace):
                        for f in files(run.candidate_workspace):(Path(run.candidate_workspace)/f).unlink()
                        copy_tree(path,run.candidate_workspace)
                    self.analyze(rid)
                except Exception as e:self.store.event(rid,'watch.error',{'error':str(e)})
        t=threading.Thread(target=loop,daemon=True);self.watchers[rid]=t;t.start()
    def dependency_event(self,rid,command):
        action=parse_dependency_command(command);run=self.store.run(rid)
        self.store.event(rid,'dependency.intercepted',{**action,'execution':'held; gateway never runs arbitrary shell'})
        # A command is a proposal. Only artifacts in the locked candidate may be authorized.
        context=ContextService(run.candidate_workspace,run.baseline_workspace,self.threats.snapshot())
        locked=json.loads(context.read('dependencies.lock.json') or '{"packages":[]}').get('packages',[])
        requested=action['packages'];pins={n['name']+'=='+n['version'] for n in locked}
        supported=action['ecosystem']=='PyPI' and action['action']=='install' and requested and all(x in pins for x in requested)
        self.analyze(rid)
        current=self.store.run(rid);records=[e for e in self.store.evidence(rid) if e['analyzer']=='CAVR' and not e['stale']]
        allowed=bool(supported and records and records[-1]['status']=='VERIFIED' and records[-1]['candidate_snapshot']==snapshot(run.candidate_workspace))
        return {'allowed':allowed,'action':action,'reason':'Exact requested artifacts match current VERIFIED dependency evidence' if allowed else 'Request not exactly pinned/verified in candidate; host execution remains blocked','run_id':rid,'execution':'analysis only; use reconstructed state'}

    def current_run(self,rid):
        with self.knowledge_guard:
            run=self.store.run(rid)
            if run.lifecycle=='COMPLETE':
                context=ContextService(run.candidate_workspace,run.baseline_workspace,self.threats.snapshot())
                invalid=invalidate_changed(self.store,run,context,lambda kind,data:self.store.event(rid,kind,data))
                if invalid or snapshot(run.candidate_workspace)!=run.candidate_snapshot:
                    run.final_decision='REVIEW';run.clean_commit=None;run.clean_workspace=None;run.reasons=['Candidate or relevant threat knowledge changed; fresh verification required']
                    self.store.save_run(run)
            return run

    def change_threats(self,bundle=None,record_id=None,enabled=None,reason='Controlled JSON import'):
        with self.knowledge_guard:
            result=self.threats.enable(record_id,enabled) if record_id is not None else self.threats.import_records(bundle,reason)
            affected=result['affected_modules'];state=result['snapshot'];invalidated=[]
            if not affected:return {**result,'invalidated_evidence':[],'cleared_cache_entries':0}
            cleared=self.store.cache_clear() if 'CAVR' in affected else 0
            for body in self.store.runs(limit=None):
                rid=body['run_id'];items=[e for e in self.store.evidence(rid) if not e['stale'] and e['analyzer'] in affected]
                for e in items:
                    self.store.invalidate(e['evidence_id']);invalidated.append(e['evidence_id'])
                    self.store.event(rid,'evidence.invalidated',{'module':e['analyzer'],'evidence_id':e['evidence_id'],'reason':'Relevant Threat Repository state changed','old_version':e.get('threat_repo_version'),'new_version':state['version'],'changed_rule_ids':result['changed_ids'],'rerun_required':True})
                self.store.event(rid,'threat_repo.changed',{'version':state['version'],'digest':state['digest'],'modules':affected,'changed_rule_ids':result['changed_ids'],'cleared_cache_entries':cleared})
                if items:
                    run=self.store.run(rid);run.final_decision='REVIEW';run.clean_commit=None;run.clean_workspace=None;run.reasons=['Relevant threat knowledge changed; affected modules require fresh verification'];self.store.save_run(run)
                    self.store.event(rid,'final_gate.changed',{'decision':'REVIEW','reasons':run.reasons})
            return {**result,'invalidated_evidence':invalidated,'cleared_cache_entries':cleared}
