import json
from pathlib import Path
import pytest
from backend.orchestrator.run_context import RunContext,Evidence
from backend.orchestrator.event_router import route
from backend.orchestrator.final_gate import decide
from backend.orchestrator.hashing import digest,snapshot
from backend.orchestrator.context_service import ContextService
from backend.orchestrator.invalidation import invalidate_changed
from backend.integrations.agent_adapter import parse_dependency_command,WorkspaceWatchAdapter,ReplayAdapter


def test_context_evidence_integrity(service,scenario):
    run,ctx=scenario();assert RunContext.model_validate_json(run.model_dump_json())==run
    e=Evidence(run_id=run.run_id,analyzer='CAVR',candidate_snapshot=run.candidate_snapshot,input_hash=ctx.input_hash('CAVR'),status='VERIFIED')
    service.store.put_evidence(e);assert service.store.evidence(run.run_id)[0]['integrity_valid']
    service.store.event(run.run_id,'test.event',{'input':1});assert service.store.verify_chain(run.run_id)
    with service.store.connect() as c:c.execute('UPDATE evidence SET body=? WHERE id=?',(json.dumps({**e.model_dump(),'status':'REJECTED'}),e.evidence_id))
    assert not service.store.evidence(run.run_id)[0]['integrity_valid']

@pytest.mark.parametrize('path,expected',[
 ('requirements.txt',{'CAVR','SATRA'}),('app/security.py',{'CAVR','SATRA'}),('tests/test_security.py',{'SATRA'}),('infra/main.tf',{'SABLE'}),('policy.json',{'CAVR','SATRA','SABLE'}),('README.md',set()),('vendor/package.py',{'CAVR','SATRA'})])
def test_routing(path,expected):assert set(route([path]))==expected

@pytest.mark.parametrize('a,b,c,expected',[
 ('VERIFIED','ACCEPT','PRESERVED','ACCEPT'),('REJECTED','ACCEPT','PRESERVED','BLOCK'),('VERIFIED','REJECT','PRESERVED','BLOCK'),('VERIFIED','ACCEPT','REGRESSED','BLOCK'),('UNRESOLVED','ACCEPT','PRESERVED','REVIEW'),('VERIFIED','INCONCLUSIVE','PRESERVED','REVIEW'),('VERIFIED','RETRY','PRESERVED','REVIEW'),('VERIFIED','ACCEPT','UNKNOWN','REVIEW'),('REJECTED','INCONCLUSIVE','UNKNOWN','BLOCK'),('VERIFIED','ACCEPT','NOT_APPLICABLE','ACCEPT')])
def test_final_matrix(a,b,c,expected):
    evidence=[{'analyzer':m,'status':s,'candidate_snapshot':'s','input_hash':m} for m,s in zip(('CAVR','SATRA','SABLE'),(a,b,c))]
    assert decide(['CAVR','SATRA','SABLE'],evidence,'s',{m:m for m in ('CAVR','SATRA','SABLE')})[0]==expected

@pytest.mark.parametrize('status,expected',[
    ('PRESERVED','ACCEPT'),('NOT_APPLICABLE','ACCEPT'),('REGRESSED','BLOCK'),('UNKNOWN','REVIEW')])
def test_sable_final_gate_statuses(status,expected):
    evidence=[{'analyzer':'SABLE','status':status,'candidate_snapshot':'s','input_hash':'i','integrity_valid':True}]
    assert decide(['SABLE'],evidence,'s',{'SABLE':'i'})[0]==expected

@pytest.mark.parametrize('patch',[
    {'candidate_snapshot':'old'},{'input_hash':'old'},{'integrity_valid':False},{'stale':True}])
def test_sable_final_gate_rejects_untrusted_evidence(patch):
    evidence=[{'analyzer':'SABLE','status':'PRESERVED','candidate_snapshot':'s','input_hash':'i','integrity_valid':True,**patch}]
    assert decide(['SABLE'],evidence,'s',{'SABLE':'i'})[0]=='REVIEW'

@pytest.mark.parametrize('patch',[{'stale':True},{'candidate_snapshot':'old'},{'input_hash':'old'},{'integrity_valid':False}])
def test_gate_refuses_stale(patch):
    e={'analyzer':'CAVR','status':'VERIFIED','candidate_snapshot':'s','input_hash':'i',**patch}
    assert decide(['CAVR'],[e],'s',{'CAVR':'i'})[0]=='REVIEW'

def test_restricted_requires_enforcement():
    e={'analyzer':'CAVR','status':'RESTRICTED','candidate_snapshot':'s','input_hash':'i','details':{'restriction_enforced':False}}
    assert decide(['CAVR'],[e],'s',{'CAVR':'i'})[0]=='REVIEW'
    e['details']['restriction_enforced']=True
    assert decide(['CAVR'],[e],'s',{'CAVR':'i'})[0]=='ACCEPT'
    assert decide([],[],'s',{})[0]=='REVIEW'

def test_invalidation_paths(service,scenario):
    r,c=scenario()
    for m in ('CAVR','SATRA','SABLE'):service.store.put_evidence(Evidence(run_id=r.run_id,analyzer=m,candidate_snapshot=r.candidate_snapshot,input_hash=c.input_hash(m),status='VERIFIED'))
    p=Path(r.candidate_workspace)/'requirements.txt';p.write_text(p.read_text()+'\n# change proposed by SATRA repair\n')
    changed=ContextService(r.candidate_workspace,r.baseline_workspace,service.threats.snapshot())
    assert invalidate_changed(service.store,r,changed,lambda *a:None)==['CAVR','SATRA']
    assert not next(e for e in service.store.evidence(r.run_id) if e['analyzer']=='SABLE')['stale']

def test_watch_and_safe_gateway(tmp_path):
    p=tmp_path/'main.py';p.write_text('x=1');w=WorkspaceWatchAdapter(tmp_path);assert w.poll()==[]
    p.write_text('x=2');assert w.poll()[0]['paths']==['main.py']
    assert parse_dependency_command('python -m pip install pypdf==6.19.0')['packages']==['pypdf==6.19.0']
    with pytest.raises(ValueError):parse_dependency_command('pip install x ; whoami')
    trace=tmp_path/'events.jsonl';trace.write_text(json.dumps({'kind':'file.changed','paths':['main.py']})+'\n')
    assert list(ReplayAdapter(trace).events())[0]['kind']=='file.changed'
