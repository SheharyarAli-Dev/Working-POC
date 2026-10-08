from pathlib import Path
import pytest
from backend.orchestrator.hashing import snapshot,files
from backend.orchestrator.service import Service
from backend.orchestrator.context_service import ContextService
pytestmark=pytest.mark.integration

def current(svc,run,module):return [e for e in svc.store.evidence(run.run_id) if e['analyzer']==module and not e['stale']][-1]

def test_safe_accepts_exact_clean_reconstruction(integration_runs):
    svc,runs=integration_runs;r=runs['safe'];assert r.final_decision=='ACCEPT',r.model_dump();assert r.clean_commit
    assert snapshot(r.clean_workspace)==r.candidate_snapshot
    assert svc.report(r.run_id)['chain_valid'];assert current(svc,r,'SATRA')['details']['oracle']['accepted']

def test_weak_oracle_is_real_discrimination(integration_runs):
    svc,runs=integration_runs;r=runs['satra_weak'];e=current(svc,r,'SATRA')
    assert r.final_decision=='BLOCK' and e['status']=='REJECT'
    assert e['details']['executions']['ordinary_candidate']['exit_code']==0
    assert e['details']['oracle']['diagnosis']=='ORACLE_WEAKENED'
    assert e['details']['executions']['test_on_counterfactual']['exit_code']==0
    assert e['details']['oracle']['valid_counterfactual']

def test_ownership_regression(integration_runs):
    svc,runs=integration_runs;r=runs['satra_bypass'];e=current(svc,r,'SATRA')
    assert r.final_decision=='BLOCK' and e['status']=='REJECT'
    assert e['details']['executions']['trusted_candidate']['failed']>=2

def test_cavr_repair_invalidates_satra_then_reverifies(integration_runs):
    svc,runs=integration_runs;r=runs['cross_module'];events=svc.store.events(r.run_id)
    assert r.final_decision=='ACCEPT',r.model_dump()
    assert any(e['kind']=='repair.applied' for e in events)
    assert any(e['kind']=='evidence.invalidated' and e['data']['module']=='SATRA' for e in events)
    assert any(e['kind']=='module.rerun' and e['data']['module']=='SATRA' for e in events)
    assert any(e['analyzer']=='CAVR' and e['status']=='REJECTED' and e['stale'] for e in svc.store.evidence(r.run_id))
    assert current(svc,r,'CAVR')['status']=='VERIFIED'
    assert current(svc,r,'SATRA')['candidate_snapshot']==r.candidate_snapshot

def test_satra_repair_differential(integration_runs):
    svc,runs=integration_runs;r=runs['satra_weak'];svc.analyze(r.run_id,auto_repair=True);fresh=svc.store.run(r.run_id)
    assert fresh.final_decision=='ACCEPT',fresh.model_dump()
    assert current(svc,fresh,'SATRA')['details']['oracle']['accepted']

def test_gateway_and_knowledge_revocation(integration_runs):
    svc,runs=integration_runs;r=runs['safe']
    assert svc.dependency_event(r.run_id,'pip install pypdf==6.19.0')['allowed']
    assert not svc.dependency_event(r.run_id,'npm install unknown')['allowed']
    before=len(svc.store.evidence(r.run_id));result=svc.change_threats(record_id='TRIG-ENV',enabled=False)
    assert result['cleared_cache_entries']>0
    assert svc.current_run(r.run_id).final_decision=='REVIEW'
    svc.analyze(r.run_id);assert svc.store.run(r.run_id).final_decision=='REVIEW'
    assert current(svc,r,'CAVR')['status']=='UNRESOLVED'
    svc.change_threats(record_id='TRIG-ENV',enabled=True);svc.analyze(r.run_id)
    assert svc.store.run(r.run_id).final_decision=='ACCEPT'
    assert len(svc.store.evidence(r.run_id))>before

@pytest.mark.parametrize('scenario,status,decision',[
    ('sable_preserved','PRESERVED','ACCEPT'),
    ('sable_regressed','REGRESSED','BLOCK'),
    ('sable_unknown','UNKNOWN','REVIEW'),
])
def test_shared_sable_evidence_drives_final_gate(tmp_path,scenario,status,decision):
    svc=Service(tmp_path/'runtime')
    run=svc.create(scenario)
    # Keep this integration run focused on the shared SABLE path so CI does not
    # need to execute unrelated CAVR/SATRA analyzers.
    candidate=Path(run.candidate_workspace)
    for relative in files(candidate):
        if relative!='policy.json' and not relative.startswith('infra/'):
            (candidate/relative).unlink()
    svc.analyze(run.run_id)
    run=svc.store.run(run.run_id)
    rows=[e for e in svc.store.evidence(run.run_id) if e['analyzer']=='SABLE' and not e['stale']]
    assert rows, 'shared orchestrator did not publish SABLE evidence'
    evidence=rows[-1]
    context=ContextService(run.candidate_workspace,run.baseline_workspace,svc.threats.snapshot())
    assert 'SABLE' in run.applicable
    assert evidence['status']==status
    assert evidence['candidate_snapshot']==run.candidate_snapshot
    assert evidence['input_hash']==context.input_hash('SABLE')
    assert evidence['integrity_valid']
    assert run.final_decision==decision,run.reasons
