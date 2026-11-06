from pathlib import Path
import json
import pytest
import asyncio
from backend.orchestrator.hashing import snapshot,files
from backend.orchestrator.service import Service
from backend.orchestrator.context_service import ContextService
from backend.integrations.git_adapter import diff,init_repo
pytestmark=pytest.mark.integration

def current(svc,run,module):return [e for e in svc.store.evidence(run.run_id) if e['analyzer']==module and not e['stale']][-1]

def test_git_diff_handles_non_utf8_fixture_content(tmp_path):
    repo=tmp_path/'repo';(repo/'fixtures').mkdir(parents=True)
    pdf=repo/'fixtures'/'invoice.pdf'
    pdf.write_bytes(b'%PDF-1.3\r\n%\xe2\xe3\xcf\xd3\r\n')
    baseline=init_repo(repo)
    pdf.unlink()
    output=diff(repo,baseline)
    assert 'fixtures/invoice.pdf' in output

def test_safe_accepts_exact_clean_reconstruction(integration_runs):
    svc,runs=integration_runs;r=runs['safe']
    if r.final_decision!='ACCEPT':
        evidence=current(svc,r,'SATRA');details=evidence['details']
        executions={name:{k:result.get(k) for k in ('available','exit_code','reason','backend','passed','failed','errors','stderr')}|{'tests':[{'name':t.get('name'),'status':t.get('status'),'message':t.get('message','')[:1000]} for t in result.get('tests',[])]} for name,result in details.get('executions',{}).items()}
        pytest.fail('safe integration expected ACCEPT; diagnostics:\n'+json.dumps({'run':{'lifecycle':r.lifecycle,'applicable':r.applicable,'final_decision':r.final_decision,'reasons':r.reasons,'error':r.error},'satra':{'status':evidence['status'],'reason':details.get('reason'),'missing_rules':details.get('missing_rules'),'dictionary_ids':[rule.get('id') for rule in details.get('dictionary',[])],'executions':executions,'oracle':details.get('oracle')}},indent=2,default=str),pytrace=False)
    assert r.clean_commit
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
    locked = json.loads((Path(r.candidate_workspace) / 'dependencies.lock.json').read_text())['packages']
    pypdf_version = next(item['version'] for item in locked if item['name'] == 'pypdf')
    assert not svc.dependency_event(r.run_id, 'pip install pypdf==6.19.0')['allowed']
    assert svc.dependency_event(r.run_id, f'pip install pypdf=={pypdf_version}')['allowed']
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
    ('sable_unresolved_role_binding','UNKNOWN','REVIEW'),
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
    published_evidence=svc.store.evidence(run.run_id)
    rows=[e for e in published_evidence if e['analyzer']=='SABLE' and not e['stale']]
    assert rows, (
        'shared orchestrator did not publish SABLE evidence; '
        f'lifecycle={run.lifecycle!r}; error={run.error!r}; '
        f'applicable={run.applicable!r}; '
        f'emitted_events={svc.store.events(run.run_id)!r}; '
        f'published_evidence={published_evidence!r}'
    )
    evidence=rows[-1]
    context=ContextService(run.candidate_workspace,run.baseline_workspace,svc.threats.snapshot())
    assert 'SABLE' in run.applicable
    assert evidence['status']==status
    assert evidence['candidate_snapshot']==run.candidate_snapshot
    assert evidence['input_hash']==context.input_hash('SABLE')
    assert evidence['integrity_valid']
    assert run.final_decision==decision,run.reasons
    if scenario=='sable_unresolved_role_binding':
        assert run.applicable==['SABLE']
        assert 'SABLE: UNKNOWN' in run.reasons
        assert any('aws_iam_role_policy.dynamic_extra: role binding unresolved' in item for item in evidence['details']['projected_authorization']['unknown'])
        assert evidence['details']['projected_authorization']['grants']

def test_shared_gate_reviews_missing_sable_baseline(tmp_path):
    svc=Service(tmp_path/'runtime')
    run=svc.create('sable_preserved')
    for file in Path(run.baseline_workspace).rglob('*.tf'):
        file.unlink()
    candidate=Path(run.candidate_workspace)
    for relative in files(candidate):
        if relative!='policy.json' and not relative.startswith('infra/'):
            (candidate/relative).unlink()
    svc.analyze(run.run_id)
    run=svc.store.run(run.run_id)
    evidence=[e for e in svc.store.evidence(run.run_id) if e['analyzer']=='SABLE' and not e['stale']][-1]
    assert evidence['status']=='UNKNOWN'
    assert evidence['details']['reason'].startswith('No trusted baseline boundary')
    assert evidence['integrity_valid']
    assert run.final_decision=='REVIEW',run.reasons


def test_sable_unresolved_bucket_policy_binding_reaches_shared_final_gate(tmp_path):
    svc=Service(tmp_path/'runtime')
    run=svc.create('sable_preserved')
    candidate=Path(run.candidate_workspace)
    for relative in files(candidate):
        if relative!='policy.json' and not relative.startswith('infra/'):
            (candidate/relative).unlink()
    main=candidate/'infra/main.tf'
    main.write_text(main.read_text()+'''\nresource "aws_s3_bucket_policy" "dynamic" {
  bucket = var.protected_bucket
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:*", Resource = "*" }]
  })
}
''')
    svc.analyze(run.run_id)
    run=svc.store.run(run.run_id)
    evidence=current(svc,run,'SABLE')
    assert evidence['status']=='UNKNOWN'
    assert evidence['integrity_valid']
    assert evidence['candidate_snapshot']==run.candidate_snapshot
    assert run.final_decision=='REVIEW'
    unknown=evidence['details']['projected_authorization']['unknown']
    assert any('aws_s3_bucket_policy.dynamic' in item for item in unknown)

def test_sable_linked_bucket_policy_keeps_shared_decision_in_review(tmp_path):
    svc=Service(tmp_path/'runtime')
    run=svc.create('sable_preserved')
    candidate=Path(run.candidate_workspace)
    for relative in files(candidate):
        if relative!='policy.json' and not relative.startswith('infra/'):
            (candidate/relative).unlink()
    main=candidate/'infra/main.tf'
    main.write_text(main.read_text()+'''
resource "aws_s3_bucket_policy" "public" {
  bucket = module.storage.aws_s3_bucket.active_invoices.id
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Principal = "*", Action = ["s3:GetObject", "s3:PutObject"], Resource = "${module.storage.active_arn}/*" }]
  })
}
''')
    svc.analyze(run.run_id)
    run=svc.store.run(run.run_id)
    evidence=current(svc,run,'SABLE')
    auth=evidence['details']['projected_authorization']
    assert evidence['status']=='UNKNOWN'
    assert evidence['integrity_valid']
    assert evidence['candidate_snapshot']==run.candidate_snapshot
    assert not auth['known'] and not auth['holds']
    assert any('aws_s3_bucket_policy.public' in item for item in auth['unknown'])
    assert run.final_decision=='REVIEW'
    assert 'SABLE: UNKNOWN' in run.reasons

def test_sable_partial_action_wildcard_is_blocked_by_shared_final_gate(tmp_path):
    svc=Service(tmp_path/'runtime')
    run=svc.create('sable_preserved')
    candidate=Path(run.candidate_workspace)
    for relative in files(candidate):
        if relative!='policy.json' and not relative.startswith('infra/'):
            (candidate/relative).unlink()
    main=candidate/'infra/main.tf'
    original=main.read_text()
    changed=original.replace('Action = ["s3:GetObject", "s3:PutObject"]',
                             'Action = ["s3:Get*", "s3:PutObject"]')
    assert changed!=original, 'fixture must contain the exact baseline action list'
    main.write_text(changed)
    svc.analyze(run.run_id)
    run=svc.store.run(run.run_id)
    evidence=current(svc,run,'SABLE')
    projection=evidence['details']['projected_authorization']
    assert evidence['status']=='REGRESSED'
    assert projection['known'] and not projection['holds']
    assert evidence['integrity_valid']
    assert evidence['candidate_snapshot']==run.candidate_snapshot
    assert run.final_decision=='BLOCK'
    assert 'SABLE: REGRESSED' in run.reasons

def test_sable_object_actions_need_object_arn_in_shared_final_gate(tmp_path):
    svc=Service(tmp_path/'runtime')
    run=svc.create('sable_preserved')
    candidate=Path(run.candidate_workspace)
    for relative in files(candidate):
        if relative!='policy.json' and not relative.startswith('infra/'):
            (candidate/relative).unlink()
    main=candidate/'infra/main.tf'
    original=main.read_text()
    changed=original.replace('Resource = ["${module.storage.active_arn}/*"]',
                             'Resource = "${module.storage.active_arn}"')
    assert changed!=original, 'fixture must contain the object ARN scope'
    main.write_text(changed)
    svc.analyze(run.run_id)
    run=svc.store.run(run.run_id)
    evidence=current(svc,run,'SABLE')
    projection=evidence['details']['projected_authorization']
    assert evidence['status']=='REGRESSED'
    assert projection['known'] and not projection['holds']
    assert evidence['integrity_valid']
    assert evidence['candidate_snapshot']==run.candidate_snapshot
    assert run.final_decision=='BLOCK'
    assert 'SABLE: REGRESSED' in run.reasons

def test_sable_wildcard_resource_is_blocked_by_shared_final_gate(tmp_path):
    svc=Service(tmp_path/'runtime')
    run=svc.create('sable_preserved')
    candidate=Path(run.candidate_workspace)
    for relative in files(candidate):
        if relative!='policy.json' and not relative.startswith('infra/'):
            (candidate/relative).unlink()
    main=candidate/'infra/main.tf'
    original=main.read_text()
    changed=original.replace('Resource = ["${module.storage.active_arn}/*"]', 'Resource = "*"')
    assert changed!=original, 'fixture must contain the exact protected object scope'
    main.write_text(changed)
    svc.analyze(run.run_id)
    run=svc.store.run(run.run_id)
    evidence=current(svc,run,'SABLE')
    projection=evidence['details']['projected_authorization']
    assert evidence['status']=='REGRESSED'
    assert projection['known'] and not projection['holds']
    assert evidence['integrity_valid']
    assert evidence['candidate_snapshot']==run.candidate_snapshot
    assert run.final_decision=='BLOCK'
    assert 'SABLE: REGRESSED' in run.reasons

def test_sable_standalone_pipeline_records_unresolved_bucket_policy_evidence(monkeypatch):
    from backend.sable import api

    scenario=dict(api.SCENARIOS['rename_with_moved'])
    scenario['candidate_tf']=dict(scenario['candidate_tf'])
    scenario['candidate_tf']['dynamic.tf']='''
resource "aws_s3_bucket_policy" "dynamic" {
  bucket = var.protected_bucket
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:*", Resource = "*" }]
  })
}
'''
    obligation=dict(api.OBLIGATION)
    events=[]
    class StorageProbe:
        completed=None
        def complete_run(self,*args):self.completed=args

    storage=StorageProbe()
    monkeypatch.setattr(api,'storage',storage)
    monkeypatch.setattr(api,'availability',lambda:{
        'terraform':{'available':False},'checkov':{'available':False},'trivy':{'available':False}
    })
    monkeypatch.setattr(api,'publish_event',lambda *args:events.append(args))
    run_id='test_standalone_dynamic_bucket_policy_binding'
    asyncio.run(api.execute_sable_pipeline(run_id,scenario,obligation))

    evidence=storage.completed[3]
    assert evidence['verdict']=='UNKNOWN'
    assert evidence['asent_mapping']=='REVIEW'
    assert evidence['candidate_auth']['known'] is False
    assert any('aws_s3_bucket_policy.dynamic: bucket binding unresolved' in item
               for item in evidence['candidate_auth']['outside_model'])
    assert any('aws_s3_bucket_policy.dynamic: bucket binding unresolved' in item
               for item in evidence['residual_uncertainty'])
    assert 'Partially outside model' in evidence['reason']
    decision=next(event[6] for event in events if event[4]=='decision.attributed')
    assert decision['verdict']=='UNKNOWN' and decision['asent_mapping']=='REVIEW'
    assert 'aws_s3_bucket_policy.dynamic: bucket binding unresolved' in decision['uncertainty']
    complete=next(event[6] for event in events if event[4]=='run.complete')
    assert complete['evidence']['decision_hash']==evidence['decision_hash']

def test_sable_standalone_pipeline_surfaces_linked_bucket_policy_uncertainty(monkeypatch):
    from backend.sable import api

    scenario=dict(api.SCENARIOS['rename_with_moved'])
    scenario['candidate_tf']=dict(scenario['candidate_tf'])
    scenario['candidate_tf']['public_policy.tf']='''
resource "aws_s3_bucket_policy" "public" {
  bucket = aws_s3_bucket.cdata.id
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Principal = "*", Action = ["s3:GetObject", "s3:PutObject"], Resource = "arn:aws:s3:::customer-data/*" }]
  })
}
'''
    events=[]
    class StorageProbe:
        completed=None
        def complete_run(self,*args):self.completed=args

    storage=StorageProbe()
    monkeypatch.setattr(api,'storage',storage)
    monkeypatch.setattr(api,'availability',lambda:{
        'terraform':{'available':False},'checkov':{'available':False},'trivy':{'available':False}
    })
    monkeypatch.setattr(api,'publish_event',lambda *args:events.append(args))
    asyncio.run(api.execute_sable_pipeline(
        'test_standalone_linked_bucket_policy',scenario,api.OBLIGATION))

    evidence=storage.completed[3]
    assert evidence['verdict']=='UNKNOWN'
    assert evidence['asent_mapping']=='REVIEW'
    assert evidence['candidate_auth']['known'] is False
    assert any('bucket-policy principal and identity-policy composition are unsupported'
               in item for item in evidence['candidate_auth']['outside_model'])
    assert any('bucket-policy principal and identity-policy composition are unsupported'
               in item for item in evidence['residual_uncertainty'])
    decision=next(event[6] for event in events if event[4]=='decision.attributed')
    assert decision['verdict']=='UNKNOWN' and decision['asent_mapping']=='REVIEW'

def test_sable_standalone_pipeline_blocks_supported_action_wildcard_widening(monkeypatch):
    from backend.sable import api

    events=[]
    class StorageProbe:
        completed=None
        def complete_run(self,*args):self.completed=args

    storage=StorageProbe()
    monkeypatch.setattr(api,'storage',storage)
    monkeypatch.setattr(api,'availability',lambda:{
        'terraform':{'available':False},'checkov':{'available':False},'trivy':{'available':False}
    })
    monkeypatch.setattr(api,'publish_event',lambda *args:events.append(args))
    run_id='test_standalone_action_wildcard_widening'
    asyncio.run(api.execute_sable_pipeline(
        run_id,api.SCENARIOS['extra_get_action_wildcard'],api.OBLIGATION))

    evidence=storage.completed[3]
    assert evidence['verdict']=='REGRESSED'
    assert evidence['asent_mapping']=='BLOCK'
    assert evidence['candidate_auth']['known'] is True
    assert 's3:Get*' in evidence['candidate_auth']['widening']
    assert 'Widening' in evidence['reason']
    decision=next(event[6] for event in events if event[4]=='decision.attributed')
    assert decision['verdict']=='REGRESSED'
    assert decision['asent_mapping']=='BLOCK'
    assert decision['failure_mode']=='widening'

def test_sable_standalone_pipeline_blocks_wildcard_resource_widening(monkeypatch):
    from backend.sable import api

    events=[]
    class StorageProbe:
        completed=None
        def complete_run(self,*args):self.completed=args

    storage=StorageProbe()
    monkeypatch.setattr(api,'storage',storage)
    monkeypatch.setattr(api,'availability',lambda:{
        'terraform':{'available':False},'checkov':{'available':False},'trivy':{'available':False}
    })
    monkeypatch.setattr(api,'publish_event',lambda *args:events.append(args))
    run_id='test_standalone_resource_wildcard_widening'
    asyncio.run(api.execute_sable_pipeline(
        run_id,api.SCENARIOS['resource_wildened'],api.OBLIGATION))

    evidence=storage.completed[3]
    assert evidence['verdict']=='REGRESSED'
    assert evidence['asent_mapping']=='BLOCK'
    assert any(item.startswith('Resource: *') for item in evidence['candidate_auth']['widening'])
    assert any(item.startswith('Resource: *') for item in evidence['candidate_auth']['unexpected_resources'])
    decision=next(event[6] for event in events if event[4]=='decision.attributed')
    assert decision['verdict']=='REGRESSED'
    assert decision['asent_mapping']=='BLOCK'
    assert decision['failure_mode']=='widening'

def test_sable_standalone_pipeline_rejects_bucket_arn_for_object_actions(monkeypatch):
    from backend.sable import api

    scenario=dict(api.SCENARIOS['rename_with_moved'])
    scenario['candidate_tf']=dict(scenario['candidate_tf'])
    original=scenario['candidate_tf']['main.tf']
    changed=original.replace('Resource = "${aws_s3_bucket.cdata.arn}/*"',
                             'Resource = "${aws_s3_bucket.cdata.arn}"')
    assert changed!=original
    scenario['candidate_tf']['main.tf']=changed
    events=[]
    class StorageProbe:
        completed=None
        def complete_run(self,*args):self.completed=args

    storage=StorageProbe()
    monkeypatch.setattr(api,'storage',storage)
    monkeypatch.setattr(api,'availability',lambda:{
        'terraform':{'available':False},'checkov':{'available':False},'trivy':{'available':False}
    })
    monkeypatch.setattr(api,'publish_event',lambda *args:events.append(args))
    run_id='test_standalone_bucket_arn_for_object_actions'
    asyncio.run(api.execute_sable_pipeline(run_id,scenario,api.OBLIGATION))

    evidence=storage.completed[3]
    assert evidence['verdict']=='REGRESSED'
    assert evidence['asent_mapping']=='BLOCK'
    assert evidence['candidate_auth']['known'] is True
    assert evidence['candidate_auth']['unexpected_resources']==['${aws_s3_bucket.cdata.arn}']
    assert 'wrong resource' in evidence['reason']
    decision=next(event[6] for event in events if event[4]=='decision.attributed')
    assert decision['verdict']=='REGRESSED'
    assert decision['asent_mapping']=='BLOCK'
    projection=next(event[6] for event in events if event[4]=='projection.complete')
    assert projection['candidate_auth']['unexpected_resources']==['${aws_s3_bucket.cdata.arn}']
