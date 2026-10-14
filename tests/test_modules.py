from pathlib import Path
from types import SimpleNamespace
import pytest
from backend.cavr.analyzer import analyze as cavr
from backend.cavr.m2_deep_analyzer import analyze as m2_deep_analysis
from backend.cavr.trigger_discovery import scan
from backend.cavr.runtime_monitor import normalize
from backend.cavr.repair import rank_repairs
from backend.sable.analyzer import analyze as sable
from backend.sable.authorization import evaluate_authorization
from backend.sable.policy_semantics import evaluate as evaluate_policy_semantics
from backend.sable.hcl_parser import parse as parse_hcl
from backend.satra.analyzer import analyze as satra
from backend.satra.security_contract import build
from backend.satra.test_validator import preflight,killed,judge
from backend.integrations.osv_adapter import OSV
from backend.config import ROOT
from backend.orchestrator.context_service import ContextService
from backend.sable.fixtures.scenarios import SCENARIOS as SABLE_FIXTURES


def test_cavr_safe_cache_and_advisory(service,scenario,tmp_path):
    r,c=scenario();first=cavr(c,service.store,tmp_path/'first',lambda *a:None);second=cavr(c,service.store,tmp_path/'second',lambda *a:None)
    assert first[0]=='VERIFIED';assert first[1]['nodes'][0]['metadata']['registry_digest_verified']
    assert second[1]['nodes'][0]['cache_hit'] and second[1]['nodes'][0]['deep_analysis_ms']==0
    assert first[1]['nodes'][0]['osv']['response_sha256']
    assert OSV(tmp_path/'empty').query('nonexistent-example','1.0')['available'] is False
    service.change_threats(record_id='TRIG-ENV',enabled=False)
    new=ContextService(r.candidate_workspace,r.baseline_workspace,service.threats.snapshot());assert cavr(new,service.store,tmp_path/'disabled',lambda *a:None)[0]=='UNRESOLVED'

# M2: the sandbox path. Since plan step 14 it is not on the orchestrator path; it is called directly here.
def test_controlled_dormant_execution(service,scenario,tmp_path):
    r,c=scenario('cavr_canary');status,details,_=m2_deep_analysis(c,service.store,tmp_path/'lab',lambda *a:None)
    node=next(n for n in details['nodes'] if n['name']=='invoice-pdf-lab')
    assert status=='REJECTED',node.get('runtime')
    normal,activated=node['runtime']['runs'];assert normal['exit_code']==activated['exit_code']==0
    # sandbox.py picks the monitor from what the machine has (docker/podman, else strace, else Python audit).
    # Any of them is acceptable, but the monitor must be the one that belongs to the execution mode.
    monitor_for={'PINNED_INERT_LAB_PYTHON_AUDIT':'PYTHON_AUDIT','PINNED_INERT_LAB_STRACE':'strace','docker':'strace','podman':'strace'}
    for run in (normal,activated):
        assert run['execution_mode'] in monitor_for,run['execution_mode']
        assert run['monitor']==monitor_for[run['execution_mode']],(run['execution_mode'],run['monitor'])
    assert normal['facts']['functional_text']==activated['facts']['functional_text']
    assert not normal['facts']['canary_received'] and activated['facts']['canary_received']
    assert not any(e['type']=='SECRET_ACCESS' for e in normal['events'])
    # The connection is observed in every monitor mode (under strace it is a non-blocking connect, -1 EINPROGRESS).
    assert any(e['type']=='NETWORK_CONNECT' for e in activated['events']),(activated['execution_mode'],sorted({e['type'] for e in activated['events']}))
    assert not any(e['type']=='NETWORK_CONNECT' for e in normal['events'])
    assert any(x['causal_confirmed'] for x in node['threat_correlations']),(activated['execution_mode'],node['threat_correlations'])
    assert all('kind' in x for x in node['causal_graph']['nodes'])
    assert all(Path(x['trace_path']).is_file() for x in node['runtime']['runs'])

def test_trigger_and_runtime_normalization():
    tree=scan({'x.py':"import os,socket\nif os.getenv('CAVR_CANARY_AWS_SECRET'):\n socket.create_connection(('127.0.0.1',18765))\n"})
    assert tree['triggers'][0]['supported'];assert 'TRIG-ENV' in tree['triggers'][0]['rule_ids']
    events=normalize('123 openat(AT_FDCWD, "canary.txt", O_WRONLY|O_CREAT, 0666) = 3\n123 openat(AT_FDCWD, "canary.txt", O_RDONLY) = 3')
    assert [e['type'] for e in events]==['FILE_WRITE','SECRET_ACCESS']

def test_trigger_predicates_bounded_and_unsupported_visible():
    tree=scan({'x.py':"""import os, socket
from pathlib import Path
if os.getenv('CAVR_CANARY_AWS_SECRET'):
 socket.create_connection(('127.0.0.1', 18765))
if Path('/tmp/feature.flag').exists():
 socket.create_connection(('127.0.0.1', 18765))
if custom_gate():
 socket.create_connection(('127.0.0.1', 18765))
"""})
    assert len(tree['triggers'])==3
    assert tree['triggers'][0]['activation_known']
    assert any(t['trigger_status']=='unsupported/unresolved' for t in tree['triggers'])
    assert all(t['reachable_sinks'] and t['file']=='x.py' and t['line'] for t in tree['triggers'])

def test_causal_graph_requires_fixture_source_and_sink_evidence():
    from backend.cavr.causal_graph import build
    trigger=[{'predicate':'flag','file':'p.py','line':2}]
    assert not any(e.get('relation')=='fixture-linked source-to-sink' for e in build('p',trigger,[],[])['edges'])
    events=[{'type':'SECRET_ACCESS','resource':'canary.txt','source':'PYTHON_AUDIT'}, {'type':'NETWORK_CONNECT','resource':'127.0.0.1:18765','source':'PYTHON_AUDIT'}]
    graph=build('p',trigger,events,['CAVR_FAKE_SECRET_NOT_A_CREDENTIAL'])
    edge=next(e for e in graph['edges'] if e.get('relation')=='fixture-linked source-to-sink')
    assert 'receiver exact fake-marker equality'==edge['provenance']
    mismatched=build('p',trigger,events,['CAVR_FAKE_SECRET_NOT_A_CREDENTIAL-extra'])
    assert not any(e.get('relation')=='fixture-linked source-to-sink' for e in mismatched['edges'])

def test_context_dependency_use_attribution_and_non_attribution(tmp_path):
    project=tmp_path/'p';baseline=tmp_path/'base';(project/'app').mkdir(parents=True);baseline.mkdir()
    (project/'dependencies.lock.json').write_text('{"packages":[{"name":"pypdf","version":"1.0"}]}')
    (project/'SRS.md').write_text('PDF invoice extraction')
    (project/'app/use.py').write_text('from pypdf import PdfReader\nreader = PdfReader(data)\n')
    (project/'app/other.py').write_text('import unrelated\nunrelated.call()\n')
    ctx=ContextService(project,baseline);attrs=ctx.dependency_context()['dependency_attributions']
    assert len(attrs)==1 and attrs[0]['package']=='pypdf' and attrs[0]['call_site']['expression']=='PdfReader'

def test_repair_constraints():
    current={'name':'x','version':'1.0.0'}
    choices=[{'name':'y','version':'1.0.0','artifact_verified':True,'level':3,'api_slice':'extract(bytes)','candidate_id':'y'},{'name':'x','version':'1.0.1','artifact_verified':True,'candidate_id':'x1'},{'name':'x','version':'1.0.2','artifact_verified':False,'candidate_id':'x2'}]
    ranked=rank_repairs(current,choices,'>=1,<2',verified_candidate_ids=['x1']);assert ranked[0]['version']=='1.0.1';assert len(ranked)==1
    assert not rank_repairs(current,[{'name':'y','version':'1','artifact_verified':True}])
    ranked=rank_repairs(current,[{'name':'safe','version':'1.0.0','level':3,'artifact_verified':True,'functional_verified':True,'security_verified':True,'candidate_id':'safe','api_slice':'extract(bytes)','files_changed':2},{'name':'unsafe','version':'1.0.0','level':3,'artifact_verified':True,'functional_verified':False,'security_verified':False,'candidate_id':'unsafe','api_slice':'extract(bytes)','files_changed':1}],verified_candidate_ids=['safe'])
    assert [x['name'] for x in ranked]==['safe'] and ranked[0]['score']['security_credit']==0

@pytest.mark.parametrize('case,wanted',[('safe','PRESERVED'),('sable_preserved','PRESERVED'),('sable_regressed','REGRESSED'),('sable_unknown','UNKNOWN'),('sable_widened','REGRESSED')])
def test_sable_real_hcl(scenario,case,wanted):
    _,c=scenario(case);status,d,_=sable(c,lambda *a:None);assert status==wanted,d
    assert not d['parse_errors'];assert d['baseline_verification']['holds']
    if wanted in ('PRESERVED','REGRESSED'):assert d['projected_authorization']['known'] is True
    if case=='sable_regressed':assert any(v['local_predicate'] for v in d['candidate_only']) and not d['projected_authorization']['holds']

def test_sable_unknown_parse_and_disabled(scenario,service):
    r,c=scenario();(c.path/'infra/main.tf').write_text('resource "broken" {');assert sable(c,lambda *a:None)[0]=='UNKNOWN'
    service.change_threats(record_id='SABLE-S3IAM-001',enabled=False);c=ContextService(r.candidate_workspace,r.baseline_workspace,service.threats.snapshot())
    status,details,_=sable(c,lambda *a:None)
    assert status=='UNKNOWN' and 'SABLE-S3IAM-001' in details['missing_rules']

def test_sable_unsupported_iam_stays_unknown(scenario):
    _,c=scenario('sable_preserved')
    policy=c.path/'infra/main.tf'
    text=policy.read_text()
    text=text.replace('Action = ["s3:GetObject", "s3:PutObject"], Resource = ["${module.storage.active_arn}/*"]',
                      'Action = ["s3:GetObject", "s3:PutObject"], Condition = { Bool = { "aws:SecureTransport" = "true" } }, Resource = ["${module.storage.active_arn}/*"]')
    policy.write_text(text)
    status,details,_=sable(c,lambda *a:None)
    assert status=='UNKNOWN',details
    assert not details['projected_authorization']['known']

def test_sable_unresolved_role_binding_with_valid_policy_is_unknown(scenario):
    _,c=scenario('sable_preserved')
    main=c.path/'infra/main.tf'
    main.write_text(main.read_text()+'''\nresource "aws_iam_role_policy" "dynamic_extra" {
  role = var.additional_role
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["s3:*"], Resource = ["*"] }]
  })
}
''')
    status,details,_=sable(c,lambda *a:None)
    assert status=='UNKNOWN',details
    authorization=details['projected_authorization']
    assert not authorization['known']
    assert authorization['grants'], 'the known valid policy should still be represented'
    assert any('aws_iam_role_policy.dynamic_extra: role binding unresolved' in item for item in authorization['unknown'])

def test_sable_standalone_evaluator_fails_closed_on_unresolved_role_binding(scenario):
    _,c=scenario('sable_preserved')
    main=c.path/'infra/main.tf'
    main.write_text(main.read_text()+'''\nresource "aws_iam_role_policy" "dynamic_extra" {
  role = var.additional_role
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["s3:*"], Resource = ["*"] }]
  })
}
''')
    model=parse_hcl(c.path/'infra')
    result=evaluate_authorization(
        model,
        'aws_iam_role.app',
        'module.storage.aws_s3_bucket.active_invoices',
        ['s3:GetObject','s3:PutObject'],
    )
    assert not result.known
    assert not result.holds
    assert result.grants, 'the known registered-role policy must remain represented'
    assert any('aws_iam_role_policy.dynamic_extra: role binding unresolved' in item for item in result.outside_model)

def test_sable_standalone_evaluator_fails_closed_on_null_role_binding():
    model={"resources": {
        "aws_iam_role.app": {"type": "aws_iam_role", "attributes": {"name": "app-role"}},
        "aws_s3_bucket.data": {"type": "aws_s3_bucket", "attributes": {"bucket": "customer-data"}},
        "aws_iam_role_policy.valid": {"type": "aws_iam_role_policy", "module": "", "attributes": {
            "role": "aws_iam_role.app.id", "policy": {"Statement": [{"Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"], "Resource": ["arn:aws:s3:::customer-data/*"]}]}}},
        "aws_iam_role_policy.dynamic_extra": {"type": "aws_iam_role_policy", "module": "", "attributes": {
            "role": None, "policy": {"Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": ["*"]}]}}},
    }}
    result=evaluate_authorization(
        model,
        'aws_iam_role.app',
        'aws_s3_bucket.data',
        ['s3:GetObject','s3:PutObject'],
    )
    assert not result.known
    assert not result.holds
    assert result.grants, 'the valid principal policy should remain represented'
    assert any('aws_iam_role_policy.dynamic_extra: role binding unresolved' in item for item in result.outside_model)

@pytest.mark.parametrize('role_binding',['','   '])
def test_empty_role_binding_is_unknown_in_both_evaluators(role_binding):
    model={"resources": {
        "aws_iam_role.app": {"type": "aws_iam_role", "attributes": {"name": "app-role"}},
        "aws_s3_bucket.data": {"type": "aws_s3_bucket", "attributes": {"bucket": "customer-data"}},
        "aws_iam_role_policy.valid": {"type": "aws_iam_role_policy", "module": "", "attributes": {
            "role": "aws_iam_role.app.id", "policy": {"Statement": [{"Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"], "Resource": ["arn:aws:s3:::customer-data/*"]}]}}},
        "aws_iam_role_policy.blank": {"type": "aws_iam_role_policy", "module": "", "attributes": {
            "role": role_binding, "policy": {"Statement": [{"Effect": "Allow",
                "Action": ["s3:*"], "Resource": ["*"]}]}}},
    }}
    shared=evaluate_policy_semantics(model,'aws_iam_role.app','aws_s3_bucket.data',['s3:GetObject','s3:PutObject'])
    standalone=evaluate_authorization(model,'aws_iam_role.app','aws_s3_bucket.data',['s3:GetObject','s3:PutObject'])
    assert not shared['known'] and not shared['holds']
    assert not standalone.known and not standalone.holds
    assert any('role binding unresolved' in message for message in shared['unknown'])
    assert any('role binding unresolved' in message for message in standalone.outside_model)

def test_sable_explicitly_unrelated_role_binding_is_ignored(scenario):
    _,c=scenario('sable_preserved')
    main=c.path/'infra/main.tf'
    main.write_text(main.read_text()+'''\nresource "aws_iam_role" "other" {
  name = "invoicehub-unrelated-role"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }] })
}
resource "aws_iam_role_policy" "other_role" {
  role = aws_iam_role.other.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["s3:*"], Resource = ["*"] }]
  })
}
''')
    status,details,_=sable(c,lambda *a:None)
    assert status=='PRESERVED',details
    standalone=evaluate_authorization(
        parse_hcl(c.path/'infra'),
        'aws_iam_role.app',
        'module.storage.aws_s3_bucket.active_invoices',
        ['s3:GetObject','s3:PutObject'],
    )
    assert standalone.known and standalone.holds

def test_sable_unsupported_terraform_stays_unknown(scenario):
    _,c=scenario('sable_preserved')
    main=c.path/'infra/main.tf'
    main.write_text(main.read_text()+'\nmodule "multi_storage" { source = "./modules/storage" count = 2 }\n')
    status,details,_=sable(c,lambda *a:None)
    assert status=='UNKNOWN',details
    assert any('Module instances need plan expansion' in error for error in details['parse_errors'])

def test_sable_unverified_baseline_and_empty_baseline(scenario):
    r,c=scenario('sable_preserved')
    baseline_policy=Path(r.baseline_workspace)/'infra/main.tf'
    baseline_policy.write_text(baseline_policy.read_text().replace('s3:PutObject','s3:ListBucket'))
    status,details,_=sable(c,lambda *a:None)
    assert status=='UNKNOWN',details
    assert details['baseline_verification']['holds'] is False

    for file in (Path(r.baseline_workspace)/'infra').rglob('*.tf'):
        file.unlink()
    status,details,_=sable(c,lambda *a:None)
    assert status=='UNKNOWN',details
    assert 'baseline' in details['reason'].lower()

@pytest.mark.parametrize('case,wanted',[
    ('rename_with_moved','PRESERVED'),
    ('rename_no_moved','PRESERVED'),
    ('move_into_module','PRESERVED'),
    ('ambiguous_resolved_by_moved','PRESERVED'),
    ('policy_rewrite_wrong_target','REGRESSED'),
    ('privilege_weakened_action','REGRESSED'),
    ('replacement_wrong_bucket','UNKNOWN'),
    ('ambiguous_set_three_candidates','UNKNOWN'),
])
def test_sable_refactor_and_correspondence_cases(tmp_path,scenario,case,wanted):
    _,source=scenario('sable_preserved')
    fixture=SABLE_FIXTURES[case]
    baseline=tmp_path/'baseline'/'infra';candidate=tmp_path/'candidate'/'infra'
    for root,files in ((baseline,fixture['baseline_tf']),(candidate,fixture['candidate_tf'])):
        for relative,content in files.items():
            path=root/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(content)
    obligation=fixture['obligation']
    policy={'infrastructure':{'principal':obligation['principal'],'protected_asset':obligation['protected_asset'],'actions':obligation['actions']}}
    context=SimpleNamespace(path=candidate.parent,baseline=baseline.parent,policy=policy,knowledge=source.knowledge)
    status,details,_=sable(context,lambda *a:None)
    assert status==wanted,details
    if wanted=='PRESERVED':
        assert details['baseline_verification']['holds']
        assert details['successor']
        assert details['projected_authorization']['holds']
    elif wanted=='REGRESSED':
        assert details['successor']
        assert details['projected_authorization']['known']
        assert not details['projected_authorization']['holds']
        if case in ('policy_rewrite_wrong_target','privilege_weakened_action'):
            standalone=evaluate_authorization(
                parse_hcl(candidate),
                obligation['principal'],
                details['successor'],
                obligation['actions'],
            )
            assert standalone.known and not standalone.holds
            if case=='privilege_weakened_action':
                assert 's3:PutObject' in standalone.weakening
    else:
        assert details['successor'] is None

def test_satra_scc_and_inconclusive(scenario,service,tmp_path):
    r,c=scenario();assert build(c)['expected_status']==403
    c.srs='No security requirements';assert build(c) is None
    assert satra(c,tmp_path/'satra',lambda *a:None)[0]=='INCONCLUSIVE'
    service.change_threats(record_id='AUTHZ.IDOR.001',enabled=False)
    c=ContextService(r.candidate_workspace,r.baseline_workspace,service.threats.snapshot());assert satra(c,tmp_path/'disabled',lambda *a:None)[0]=='INCONCLUSIVE'

def test_oracle_validation_rejects_errors():
    assert preflight('def test_x():\n assert True')[0] is False
    assert preflight("import os\ndef test_x():\n assert '/invoices/'")[0] is False
    error={'available':True,'exit_code':1,'failed':1,'errors':0,'tests':[{'status':'FAIL','message':'RuntimeError: failed import'}]}
    assert not killed(error)
    ok={'available':True,'exit_code':0,'passed':1};assert judge(ok,error,ok,True)['diagnosis']=='INCONCLUSIVE'

def test_builtin_fallback_rejects_native_or_unknown_configuration(scenario):
    from backend.satra.pytest_runner import permitted_builtin
    _,c=scenario();assert permitted_builtin(c.path)
    (c.path/'hostile.so').write_bytes(b'not executed')
    assert not permitted_builtin(c.path)
    (c.path/'hostile.so').unlink();(c.path/'pytest.ini').write_text('[pytest]\npythonpath = /other')
    assert not permitted_builtin(c.path)
