from pathlib import Path
from types import SimpleNamespace
import pytest
from backend.cavr.analyzer import analyze as cavr
from backend.cavr.ast_scan import rule_scan as scan
from backend.sable.analyzer import analyze as sable
from backend.sable.authorization import evaluate_authorization
from backend.sable.policy_semantics import evaluate as evaluate_policy_semantics
from backend.sable.baselines import _load_models
from backend.sable.hcl_parser import parse as parse_hcl
from backend.satra.analyzer import analyze as satra
from backend.satra.security_contract import build
from backend.satra.test_validator import preflight,killed,judge
from backend.integrations.osv_adapter import OSV
from backend.config import ROOT
from backend.orchestrator.context_service import ContextService
from backend.sable.fixtures.scenarios import SCENARIOS as SABLE_FIXTURES


def test_cavr_safe_cache_and_advisory(service,scenario,tmp_path):
    # PR 1 of docs/cavr-m2-plan.md: the demo's pypdf node is judged by verify_request, on the recorded
    # pypdf 6.21.4 wheel, registry JSON and OSV answer (tests/conftest.py::_offline_demo_runs).
    from test_cavr_support import PIN_SHA256
    r,c=scenario();first=cavr(c,service.store,tmp_path/'first',lambda *a:None);second=cavr(c,service.store,tmp_path/'second',lambda *a:None)
    node=first[1]['nodes'][0]
    assert first[0]=='VERIFIED' and (node['engine'],node['name'],node['version'])==('pipeline','pypdf','6.21.4')
    assert node['sha256']==PIN_SHA256 and node['cache']['lookup']=='MISS' and node['cache']['stored']
    (advisory,)=node['advisories'];assert advisory['rule']=='NO_KNOWN_VULNERABILITY' and advisory['response_sha256']
    again=second[1]['nodes'][0]
    assert again['cache_hit'] and again['cache']['lookup']=='HIT' and again['cache']['key']==node['cache']['key']
    assert again['advisories'][0]['response_sha256']==advisory['response_sha256']  # OSV is asked on a hit too
    assert OSV(tmp_path/'empty').query('nonexistent-example','1.0')['available'] is False
    # Revoking a sink rule the contract depends on: the stored VERIFIED is not reused. The contract is worked out
    # again from the new rules first and fails, so no 8-field key exists and the cache is never consulted.
    service.change_threats(record_id='BEH-PROCESS_EXEC',enabled=False)
    new=ContextService(r.candidate_workspace,r.baseline_workspace,service.threats.snapshot())
    status,details,_=cavr(new,service.store,tmp_path/'disabled',lambda *a:None);revoked=details['nodes'][0]
    assert status=='UNRESOLVED' and (revoked['stage'],revoked['rule'])==('contract','CAPABILITY_POLICY_INVALID')
    assert revoked['cache_hit'] is False and revoked['cache']['lookup'] is None and revoked['key_fields'] is None
    assert 'PROCESS_EXEC' in revoked['reason']
    service.change_threats(record_id='BEH-PROCESS_EXEC',enabled=True)
    restored=ContextService(r.candidate_workspace,r.baseline_workspace,service.threats.snapshot())
    status,details,_=cavr(restored,service.store,tmp_path/'restored',lambda *a:None)
    assert status=='VERIFIED' and details['nodes'][0]['cache']['key']==node['cache']['key'] and details['nodes'][0]['cache_hit']

def test_committed_advisory_evidence_is_fresh_on_the_fixed_clock_and_stale_after_max_age():
    # Guards the fixed-clock fix: the frozen clock only moves "now", the 30-day max-age rule still fails closed.
    from tests.conftest import advisory_clock_time,fixed_advisory_clock
    from datetime import timedelta
    fresh=advisory_clock_time()
    with fixed_advisory_clock(fresh):
        answer=OSV().query('pypdf','6.19.0')
    assert answer['available'] and answer['age_days']<=30,answer
    with fixed_advisory_clock(fresh+timedelta(days=30)):
        stale=OSV().query('pypdf','6.19.0')
    assert stale['available'] is False and stale['mode']=='UNAVAILABLE',stale

def test_trigger_and_runtime_normalization():
    # The runtime_monitor half was deleted with the LOCAL lab (CAVR Step M2-18); sandbox_events has its own tests.
    tree=scan({'x.py':"import os,socket\nif os.getenv('CAVR_CANARY_AWS_SECRET'):\n socket.create_connection(('127.0.0.1',18765))\n"})
    assert tree['triggers'][0]['supported'];assert 'TRIG-ENV' in tree['triggers'][0]['rule_ids']

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

def test_context_dependency_use_attribution_and_non_attribution(tmp_path):
    project=tmp_path/'p';baseline=tmp_path/'base';(project/'app').mkdir(parents=True);baseline.mkdir()
    (project/'dependencies.lock.json').write_text('{"packages":[{"name":"pypdf","version":"1.0"}]}')
    (project/'SRS.md').write_text('PDF invoice extraction')
    (project/'app/use.py').write_text('from pypdf import PdfReader\nreader = PdfReader(data)\n')
    (project/'app/other.py').write_text('import unrelated\nunrelated.call()\n')
    ctx=ContextService(project,baseline);attrs=ctx.dependency_context()['dependency_attributions']
    assert len(attrs)==1 and attrs[0]['package']=='pypdf' and attrs[0]['call_site']['expression']=='PdfReader'

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
@pytest.mark.parametrize('binding', [
    'var.protected_bucket',
    '${local.protected_bucket}',
    None,
    ['aws_s3_bucket.data.id'],
    'aws_s3_bucket.other.arn',
])
def test_sable_standalone_evaluator_fails_closed_on_unresolved_bucket_policy_binding(binding):
    model={"resources": {
        "aws_iam_role.app": {"type": "aws_iam_role", "attributes": {"name": "app-role"}},
        "aws_s3_bucket.data": {"type": "aws_s3_bucket", "attributes": {"bucket": "customer-data"}},
        "aws_iam_role_policy.valid": {"type": "aws_iam_role_policy", "attributes": {
            "role": "aws_iam_role.app.id", "policy": {"Statement": [{"Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"], "Resource": ["arn:aws:s3:::customer-data/*"]}]}}},
        "aws_s3_bucket_policy.dynamic": {"type": "aws_s3_bucket_policy", "attributes": {
            "bucket": binding, "policy": {"Statement": [{"Effect": "Allow",
                "Action": "s3:*", "Resource": "*"}]}}},
    }}
    result=evaluate_authorization(model, 'aws_iam_role.app', 'aws_s3_bucket.data',
                                  ['s3:GetObject','s3:PutObject'])
    assert not result.known
    assert not result.holds
    assert any('aws_s3_bucket_policy.dynamic: bucket binding unresolved' in item
               for item in result.outside_model)

    # A reference to a different declared bucket is statically unrelated and remains ignorable.
    model['resources']['aws_s3_bucket.other']={"type": "aws_s3_bucket", "attributes": {"bucket": "logs"}}
    model['resources']['aws_s3_bucket_policy.dynamic']['attributes']['bucket']='aws_s3_bucket.other.id'
    unrelated=evaluate_authorization(model, 'aws_iam_role.app', 'aws_s3_bucket.data',
                                     ['s3:GetObject','s3:PutObject'])
    assert unrelated.known and unrelated.holds

def test_sable_standalone_evaluator_does_not_treat_bucket_policy_as_role_grant():
    model={"resources": {
        "aws_iam_role.app": {"type": "aws_iam_role", "attributes": {"name": "app-role"}},
        "aws_s3_bucket.data": {"type": "aws_s3_bucket", "attributes": {"bucket": "customer-data"}},
        "aws_iam_role_policy.valid": {"type": "aws_iam_role_policy", "attributes": {
            "role": "aws_iam_role.app.id", "policy": {"Statement": [{"Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"], "Resource": ["arn:aws:s3:::customer-data/*"]}]}}},
        "aws_s3_bucket_policy.public": {"type": "aws_s3_bucket_policy", "attributes": {
            "bucket": "aws_s3_bucket.data.id", "policy": {"Statement": [{"Effect": "Allow",
                "Principal": "*", "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": ["arn:aws:s3:::customer-data/*"]}]}}},
    }}
    result=evaluate_authorization(model, 'aws_iam_role.app', 'aws_s3_bucket.data',
                                  ['s3:GetObject','s3:PutObject'])
    assert not result.known
    assert not result.holds
    assert any('bucket-policy principal and identity-policy composition are unsupported' in item
               for item in result.outside_model)

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
    ('resource_wildened','REGRESSED'),
    ('privilege_weakened_action','REGRESSED'),
    ('extra_get_action_wildcard','REGRESSED'),
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

def test_sable_standalone_evaluator_rejects_action_wildcard_widening():
    fixture=SABLE_FIXTURES['extra_get_action_wildcard']
    _,candidate,_=_load_models(fixture['baseline_tf'],fixture['candidate_tf'])
    obligation=fixture['obligation']
    result=evaluate_authorization(candidate,obligation['principal'],obligation['protected_asset'],obligation['actions'])
    assert result.known
    assert not result.holds
    assert 's3:Get*' in result.widening

def test_sable_standalone_evaluator_rejects_wildcard_resource_widening():
    fixture=SABLE_FIXTURES['resource_wildened']
    _,candidate,_=_load_models(fixture['baseline_tf'],fixture['candidate_tf'])
    obligation=fixture['obligation']
    result=evaluate_authorization(candidate,obligation['principal'],obligation['protected_asset'],obligation['actions'])
    assert result.known
    assert not result.holds
    assert any(item.startswith('Resource: *') for item in result.widening)
    assert any(item.startswith('Resource: *') for item in result.unexpected_resources)
    assert 'Widening' in result.reason

def test_sable_standalone_evaluator_requires_object_arn_for_object_actions():
    model={"resources": {
        "aws_iam_role.app": {"type": "aws_iam_role", "attributes": {"name": "app-role"}},
        "aws_s3_bucket.data": {"type": "aws_s3_bucket", "attributes": {"bucket": "customer-data"}},
        "aws_iam_role_policy.app": {"type": "aws_iam_role_policy", "attributes": {
            "role": "aws_iam_role.app.id", "policy": {"Statement": [{"Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"], "Resource": ["arn:aws:s3:::customer-data"]}]}}},
    }}
    result=evaluate_authorization(model,'aws_iam_role.app','aws_s3_bucket.data',
                                  ['s3:GetObject','s3:PutObject'])
    assert result.known
    assert not result.holds
    assert not result.misbinding
    assert result.unexpected_resources==['arn:aws:s3:::customer-data']

def test_sable_benchmark_does_not_claim_unmeasured_correspondence_or_evidence_quality():
    from backend.sable.benchmark import _compute_metrics

    measured=_compute_metrics([{'scenario_id':'r','verdict':'REGRESSED','correct':True}],
                              {'r':'REGRESSED'})
    assert measured['n']==1
    assert measured['verdict_accuracy']==1.0
    assert measured['correspondence_accuracy'] is None
    assert measured['evidence_completeness'] is None

def test_satra_scc_and_inconclusive(scenario,service,tmp_path):
    r,c=scenario();assert build(c)['expected_status']==403
    c.srs='No security requirements';assert build(c) is None
    assert satra(c,tmp_path/'satra',lambda *a:None)[0]=='INCONCLUSIVE'
    service.change_threats(record_id='AUTHZ.IDOR.001',enabled=False)
    c=ContextService(r.candidate_workspace,r.baseline_workspace,service.threats.snapshot());assert satra(c,tmp_path/'disabled',lambda *a:None)[0]=='INCONCLUSIVE'

def test_satra_docker_runner_matches_bind_mount_owner():
    import os
    from backend.satra.pytest_runner import container_user_args
    expected=['--user',f'{os.getuid()}:{os.getgid()}'] if os.name=='posix' else []
    assert container_user_args('docker')==expected
    assert container_user_args('podman')==[]

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
