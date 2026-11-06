import copy
import pytest
from backend.threat_repo.repository import ThreatRepository
from backend.threat_repo.osv_importer import records
from backend.threat_repo.package_records import affected,packages,vulnerabilities
from backend.threat_repo.satra_rules import dictionary as satra_dictionary
from backend.orchestrator.context_service import ContextService
from backend.orchestrator.run_context import Evidence

def test_version_history_import_export_atomic(service,tmp_path):
    repo=service.threats;first=repo.snapshot();assert len(first['records'])>=48
    result=repo.enable('TRIG-ENV',False);assert result['affected_modules']==['CAVR'];assert first['digest']!=result['snapshot']['digest']
    assert first['module_digests']['SATRA']==result['snapshot']['module_digests']['SATRA']
    assert len(repo.history())==2
    assert not repo.enable('TRIG-ENV',False)['changed_ids']
    exported=repo.export();replica=ThreatRepository(tmp_path/'replica.db');replica.import_records(exported)
    assert [(r['id'],r['enabled']) for r in replica.snapshot()['records']]==[(r['id'],r['enabled']) for r in repo.snapshot()['records']]
    broken=copy.deepcopy(exported);broken['records'][1]['source_id']='UNREGISTERED'
    prior=repo.snapshot()['digest']
    with pytest.raises(ValueError):repo.import_records(broken)
    assert repo.snapshot()['digest']==prior

def test_knowledge_invalidates_only_relevant(service,scenario):
    r,c=scenario()
    for m in ('CAVR','SATRA','SABLE'):service.store.put_evidence(Evidence(run_id=r.run_id,analyzer=m,candidate_snapshot=r.candidate_snapshot,input_hash=c.input_hash(m),status='VERIFIED',threat_repo_version=c.knowledge['version']))
    service.store.cache_put('old',{'status':'VERIFIED'});service.change_threats(record_id='TRIG-ENV',enabled=False)
    assert service.store.cache_get('old') is None
    assert {e['analyzer'] for e in service.store.evidence(r.run_id) if e['stale']}=={'CAVR'}
    assert service.store.run(r.run_id).final_decision=='REVIEW'
    assert any(e['kind']=='threat_repo.changed' for e in service.store.events(r.run_id))
    current=ContextService(r.candidate_workspace,r.baseline_workspace,service.threats.snapshot())
    assert current.input_hash('SATRA')==c.input_hash('SATRA')
    assert current.input_hash('CAVR')!=c.input_hash('CAVR')

def test_osv_import_ranges_and_provenance(service):
    # Synthetic EXTERNAL ADAPTER INPUT for range semantics, never shipped as a real advisory.
    payload={'id':'TEST-ADVISORY-001','summary':'Unit-test affected range','modified':'2026-01-01T00:00:00Z','affected':[{'package':{'ecosystem':'PyPI','name':'example-test-package'},'ranges':[{'type':'ECOSYSTEM','events':[{'introduced':'1.0'},{'fixed':'2.0'}]}]}]}
    bundle=records(payload);service.change_threats(bundle)
    node={'name':'example-test-package','version':'1.9','ecosystem':'PyPI'}
    hits,unknown=vulnerabilities(service.threats.snapshot(),node);assert len(hits)==1 and not unknown
    assert hits[0]['source_id']=='SRC-OSV' and hits[0]['data']['response_digest']
    node['version']='2.0';assert vulnerabilities(service.threats.snapshot(),node)==([],[])
    assert affected('1.0',{'ranges':[{'type':'GIT','events':[]}]}) is None
    with pytest.raises(ValueError):records({'error':'network failed'})

def test_package_name_is_only_supporting_evidence(service):
    matches=packages(service.threats.snapshot(),{'name':'invoice-pdf-lab','version':'1.0.0','ecosystem':'LOCAL','sha256':'unknown'})
    assert matches and matches[0]['match_strength']=='name metadata only' and matches[0]['automatic_verdict'] is False

def test_genuine_public_advisory_range(service):
    node={'name':'pypdf','version':'6.7.1','ecosystem':'PyPI'}
    matches,unknown=vulnerabilities(service.threats.snapshot(),node)
    assert any(r['data'].get('advisory_id')=='PYSEC-2026-3005' for r in matches)
    assert not unknown
    node['version']='6.19.0';assert vulnerabilities(service.threats.snapshot(),node)==([],[])

def test_satra_adapter_compiles_seeded_invoicehub_rules(service):
    compiled,unsupported=satra_dictionary(service.threats.snapshot())
    expected={'AUTHZ.IDOR.001','AUTHN.001','AUTHZ.ADMIN.001','INPUT.PDF.001'}
    assert {rule['id'] for rule in compiled}==expected
    assert not unsupported
    assert all(rule['implementation']=='executable bounded InvoiceHub template' for rule in compiled)

def test_satra_adapter_still_rejects_disabled_required_rule(service):
    knowledge=service.threats.snapshot()
    knowledge['records']=[
        {**record,'enabled':False} if record['id']=='AUTHZ.IDOR.001' else record
        for record in knowledge['records']
    ]
    compiled,unsupported=satra_dictionary(knowledge)
    assert 'AUTHZ.IDOR.001' in unsupported
    assert 'AUTHZ.IDOR.001' not in {rule['id'] for rule in compiled}
