import json
from pathlib import Path
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from backend.threat_repo.api import router
from backend.integrations.replay import prepare,execute
from backend.config import ROOT
from backend.integrations.research_loader import load
from backend.orchestrator.hashing import digest


def test_threat_api_validation_and_export(service):
    app=FastAPI();app.include_router(router(service));client=TestClient(app)
    state=client.get('/api/threat-repository').json();assert state['version']
    response=client.post('/api/threat-repository/records/TRIG-ENV/enabled',json={'enabled':False})
    assert response.status_code==200 and response.json()['affected_modules']==['CAVR']
    bundle=client.get('/api/threat-repository/export');assert 'attachment' in bundle.headers['content-disposition']
    assert client.post('/api/threat-repository/import',json=bundle.json()).status_code==200
    bad={'records':[{'id':'X','category':'behaviors','name':'x','source_id':'missing'}]}
    assert client.post('/api/threat-repository/import',json=bad).status_code==400
    assert client.post('/api/threat-repository/import',json={'records':[],'unexpected':True}).status_code==422
    assert client.post('/api/threat-repository/osv/import',json={'response':{'error':'offline'}}).status_code==400

@pytest.mark.integration
def test_real_recorded_replay(service):
    r,events=prepare(service,ROOT/'scenarios/replay/weak-oracle/bundle.json');execute(service,r,events)
    run=service.store.run(r.run_id);assert run.final_decision=='BLOCK',run.model_dump()
    evidence=[e for e in service.store.evidence(r.run_id) if e['analyzer']=='SATRA'][-1]
    assert evidence['details']['oracle']['diagnosis']=='ORACLE_WEAKENED'
    assert run.evidence_source=='CONTROLLED REPRODUCTION'
    assert any(e['kind']=='replay.loaded' for e in service.store.events(r.run_id))

def test_research_is_explicit_and_local(tmp_path):
    with pytest.raises(ValueError,match='opt-in'):load(tmp_path/'absent.json')

import sys

@pytest.mark.skipif(sys.platform == "win32", reason="Symlinks require POSIX filesystem or Windows Developer Mode")
def test_snapshot_rejects_symlinks_and_cache_tampering(service,tmp_path):
    from backend.orchestrator.hashing import snapshot
    p=tmp_path/'repo';p.mkdir();(p/'app').symlink_to(ROOT/'backend',target_is_directory=True)
    with pytest.raises(ValueError,match='Symlinked'):snapshot(p)
    service.store.cache_put('x',{'status':'VERIFIED'})
    assert service.store.cache_get('x')=={'status':'VERIFIED'}
    with service.store.connect() as c:c.execute('UPDATE cache SET body=? WHERE key=?',(json.dumps({'status':'VERIFIED','_cache_digest':'wrong'}),'x'))
    assert service.store.cache_get('x') is None
