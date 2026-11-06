import json
from pathlib import Path
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from backend.threat_repo.api import router
from backend.integrations.replay import prepare,execute
from backend.config import ROOT
from backend.integrations.research_loader import load
from backend.orchestrator.hashing import digest, snapshot


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


@pytest.mark.parametrize('line', ['[]', 'null', '"event"', '42'])
def test_replay_adapter_rejects_non_object_events(tmp_path, line):
    from backend.integrations.agent_adapter import ReplayAdapter
    trace = tmp_path / 'events.jsonl'
    trace.write_text(line + '\n', encoding='utf-8')
    with pytest.raises(ValueError, match='event must be an object'):
        list(ReplayAdapter(trace).events())


@pytest.mark.parametrize('line', [
    '{"writes":{}}',
    '{"kind":null}',
    '{"kind":[]}',
    '{"kind":"unsupported.event"}',
    '{"kind":"file.changed","writes":[]}',
    '{"kind":"file.changed","writes":{"a.txt":null}}',
])
def test_replay_adapter_rejects_malformed_kind_or_writes(tmp_path, line):
    from backend.integrations.agent_adapter import ReplayAdapter
    trace = tmp_path / 'events.jsonl'
    trace.write_text(line + '\n', encoding='utf-8')
    with pytest.raises(ValueError):
        list(ReplayAdapter(trace).events())


def test_replay_event_optional_writes_and_unknown_fields_are_supported(tmp_path):
    from backend.integrations.agent_adapter import ReplayAdapter
    from backend.integrations.replay import _validated_writes
    trace = tmp_path / 'events.jsonl'
    trace.write_text('{"kind":"task.registered","metadata":{"note":"fixture"},"future_field":true}\n', encoding='utf-8')
    events = list(ReplayAdapter(trace).events())
    assert events[0]['future_field'] is True
    assert _validated_writes(events) == [{}]


@pytest.mark.parametrize('events', [
    [
        {'kind':'file.changed','writes':{'first.txt':'would write'}},
        {'kind':'file.changed','writes':[]},
    ],
    [
        {'kind':'file.changed','writes':{'first.txt':'would write'}},
        {'kind':'file.changed','writes':{'../escape.txt':'invalid'}},
    ],
    [
        {'kind':'file.changed','writes':{'first.txt':'would write'}},
        {'kind':'file.changed','writes':{'C:\\escape.txt':'invalid'}},
    ],
    [
        {'kind':'file.changed','writes':{'first.txt':'would write'}},
        {'kind':'file.changed','writes':{'/tmp/escape.txt':'invalid'}},
    ],
    [{'kind':'file.changed','writes':{'dir//./file.txt':'one','dir/file.txt':'two'}}],
    [{'kind':'file.changed','writes':{'same.txt':'one','SAME.txt':'two'}}],
    [
        {'kind':'file.changed','writes':{'prefix':'would write'}},
        {'kind':'file.changed','writes':{'prefix/child.txt':'invalid'}},
    ],
    [
        {'kind':'file.changed','writes':{'prefix/child.txt':'would write'}},
        {'kind':'file.changed','writes':{'prefix':'invalid'}},
    ],
])
def test_execute_rejects_invalid_write_bundle_before_any_write(service, events):
    from backend.integrations.replay import execute
    run = service.create('safe')
    before = snapshot(Path(run.candidate_workspace))
    execute(service, run, events)
    assert snapshot(Path(run.candidate_workspace)) == before
    stored = service.store.run(run.run_id)
    assert stored.final_decision == 'REVIEW'
    assert stored.lifecycle == 'ERROR'


@pytest.mark.parametrize('config', [None, [], {'schema':'asent.replay.v2'}, {'schema':'asent.replay.v1'}])
def test_invalid_or_incomplete_bundle_is_rejected_before_run_creation(service, tmp_path, config):
    bundle = tmp_path / 'bundle.json'
    bundle.write_text(json.dumps(config), encoding='utf-8')
    before = service.store.runs()
    with pytest.raises((ValueError, KeyError)):
        prepare(service, bundle)
    assert service.store.runs() == before


def test_replay_api_returns_400_for_validation_error(monkeypatch):
    import backend.integrations.replay as replay
    from backend.main import app
    monkeypatch.setattr(replay, 'prepare', lambda *_: (_ for _ in ()).throw(ValueError('Invalid replay event')))
    response = TestClient(app).post('/api/replay', json={'bundle':'invalid.json'})
    assert response.status_code == 400
    assert response.json()['detail'] == 'Invalid replay event'

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
