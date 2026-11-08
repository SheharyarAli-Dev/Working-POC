"""Final acceptance through a running HTTP server, with retained observed reports."""
import json
import os
import runpy
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import httpx
root=Path(__file__).resolve().parents[2];sys.path.insert(0,str(root));os.chdir(root)
from backend.config import DEMO
from backend.orchestrator.run_context import now
reports=root/'reports';reports.mkdir(exist_ok=True)
results={'checked_at':now(),'checks':{},'runs':{},'external_tools':{}}
with tempfile.TemporaryDirectory(prefix='asent-final-http-') as temp:
    data=Path(temp)/'runtime';env={**os.environ,'ASENT_DATA':str(data)}
    with (reports/'acceptance-server.log').open('w') as log:
        server=subprocess.Popen([sys.executable,'-m','uvicorn','backend.main:app','--host','127.0.0.1','--port','8000'],env=env,stdout=log,stderr=log)
        try:
            with httpx.Client(base_url='http://127.0.0.1:8000',timeout=60,trust_env=False) as c:
                for _ in range(50):
                    try:
                        if c.get('/api/health').status_code==200:break
                    except httpx.HTTPError:pass
                    time.sleep(.2)
                else:raise AssertionError('Backend startup failed')
                results['checks']['backend_start']=True
                assert c.get('/').status_code==200;results['checks']['frontend_served']=True
                results['external_tools']=c.get('/api/capabilities').json()['tools']
                assert (data/'asent.sqlite3').is_file() and (data/'threat-repository.sqlite3').is_file()
                results['checks']['sqlite_initialized']=True
                knowledge=c.get('/api/threat-repository').json()
                assert len(knowledge['records'])>=49 and knowledge['digest'] and knowledge['module_digests']
                results['checks']['versioned_threat_records']=len(knowledge['records'])
                pdf=runpy.run_path('tests/test_document_intake.py')['make_srs_pdf']()
                response=c.post('/api/intake/document',files={'file':('SRS.pdf',pdf,'application/pdf')});assert response.status_code==200,response.text
                srs=response.json()['text'];assert 'FR-03' in srs and 'HTTP 403' in srs
                results['checks']['pdf_srs_intake']=True
                response=c.post('/api/intake/document',files={'file':('SRS.md',(DEMO/'SRS.md').read_bytes())});assert response.status_code==200
                results['checks']['text_srs_intake']=True
                assert c.post('/api/runs',json={'scenario':'safe'},headers={'Origin':'https://untrusted.invalid'}).status_code==403
                def wait(rid,revision=0):
                    deadline=time.monotonic()+160
                    while time.monotonic()<deadline:
                        r=c.get('/api/runs/'+rid);r.raise_for_status();body=r.json()
                        if body['revision']>revision and body['lifecycle'] in ('COMPLETE','ERROR'):return body
                        time.sleep(.2)
                    raise TimeoutError(rid)
                def save(label,run):
                    report=c.get('/api/runs/'+run['run_id']+'/report').json();assert report['chain_valid']
                    (reports/(label+'-assurance.json')).write_text(json.dumps(report,indent=2))
                    results['runs'][label]={'run_id':run['run_id'],'decision':run['final_decision'],'lifecycle':run['lifecycle'],'modules':{e['analyzer']:e['status'] for e in report['evidence'] if not e['stale']},'clean_commit':run['clean_commit'],'candidate_snapshot':run['candidate_snapshot'],'error':run['error']}
                    return report
                for label,case,wanted in [('safe','safe','ACCEPT'),('block','satra_weak','BLOCK'),('review','sable_unknown','REVIEW')]:
                    r=c.post('/api/runs',json={'scenario':case});assert r.status_code==202,r.text
                    run=wait(r.json()['run_id']);assert run['final_decision']==wanted,run
                    report=save(label,run)
                    if label=='safe':safe=run;assert run['clean_commit']
                    if label=='block':assert next(e for e in report['evidence'] if e['analyzer']=='CAVR')['details']['nodes'][0]['cache_hit']
                    print(label,wanted,flush=True)
                results['checks']['cache_hit']=True
                with c.stream('GET','/api/runs/'+safe['run_id']+'/stream') as response:
                    assert response.headers['content-type'].startswith('text/event-stream')
                    for line in response.iter_lines():
                        if line.startswith('data: '):
                            first=json.loads(line[6:]);assert first['kind']=='run.created';results['checks']['sse_stream']=True;break
                result=c.post('/api/threat-repository/records/TRIG-ENV/enabled',json={'enabled':False}).json()
                assert result['invalidated_evidence'] and result['cleared_cache_entries']
                changed=c.get('/api/runs/'+safe['run_id']).json();assert changed['final_decision']=='REVIEW' and changed['clean_commit'] is None
                results['checks']['threat_update_revokes_accept']=True
                stale=c.get('/api/runs/'+safe['run_id']+'/evidence').json();assert any(e['stale'] and e['analyzer']=='CAVR' for e in stale)
                assert not any(e['stale'] and e['analyzer'] in ('SATRA','SABLE') for e in stale)
                results['checks']['selective_invalidation']=True
                c.post('/api/runs/'+safe['run_id']+'/rerun',json={});disabled=wait(safe['run_id'],safe['revision']);assert disabled['final_decision']=='REVIEW'
                c.post('/api/threat-repository/records/TRIG-ENV/enabled',json={'enabled':True})
                c.post('/api/runs/'+safe['run_id']+'/rerun',json={});restored=wait(safe['run_id'],disabled['revision']);assert restored['final_decision']=='ACCEPT'
                save('knowledge-reverified',restored);results['checks']['fresh_reverification']=True
                report=c.get('/api/runs/'+safe['run_id']+'/report/download');assert report.status_code==200 and 'attachment' in report.headers['content-disposition']
                results['checks']['assurance_download']=True
                assert len(c.get('/api/experiments').json())==3;results['checks']['experiments_persisted']=True
                login=c.post('/invoicehub/auth/login',json={'username':'alice','password':'demo-password'});assert login.status_code==200
                auth={'Authorization':'Bearer '+login.json()['access_token']}
                invoice=c.post('/invoicehub/invoices',headers=auth,files={'file':('invoice.pdf',(DEMO/'fixtures/invoice.pdf').read_bytes(),'application/pdf')});assert invoice.status_code==201 and 'Invoice IH-' in invoice.json()['text']
                results['checks']['invoice_pdf_upload']=True
                command=subprocess.run([sys.executable,'-m','backend.cli','--url','http://127.0.0.1:8000','report','--run',safe['run_id']],capture_output=True,text=True,timeout=15)
                assert command.returncode==0 and json.loads(command.stdout)['chain_valid'];results['checks']['cli_report']=True
                # Retain genuine JUnit/traces/envelopes for these executions, never live DB credentials.
                dest=reports/'acceptance-artifacts'
                if dest.exists():shutil.rmtree(dest)
                shutil.copytree(data/'evidence',dest)
        finally:server.terminate();server.wait(timeout=10)
results['all_checks_passed']=all(bool(x) for x in results['checks'].values())
(reports/'acceptance-summary.json').write_text(json.dumps(results,indent=2))
print(json.dumps({'checks':len(results['checks']),'all_passed':results['all_checks_passed']},indent=2))
