from __future__ import annotations
import asyncio
import json
import os
import sys
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI,HTTPException,Request,UploadFile,File
from fastapi.responses import FileResponse,StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel,Field
from backend.config import ASSETS,DATA,DEMO
from backend.orchestrator.service import Service
from backend.orchestrator.scenarios import catalog
from backend.integrations.tooling import availability

service=Service()
@asynccontextmanager
async def lifespan(app):
    yield
    service.stop.set()
app=FastAPI(title='ASENT assurance API',version='1.0.0',lifespan=lifespan)
from backend.threat_repo.api import router as threat_router
app.include_router(threat_router(service))
from backend.cavr.api import cavr_router
app.include_router(cavr_router)
from backend.satra.api import satra_router
app.include_router(satra_router)
from backend.sable.api import sable_router
app.include_router(sable_router)

@app.middleware('http')
async def local_origin(request:Request,call_next):
    origin=request.headers.get('origin')
    allowed={'http://127.0.0.1:8000','http://localhost:8000','http://127.0.0.1:5173','http://localhost:5173','http://127.0.0.1:4173','http://localhost:4173'}
    if request.method not in ('GET','HEAD','OPTIONS') and origin and origin not in allowed:
        from fastapi.responses import JSONResponse
        return JSONResponse({'detail':'Untrusted origin'},status_code=403)
    return await call_next(request)

class Intake(BaseModel):
    scenario:str='safe'
    repository:str | None=None
    srs:str | None=Field(default=None,max_length=200000)
    plan:str | None=Field(default=None,max_length=100000)
    policy:dict | None=None
    mode:str='manual'
    agent_metadata:dict=Field(default_factory=dict)
    auto_repair:bool=False
class Revision(BaseModel):scenario:str
class Command(BaseModel):command:str=Field(max_length=4000)
class Event(BaseModel):kind:str;paths:list[str]=Field(default_factory=list);metadata:dict=Field(default_factory=dict)

class ReplayInput(BaseModel):
    bundle:str
    auto_repair:bool=False

@app.post('/api/replay',status_code=202)
def replay(body:ReplayInput):
    from backend.integrations.replay import prepare,execute
    try:
        run,events=prepare(service,body.bundle)
        threading.Thread(target=execute,args=(service,run,events,body.auto_repair),daemon=True).start()
        return run.model_dump(mode='json')
    except (ValueError,KeyError,FileNotFoundError) as e:raise HTTPException(400,str(e))

@app.post('/api/intake/document')
async def intake_document(file:UploadFile=File(...)):
    from backend.integrations.document_intake import extract_document
    import subprocess
    content=await file.read(5*1024*1024+1)
    try:return await asyncio.to_thread(extract_document,file.filename or '',content)
    except (ValueError,subprocess.TimeoutExpired) as e:raise HTTPException(422,str(e))

@app.get('/api/health')
def health():return {'status':'ok','version':'1.0.0','database':str(service.store.path)}
@app.get('/api/capabilities')
def capabilities():return {'tools':availability(),'supported':{'CAVR':'Python wheels + pinned inert Python lab; npm requests fail closed','SATRA':'InvoiceHub FastAPI authentication/ownership/admin/upload subset','SABLE':'Local Terraform modules, S3 and inline IAM role policies'},'sandbox_notice':'External or modified code requires Docker/Podman. Without it only hash-pinned inert fixtures execute.'}
@app.get('/api/scenarios')
def scenarios():return catalog()
@app.get('/api/project')
def project():return {'name':'InvoiceHub','repository':str(DEMO),'srs':(DEMO/'SRS.md').read_text(),'plan':(DEMO/'plan.md').read_text(),'policy':json.loads((DEMO/'policy.json').read_text())}
@app.get('/api/runs')
def runs():return service.store.runs()
@app.post('/api/runs',status_code=202)
def create(body:Intake):
    try:
        r=service.create(body.scenario,body.repository,body.srs,body.plan,body.policy,body.mode,body.agent_metadata)
        service.start(r.run_id,body.auto_repair)
        if body.mode=='watch':service.watch(r.run_id,body.repository)
        return r.model_dump(mode='json')
    except Exception as e:raise HTTPException(400,str(e))
@app.get('/api/runs/{rid}')
def run(rid:str):
    try:return service.current_run(rid).model_dump(mode='json')
    except KeyError:raise HTTPException(404,'Run not found')
@app.get('/api/runs/{rid}/evidence')
def evidence(rid:str):run(rid);return service.store.evidence(rid)
@app.get('/api/runs/{rid}/events')
def events(rid:str,after:int=0):run(rid);return service.store.events(rid,after)
@app.get('/api/runs/{rid}/stream')
async def stream(rid:str,request:Request,after:int=0):
    run(rid)
    async def messages():
        cursor=max(after,int(request.headers.get('last-event-id','0')))
        while not await request.is_disconnected():
            pending=service.store.events(rid,cursor)
            for event in pending:
                cursor=event['id'];yield f'id: {cursor}\ndata: {json.dumps(event)}\n\n'
            if not pending:yield ': heartbeat\n\n'
            await asyncio.sleep(.5)
    return StreamingResponse(messages(),media_type='text/event-stream',headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})
@app.post('/api/runs/{rid}/rerun',status_code=202)
def rerun(rid:str,repair:bool=False):run(rid);service.start(rid,repair);return {'queued':True}
@app.post('/api/runs/{rid}/revise',status_code=202)
def revise(rid:str,body:Revision):
    try:r=service.revise(rid,body.scenario);service.start(rid);return r.model_dump(mode='json')
    except (ValueError,KeyError) as e:raise HTTPException(409,str(e))
@app.post('/api/runs/{rid}/dependency')
def dependency(rid:str,body:Command):
    try:return service.dependency_event(rid,body.command)
    except (ValueError,KeyError) as e:raise HTTPException(400,str(e))
@app.post('/api/runs/{rid}/events',status_code=202)
def ingest(rid:str,body:Event):
    run(rid)
    if body.kind not in ('file.changed','task.registered','dependency.intercepted'):raise HTTPException(400,'Unsupported event')
    service.store.event(rid,body.kind,{'paths':body.paths,'metadata':body.metadata,'authority':'sensor only; meaning read from candidate files'})
    service.start(rid);return {'queued':True}
@app.get('/api/runs/{rid}/report')
def report(rid:str):run(rid);return service.report(rid)
@app.get('/api/runs/{rid}/report/download')
def download(rid:str):
    run(rid);data=json.dumps(service.report(rid),indent=2)
    return StreamingResponse(iter([data]),media_type='application/json',headers={'Content-Disposition':f'attachment; filename="ASENT_{rid}_assurance.json"'})
@app.get('/api/experiments')
def experiments():return service.store.experiments()
@app.get('/api/runs/{rid}/artifact')
def artifact(rid:str,path:str):
    run(rid);root=(service.root/'evidence'/rid).resolve();f=Path(path).resolve()
    if not f.is_relative_to(root) or not f.is_file():raise HTTPException(404,'Artifact not in run evidence directory')
    return FileResponse(f)

# The showcase app uses only the immutable supplied baseline. Untrusted candidates are never mounted.
sys.path.insert(0,str(DEMO))
from app.main import create_app
app.mount('/invoicehub',create_app(DATA/'invoicehub-demo',seed=True))
if (ASSETS/'frontend/dist').is_dir():app.mount('/',StaticFiles(directory=ASSETS/'frontend/dist',html=True),name='dashboard')
