"""Replay recorded file writes into an isolated candidate; never execute trace commands."""
import json
import ntpath
from pathlib import Path
from pathlib import PureWindowsPath
from backend.orchestrator.hashing import digest,files,snapshot
from backend.integrations.agent_adapter import ReplayAdapter

_REPLAY_EVENT_KINDS = {'file.changed','dependency.intercepted','task.registered'}

def _validated_writes(events, baseline_paths=()):
    prepared=[]
    names=set(baseline_paths)
    for event in events:
        if not isinstance(event,dict) or not isinstance(event.get('kind'),str) or event['kind'] not in _REPLAY_EVENT_KINDS:
            raise ValueError('Unsupported replay event')
        writes=event.get('writes',{})
        if not isinstance(writes,dict):raise ValueError('Replay writes must be an object')
        clean={}
        for raw,text in writes.items():
            if not isinstance(raw,str) or not raw or '\x00' in raw or not isinstance(text,str) or len(text)>2_000_000:
                raise ValueError('Unsupported replay write')
            slash=raw.replace('\\','/')
            drive,_=ntpath.splitdrive(raw)
            if slash.startswith('/') or drive or PureWindowsPath(raw).is_absolute():
                raise ValueError('Replay write path must be relative')
            parts=slash.split('/')
            if any(part=='..' for part in parts):raise ValueError('Replay write path traversal is not allowed')
            parts=[part for part in parts if part not in ('','.')]
            if not parts:raise ValueError('Invalid replay write path')
            reserved={'CON','PRN','AUX','NUL',*(f'COM{i}' for i in range(1,10)),*(f'LPT{i}' for i in range(1,10))}
            if any(':' in part or part.endswith((' ','.')) or part.split('.',1)[0].upper() in reserved for part in parts):
                raise ValueError('Replay write path is not portable')
            name='/'.join(parts)
            if parts[0].casefold() in {'.git','.venv','node_modules'}:raise ValueError('Unsupported replay write')
            if name in clean:raise ValueError('Replay event contains duplicate normalized write paths')
            collision=next((old for old in names if old.casefold()==name.casefold() and old!=name),None)
            if collision:raise ValueError('Replay writes contain case-fold-colliding paths')
            names.add(name)
            clean[name]=text
        prepared.append(clean)
    folded={name.casefold() for name in names}
    for name in folded:
        parts=name.split('/')
        if any('/'.join(parts[:index]) in folded for index in range(1,len(parts))):
            raise ValueError('Replay writes contain a file/directory path conflict')
    return prepared

def prepare(service,bundle):
    path=Path(bundle).expanduser().resolve();config=json.loads(path.read_text())
    if not isinstance(config,dict):raise ValueError('Replay bundle must be an object')
    if config.get('schema')!='asent.replay.v1':raise ValueError('Unsupported replay bundle')
    repo=(path.parent/config['repository']).resolve();trace=(path.parent/config['events']).resolve()
    if not repo.is_relative_to(path.parent) or not trace.is_relative_to(path.parent):raise ValueError('Replay inputs must be inside bundle folder')
    if snapshot(repo)!=config['initial_snapshot_sha256'] or digest(trace.read_bytes())!=config['trace_sha256']:raise ValueError('Replay input digest mismatch')
    events=list(ReplayAdapter(trace).events())
    if len(events)>100:raise ValueError('Replay event budget exceeded')
    prepared=_validated_writes(events,files(repo))
    events=[{**event,'writes':writes} for event,writes in zip(events,prepared)]
    metadata={**config.get('agent_metadata',{}),'trace_sha256':config['trace_sha256'],'recorded_trace':str(trace),'provenance':config.get('provenance','user-supplied; agent identity unverified')}
    run=service.create(source=repo,mode='replay',agent_metadata=metadata)
    run.evidence_source='CONTROLLED REPRODUCTION' if config.get('controlled',True) else 'RECORDED AGENT RUN'
    run.title=config.get('title','Recorded development replay');service.store.save_run(run)
    experiment=next(x for x in service.store.experiments() if x['experiment_id']==run.run_id)
    experiment.update(evidence_source=run.evidence_source,recorded_trace=str(trace),trace_sha256=config['trace_sha256']);service.store.experiment(experiment)
    service.store.event(run.run_id,'replay.loaded',{'source':run.evidence_source,'trace_sha256':config['trace_sha256'],'events':len(events),'provenance':metadata['provenance']})
    return run,events

def execute(service,run,events,repair=False):
    try:
        root=Path(run.candidate_workspace).resolve()
        prepared=_validated_writes(events,files(root))
        plans=[]
        for writes in prepared:
            plan=[]
            for name,text in writes.items():
                target=root.joinpath(*name.split('/')).resolve()
                if not target.is_relative_to(root):raise ValueError('Replay write escapes candidate workspace')
                plan.append((target,text))
            plans.append(plan)
        for plan in plans:
            for target,text in plan:
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_text(text,encoding='utf-8')
        for event,writes in zip(events,prepared):
            service.store.event(run.run_id,event['kind'],{**event,'writes':writes,'authority':'replayed sensor; analysis reads actual files'})
        service.analyze(run.run_id,repair)
    except Exception as e:
        r=service.store.run(run.run_id);r.lifecycle='ERROR';r.final_decision='REVIEW';r.error=str(e);service.store.save_run(r)
        service.store.event(run.run_id,'replay.error',{'reason':str(e)})
