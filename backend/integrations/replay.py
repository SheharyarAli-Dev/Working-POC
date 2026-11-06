"""Replay recorded file writes into an isolated candidate; never execute trace commands."""
import json
from pathlib import Path
from backend.orchestrator.hashing import digest,snapshot
from backend.integrations.agent_adapter import ReplayAdapter

def prepare(service,bundle):
    path=Path(bundle).expanduser().resolve();config=json.loads(path.read_text())
    if config.get('schema')!='asent.replay.v1':raise ValueError('Unsupported replay bundle')
    repo=(path.parent/config['repository']).resolve();trace=(path.parent/config['events']).resolve()
    if not repo.is_relative_to(path.parent) or not trace.is_relative_to(path.parent):raise ValueError('Replay inputs must be inside bundle folder')
    if snapshot(repo)!=config['initial_snapshot_sha256'] or digest(trace.read_bytes())!=config['trace_sha256']:raise ValueError('Replay input digest mismatch')
    events=list(ReplayAdapter(trace).events())
    if len(events)>100:raise ValueError('Replay event budget exceeded')
    for event in events:
        for name,text in event.get('writes',{}).items():
            p=Path(name)
            if p.is_absolute() or '..' in p.parts or p.parts[0] in ('.git','.venv','node_modules') or not isinstance(text,str) or len(text)>2_000_000:raise ValueError('Unsupported replay write')
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
        for event in events:
            for name,text in event.get('writes',{}).items():
                p=Path(run.candidate_workspace)/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
            service.store.event(run.run_id,event['kind'],{**event,'authority':'replayed sensor; analysis reads actual files'})
        service.analyze(run.run_id,repair)
    except Exception as e:
        r=service.store.run(run.run_id);r.lifecycle='ERROR';r.final_decision='REVIEW';r.error=str(e);service.store.save_run(r)
        service.store.event(run.run_id,'replay.error',{'reason':str(e)})
