import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from backend.config import ROOT
from backend.orchestrator.hashing import digest
from backend.cavr.runtime_monitor import normalize
from backend.integrations.tooling import availability
LAB_LOCK=threading.Lock()

def run_counterfactual(source,pdf,outdir,emit):
    source,pdf,outdir=Path(source),Path(pdf),Path(outdir);outdir.mkdir(parents=True,exist_ok=True)
    caps=availability();engine=next((e for e in ('docker','podman') if caps[e]['available']),None)
    known_path=ROOT/'scenarios'/'laboratory_hashes.json'
    known=json.loads(known_path.read_text()) if known_path.exists() else {}
    pinned=digest(source.read_bytes()) in known.get('cavr_sources',[])
    if not engine and not pinned:return {'available':False,'reason':'Untrusted package requires Docker/Podman; host fallback only accepts hash-pinned inert sources','runs':[]}
    use_strace=bool(engine or caps['strace']['available'])
    backend=engine or ('PINNED_INERT_LAB_STRACE' if use_strace else 'PINNED_INERT_LAB_PYTHON_AUDIT')
    if not use_strace and not engine:
        emit('cavr.monitor_fallback',{'requested':'strace','available':False,'reason':caps['strace'].get('reason'),'selected':'Python audit events','scope':'pinned inert source only'})
    runs=[]
    with LAB_LOCK:
        for mode in ('normal','counterfactual'):
            emit('cavr.counterfactual_started',{'mode':mode,'backend':backend})
            with tempfile.TemporaryDirectory(prefix='asent-cavr-') as d:
                work=Path(d);shutil.copyfile(source,work/'package.py');shutil.copyfile(pdf,work/'invoice.pdf')
                shutil.copyfile(ROOT/'backend/cavr/lab_harness.py',work/'harness.py')
                dest=outdir/mode;dest.mkdir(exist_ok=True)
                if engine:
                    cmd=[engine,'run','--rm','--network','none','--read-only','--cap-drop','ALL','--cap-add','SYS_PTRACE','--security-opt','no-new-privileges','--memory','256m','--cpus','1','--pids-limit','64','--tmpfs','/tmp:rw,noexec,nosuid,size=32m','-v',str(work)+':/input:ro','-v',str(dest)+':/out:rw','-w','/tmp','asent-sandbox:local','strace','-f','-s','1024','-e','trace=%file,%network,%process','-o','/out/trace.log','python','-I','/input/harness.py',mode,'/input/package.py','/input/invoice.pdf']
                else:
                    cmd=['strace','-f','-s','1024','-e','trace=%file,%network,%process','-o',str(dest/'trace.log'),sys.executable,'-I',str(work/'harness.py'),mode,str(work/'package.py'),str(work/'invoice.pdf')]
                if not engine and not use_strace:cmd=[sys.executable,'-I',str(work/'harness.py'),mode,str(work/'package.py'),str(work/'invoice.pdf')]
                env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'HOME':str(work),'LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'}
                try:
                    p=subprocess.run(cmd,cwd=work,env=env,text=True,capture_output=True,timeout=18)
                    (dest/'stdout.log').write_text(p.stdout);(dest/'stderr.log').write_text(p.stderr)
                    facts=json.loads(p.stdout.strip().splitlines()[-1]) if p.returncode==0 and p.stdout.strip() else {}
                    trace=(dest/'trace.log').read_text() if (dest/'trace.log').exists() else ''
                    audit_events=facts.pop('audit_events',[])
                    (dest/'audit.json').write_text(json.dumps(audit_events,indent=2))
                    events=normalize(trace) if use_strace else audit_events
                    evidence_path=dest/('trace.log' if use_strace else 'audit.json')
                    for ev in events:
                        if ev['type'] in ('SECRET_ACCESS','NETWORK_CONNECT'):emit('cavr.runtime_event',{'mode':mode,**ev})
                    receiver_mode='loopback receiver' if facts.get('observation_mode','').endswith('loopback receiver') else 'harness/mock receiver interception'
                    runs.append({'mode':mode,'exit_code':p.returncode,'facts':facts,'events':events,'trace_path':str(evidence_path),'trace_sha256':digest(evidence_path.read_bytes()) if evidence_path.exists() else None,'monitor':'strace' if use_strace else 'PYTHON_AUDIT','execution_mode':backend,'execution_modes':{'containerized':bool(engine),'kernel_strace_observation':bool(use_strace),'python_audit_only_fallback':not use_strace,'receiver_interception':receiver_mode},'observation_scope':'kernel syscall trace' if use_strace else 'Python audit events; pinned inert source only','uncertainty':(['No kernel syscall observation'] if not use_strace else [])+(['No container isolation'] if not engine else []),'stderr':p.stderr[-2000:]})
                except Exception as e:runs.append({'mode':mode,'exit_code':None,'error':str(e),'events':[],'facts':{},'execution_mode':backend,'monitor':'strace' if use_strace else 'PYTHON_AUDIT','execution_modes':{'containerized':bool(engine),'kernel_strace_observation':bool(use_strace),'python_audit_only_fallback':not use_strace,'receiver_interception':'harness/mock receiver interception (result unavailable)'},'observation_scope':'kernel syscall trace' if use_strace else 'Python audit events; pinned inert source only','uncertainty':['Execution failed; receiver evidence unavailable']+([] if use_strace else ['No kernel syscall observation'])+([] if engine else ['No container isolation'])})
    return {'available':all(r['exit_code']==0 for r in runs),'backend':backend,'execution_mode':backend,'execution_modes':{'containerized':bool(engine),'kernel_strace_observation':bool(use_strace),'python_audit_only_fallback':not use_strace},'degraded':not use_strace and not engine,'strace_status':caps['strace'],'uncertainty':['No container isolation'] if not engine else [],'isolation':'container, network none' if engine else 'Pinned inert fixture with Python audit restrictions; not a hostile-code sandbox.','runs':runs}
