"""Execute pytest in a disposable copy. Arbitrary code requires a container."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from xml.etree import ElementTree as ET
from backend.config import ROOT
from backend.orchestrator.hashing import copy_tree,digest,files
from backend.integrations.tooling import availability


def _lf_digest(data: bytes) -> str:
    """Hash with CRLF normalized to LF — matches git text-mode checkout on any OS."""
    import hashlib
    return hashlib.sha256(data.replace(b'\r\n', b'\n')).hexdigest()

def permitted_builtin(root):
    index=ROOT/'scenarios/laboratory_hashes.json'
    allowed=json.loads(index.read_text()).get('python_sources',[]) if index.exists() else []
    names=files(root)
    if any(f.endswith(('.so','.pyd','.dll','.dylib','.pyw','.pth','.zip','.egg')) for f in names):return False
    for name in ('pytest.ini','fixtures/invoice.pdf'):
        reference=ROOT/'demo_project/InvoiceHub'/name;candidate=Path(root)/name
        if not candidate.is_file() or _lf_digest(candidate.read_bytes())!=_lf_digest(reference.read_bytes()):return False
    return all(_lf_digest((Path(root)/f).read_bytes()) in allowed for f in names if f.endswith('.py'))


def run_pytest(root,output,selected='all',trusted=False):
    start=time.perf_counter();output=Path(output);output.mkdir(parents=True,exist_ok=True)
    caps=availability();engine=next((e for e in ('docker','podman') if caps[e]['available']),None)
    if not engine and not permitted_builtin(root):return {'available':False,'exit_code':None,'reason':'External/modified code requires Docker/Podman; host execution is limited to hash-pinned bundled sources','tests':[]}
    with tempfile.TemporaryDirectory(prefix='asent-pytest-') as d:
        work=copy_tree(root,Path(d)/'project')
        if trusted:
            testdir=work/'assurance';testdir.mkdir()
            shutil.copyfile(ROOT/'backend/satra/trusted_fixtures.py',testdir/'conftest.py')
            for name in ['security','functional']:shutil.copyfile(ROOT/f'backend/satra/trusted_{name}.py',testdir/f'test_{name}.py')
            targets=['assurance'] if selected=='all' else ['assurance/test_'+selected+'.py']
        else:targets=['tests'] if selected=='all' else ['tests/test_'+selected+'.py']
        args=['-q','-o','addopts=','-c',str(work/'pytest.ini'),'--junitxml='+str(work/'results.xml'),*targets]
        if engine:
            args=['-q','-o','addopts=','-c','/work/pytest.ini','--junitxml=/work/results.xml',*targets]
            user_flag=['-u',f"{os.getuid()}:{os.getgid()}"] if hasattr(os,'getuid') else []
            cmd=[engine,'run','--rm',*user_flag,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','512m','--cpus','1','--pids-limit','64','--tmpfs','/tmp:rw,nosuid,size=64m','-v',str(work)+':/work:rw','-w','/work','-e','PYTEST_DISABLE_PLUGIN_AUTOLOAD=1','asent-sandbox:local','python','-m','pytest',*args]
        else:
            cmd=[sys.executable,'-I',str(ROOT/'backend/satra/runner_entry.py'),str(work),*args]
        env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'HOME':str(work),'LANG':'C.UTF-8','PYTEST_DISABLE_PLUGIN_AUTOLOAD':'1','PYTHONDONTWRITEBYTECODE':'1'}
        try:
            result=subprocess.run(cmd,cwd=work,env=env,text=True,capture_output=True,timeout=40)
            (output/'stdout.log').write_text(result.stdout);(output/'stderr.log').write_text(result.stderr)
            xml=work/'results.xml';tests=[]
            if xml.exists():
                shutil.copyfile(xml,output/'junit.xml')
                for t in ET.parse(xml).getroot().iter('testcase'):
                    error=t.find('error');failure=t.find('failure');skip=t.find('skipped')
                    status='ERROR' if error is not None else 'FAIL' if failure is not None else 'SKIP' if skip is not None else 'PASS'
                    detail=error if error is not None else failure
                    tests.append({'name':t.attrib.get('name'),'classname':t.attrib.get('classname'),'status':status,'seconds':float(t.attrib.get('time',0)),'message':(detail.text or '')[-4000:] if detail is not None else ''})
            return {'available':True,'exit_code':result.returncode,'tests':tests,'passed':sum(t['status']=='PASS' for t in tests),'failed':sum(t['status']=='FAIL' for t in tests),'errors':sum(t['status']=='ERROR' for t in tests),'skipped':sum(t['status']=='SKIP' for t in tests),'duration_ms':round((time.perf_counter()-start)*1000,2),'backend':engine or 'HASH_PINNED_BUILTIN_SUBPROCESS','isolation':'container with network none' if engine else 'Known bundled sources only; isolated temp workspace, sanitized environment, resource limits and network/process audit restrictions; not an arbitrary-code sandbox','stdout':result.stdout[-10000:],'stderr':result.stderr[-2000:],'junit_path':str(output/'junit.xml'),'junit_sha256':digest(xml.read_bytes()) if xml.exists() else None}
        except Exception as e:return {'available':False,'exit_code':None,'reason':str(e),'tests':[]}
