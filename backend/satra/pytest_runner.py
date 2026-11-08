"""Execute pytest in a disposable copy. Arbitrary code requires a container."""
import hashlib
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
    """Hash pinned Python source using the manifest's LF-normalized contract."""
    return hashlib.sha256(data.replace(b'\r\n', b'\n')).hexdigest()


def permitted_builtin(root):
    index=ROOT/'scenarios/laboratory_hashes.json'
    allowed=json.loads(index.read_text()).get('python_sources',[]) if index.exists() else []
    names=files(root)
    if any(f.endswith(('.so','.pyd','.dll','.dylib','.pyw','.pth','.zip','.egg')) for f in names):return False
    for name in ('pytest.ini','fixtures/invoice.pdf'):
        reference=ROOT/'demo_project/InvoiceHub'/name;candidate=Path(root)/name
        if not candidate.is_file() or digest(candidate.read_bytes())!=digest(reference.read_bytes()):return False
    return all(_lf_digest((Path(root)/f).read_bytes()) in allowed for f in names if f.endswith('.py'))


def container_user_args(engine):
    # Preserve host ownership for bind-mounted Docker workspaces without changing sandbox controls.
    if engine == 'docker' and os.name == 'posix':
        return ['--user', f'{os.getuid()}:{os.getgid()}']
    return []

# Trusted gate runs (docs/satra/harness-isolation.md): the base tests and ini are mounted read-only at
# /trusted, the head at /work, and pytest starts from /trusted with every head config source switched off.
TRUSTED_PLUGIN='asent_satra_trusted_run'
TRUSTED_PYTHON=['python','-P','-s','-m','pytest']


def _trusted_layout(base,trusted_tests_dir,pytest_ini):
    """/trusted = base pytest.ini (or an empty one) + the base tests as asent_assurance/; /asent = the plugin only."""
    trusted=Path(base)/'trusted';plugin=Path(base)/'asent'
    copy_tree(trusted_tests_dir,trusted/'asent_assurance')
    if pytest_ini is not None:shutil.copyfile(pytest_ini,trusted/'pytest.ini')
    else:(trusted/'pytest.ini').write_text('[pytest]\n')
    plugin.mkdir();shutil.copyfile(Path(__file__).with_name('trusted_run_plugin.py'),plugin/(TRUSTED_PLUGIN+'.py'))
    return trusted,plugin


def run_pytest(root,output,selected='all',trusted=False,trusted_tests_dir=None,external=False,targets=None,pytest_ini=None,image='asent-sandbox:local',timeout=40,memory='512m'):
    # Gate runs pass external=True (never on the host, whatever the files), trusted_tests_dir (the
    # base .asent/ tests), targets (explicit project test paths), pytest_ini (the trusted ini), and
    # image/timeout/memory from backend.satra.project_image (the per-project image and base limits).
    # The defaults are the built-in demo's shared image and limits.
    # A trusted run with trusted_tests_dir in a container keeps the tests and ini outside the head
    # (_trusted_layout); every other run is unchanged.
    start=time.perf_counter();output=Path(output);output.mkdir(parents=True,exist_ok=True)
    caps=availability();engine=next((e for e in ('docker','podman') if caps[e]['available']),None)
    if not engine and (external or not permitted_builtin(root)):return {'available':False,'exit_code':None,'reason':'External/modified code requires Docker/Podman; host execution is limited to hash-pinned bundled sources','tests':[]}
    with tempfile.TemporaryDirectory(prefix='asent-pytest-') as d:
        work=copy_tree(root,Path(d)/'project')
        generic=trusted_tests_dir is not None or targets is not None or pytest_ini is not None
        isolated=bool(engine) and trusted and trusted_tests_dir is not None
        if trusted and trusted_tests_dir is not None:
            if (work/'asent_assurance').exists():return {'available':False,'exit_code':None,'reason':'project already has an asent_assurance directory','tests':[]}
            suite=work
            if isolated:suite,plugin=_trusted_layout(d,trusted_tests_dir,pytest_ini)
            else:copy_tree(trusted_tests_dir,work/'asent_assurance')
            wanted='asent_assurance/test_'+selected+'.py'
            targets=['asent_assurance'] if selected=='all' or not (suite/wanted).is_file() else [wanted]
        elif targets is not None:targets=list(targets)
        elif trusted:
            testdir=work/'assurance';testdir.mkdir()
            shutil.copyfile(ROOT/'backend/satra/trusted_fixtures.py',testdir/'conftest.py')
            for name in ['security','functional']:shutil.copyfile(ROOT/f'backend/satra/trusted_{name}.py',testdir/f'test_{name}.py')
            targets=['assurance'] if selected=='all' else ['assurance/test_'+selected+'.py']
        else:targets=['tests'] if selected=='all' else ['tests/test_'+selected+'.py']
        ini='pytest.ini'
        if generic and not isolated:
            if pytest_ini is not None:shutil.copyfile(pytest_ini,work/'.asent-pytest.ini');ini='.asent-pytest.ini'
            elif not (work/'pytest.ini').is_file():ini=None
        args=['-q','-o','addopts=',*(['-c',str(work/ini)] if ini else []),'--junitxml='+str(work/'results.xml'),*targets]
        if isolated:
            # -P: /work (the cwd) is not put on sys.path; -s: no user site. -c/--rootdir/--confcutdir keep pytest's
            # config and conftest discovery inside /trusted; autoload off and no cacheprovider. The plugin then
            # appends the head to the end of sys.path (backend/satra/trusted_run_plugin.py).
            args=['-q','-o','addopts=','-c','/trusted/pytest.ini','--rootdir=/trusted','--confcutdir=/trusted','-p','no:cacheprovider','-p',TRUSTED_PLUGIN,
                  '--junitxml=/work/results.xml',*['/trusted/'+t for t in targets]]
            cmd=[engine,'run','--rm',*container_user_args(engine),'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory',memory,'--cpus','1','--pids-limit','64','--tmpfs','/tmp:rw,nosuid,size=64m',
                 '-v',str(work)+':/work:rw','-v',str(suite)+':/trusted:ro','-v',str(plugin)+':/asent:ro','-w','/work',
                 '-e','PYTEST_DISABLE_PLUGIN_AUTOLOAD=1','-e','PYTHONPATH=/asent','-e','ASENT_SATRA_TRUSTED=/trusted','-e','ASENT_SATRA_HEAD=/work',image,*TRUSTED_PYTHON,*args]
        elif engine:
            args=['-q','-o','addopts=',*(['-c','/work/'+ini] if ini else []),'--junitxml=/work/results.xml',*targets]
            cmd=[engine,'run','--rm',*container_user_args(engine),'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory',memory,'--cpus','1','--pids-limit','64','--tmpfs','/tmp:rw,nosuid,size=64m','-v',str(work)+':/work:rw','-w','/work','-e','PYTEST_DISABLE_PLUGIN_AUTOLOAD=1',image,'python','-m','pytest',*args]
        else:
            cmd=[sys.executable,'-I',str(ROOT/'backend/satra/runner_entry.py'),str(work),*args]
        env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'HOME':str(work),'LANG':'C.UTF-8','PYTEST_DISABLE_PLUGIN_AUTOLOAD':'1','PYTHONDONTWRITEBYTECODE':'1'}
        if os.name == 'nt':
            # Windows Python needs SystemRoot to initialize the Winsock provider used by TestClient.
            system_root = os.environ.get('SYSTEMROOT') or os.environ.get('SystemRoot')
            if system_root:
                env['SYSTEMROOT'] = system_root
        try:
            result=subprocess.run(cmd,cwd=work,env=env,text=True,capture_output=True,timeout=timeout)
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
