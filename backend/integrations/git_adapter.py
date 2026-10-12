import os
import subprocess
from pathlib import Path

def git(path,*args,decode_errors='strict'):
    env={**os.environ,'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,'GIT_TERMINAL_PROMPT':'0'}
    p=subprocess.run(['git','-c','core.hooksPath=/dev/null','-c','protocol.file.allow=always',*args],cwd=path,env=env,text=True,errors=decode_errors,capture_output=True,timeout=30)
    if p.returncode:raise RuntimeError(p.stderr.strip())
    return p.stdout.strip()

def init_repo(path):
    git(path,'init');git(path,'checkout','-b','baseline');git(path,'config','user.name','ASENT Local');git(path,'config','user.email','asent@localhost')
    git(path,'add','--all');git(path,'commit','-m','Trusted InvoiceHub baseline')
    return git(path,'rev-parse','HEAD')

def diff(path,baseline):
    # Include new files in the candidate diff without committing them.
    # This display-only diff can include binary-ish files that Git presents as
    # text, so decode undecodable bytes safely instead of aborting analysis.
    git(path,'add','--all',decode_errors='replace')
    return git(path,'diff','--cached','--no-ext-diff',baseline,'--',decode_errors='replace')
