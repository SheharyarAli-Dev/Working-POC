import os
import sys
from pathlib import Path
work=Path(sys.argv[1]).resolve()
try:
    import resource
    resource.setrlimit(resource.RLIMIT_AS,(768*1024*1024,768*1024*1024))
    resource.setrlimit(resource.RLIMIT_CPU,(30,30));resource.setrlimit(resource.RLIMIT_FSIZE,(32*1024*1024,32*1024*1024));resource.setrlimit(resource.RLIMIT_NOFILE,(256,256))
except (ImportError,ValueError):
    pass  # resource limits unavailable on Windows; audit hook still enforces subprocess/network restrictions
sys.path.insert(0,str(work));os.chdir(work)
import pytest

def audit(event,args):
    if event in ('subprocess.Popen','os.system','os.exec','os.posix_spawn'):raise PermissionError('Child process forbidden in built-in test mode')
    if event=='socket.connect':raise PermissionError('Network unavailable in built-in test mode')
sys.addaudithook(audit)
raise SystemExit(pytest.main(sys.argv[2:]))

