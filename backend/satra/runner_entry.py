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

FORBIDDEN_LOCAL_PORTS={22,80,443,2375,2376,3000,3306,5000,5432,6379,8000,8080,9000,9200,11434,27017}

def audit(event,args):
    if event in ('subprocess.Popen','os.system','os.exec','os.posix_spawn'):raise PermissionError('Child process forbidden in built-in test mode')
    if event=='socket.connect':
        addr=args[1] if len(args)>1 else None
        if isinstance(addr,tuple) and addr and addr[0] in ('127.0.0.1','localhost','::1'):
            port=addr[1] if len(addr)>1 and isinstance(addr[1],int) else 0
            if port<1024 or port in FORBIDDEN_LOCAL_PORTS:
                raise PermissionError(f'Access to local port {port} forbidden in built-in test mode')
            return
        raise PermissionError('Network unavailable in built-in test mode')
sys.addaudithook(audit)
raise SystemExit(pytest.main(sys.argv[2:]))
