"""Trusted harness for the shipped INERT example. JSON facts come from execution."""
import importlib.util
import json
import os
import resource
import socket
import sys
import threading
from pathlib import Path

FAKE='CAVR_FAKE_SECRET_NOT_A_CREDENTIAL'
work=Path.cwd();mode=sys.argv[1];source=Path(sys.argv[2]).resolve();pdf=Path(sys.argv[3]).read_bytes()
resource.setrlimit(resource.RLIMIT_AS,(256*1024*1024,256*1024*1024))
resource.setrlimit(resource.RLIMIT_CPU,(8,8))
resource.setrlimit(resource.RLIMIT_FSIZE,(8*1024*1024,8*1024*1024))
resource.setrlimit(resource.RLIMIT_NOFILE,(128,128))
received=[]
audit_events=[]
intercept_events=[]
try:
    listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('127.0.0.1',18765));listener.listen(1);listener.settimeout(1.5)
except OSError:
    listener=None
    # This controlled endpoint shim is used only for the pinned inert fixture
    # when VM policy prohibits even loopback sockets. It is not OS observation.
    class MockConnection:
        def __enter__(self):return self
        def __exit__(self,*args):return False
        def sendall(self,data):received.append(data.decode());intercept_events.append({'type':'NETWORK_CONNECT','resource':'127.0.0.1:18765','pid':os.getpid(),'source':'HARNESS_INTERCEPT','raw':'mock receiver sendall'})
    def mocked_create_connection(address,timeout=None):
        if address != ('127.0.0.1',18765):raise PermissionError('Only mock receiver is permitted')
        return MockConnection()
    socket.create_connection=mocked_create_connection
def receive():
    if listener is None:return
    try:
        client,_=listener.accept()
        with client:received.append(client.recv(1024).decode())
    except TimeoutError:pass
    finally:listener.close()
thread=threading.Thread(target=receive,daemon=True);thread.start()
(work/'canary.txt').write_text(FAKE)
if mode=='counterfactual':os.environ['CAVR_CANARY_AWS_SECRET']=FAKE
else:os.environ.pop('CAVR_CANARY_AWS_SECRET',None)
# Supplemental restriction for known bundled source. This is not an arbitrary-code sandbox.
def audit(event,args):
    kind=None;target=None
    if event=='socket.connect':kind='NETWORK_CONNECT';target=str(args[1])
    if event=='open' and isinstance(args[0],str):
        target=args[0];flags=args[2] if len(args)>2 else 0
        writing=(isinstance(args[1],str) and any(x in args[1] for x in 'wa+')) or (isinstance(flags,int) and flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT))
        kind='FILE_WRITE' if writing else 'SECRET_ACCESS' if 'canary.txt' in target else 'FILE_READ'
    if event in ('os.system','subprocess.Popen','os.exec','os.posix_spawn'):kind='PROCESS_CREATE';target=str(args)[:500]
    if kind:audit_events.append({'type':kind,'resource':target,'pid':os.getpid(),'raw':event+' '+str(args)[:1000],'source':'PYTHON_AUDIT'})
    if event in ('os.system','subprocess.Popen','os.exec','os.posix_spawn'):raise PermissionError('Process execution forbidden')
    if event=='socket.connect' and args[1]!=('127.0.0.1',18765):raise PermissionError('Only mock receiver is permitted')
    if event=='open' and isinstance(args[0],str):
        p=Path(args[0]).resolve();mode=args[1];flags=args[2] if len(args)>2 else 0
        writing=(isinstance(mode,str) and any(x in mode for x in 'wa+')) or (isinstance(flags,int) and flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT))
        if writing and not p.is_relative_to(work):raise PermissionError('Write outside disposable workspace')
        if not writing and not any(p.is_relative_to(Path(x).resolve()) for x in [str(work),str(source.parent),sys.prefix,sys.base_prefix]):raise PermissionError('Read outside prepared runtime')
sys.addaudithook(audit)
spec=importlib.util.spec_from_file_location('lab_package',source);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
result=module.extract_invoice_text(pdf);thread.join(2)
print(json.dumps({'mode':mode,'functional_text':result,'receiver_payloads':received,'canary_received':FAKE in received,'audit_events':audit_events+intercept_events,'observation_mode':'PYTHON_AUDIT plus controlled mock receiver' if listener is None else 'PYTHON_AUDIT plus loopback receiver'}))
