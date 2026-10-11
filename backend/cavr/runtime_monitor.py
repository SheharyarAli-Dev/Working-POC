import re

def normalize(trace):
    events=[]
    for line in trace.splitlines():
        if ' = -1 ' in line and 'EINPROGRESS' not in line:continue
        kind=None;resource=None
        if 'connect(' in line and 'AF_INET' in line:
            kind='NETWORK_CONNECT';resource='127.0.0.1:18765' if '18765' in line else 'unresolved socket'
        elif 'openat(' in line or re.search(r'\bopen\(',line):
            match=re.search(r'"([^"]+)"',line);resource=match.group(1) if match else '?'
            if any(x in line for x in ['O_WRONLY','O_RDWR','O_CREAT']):kind='PERSISTENCE_WRITE' if any(x in resource for x in ['.bashrc','cron','systemd']) else 'FILE_WRITE'
            elif 'canary.txt' in resource:kind='SECRET_ACCESS'
            else:kind='FILE_READ'
        elif 'execve(' in line:kind='EXECUTE_BINARY';resource=re.search(r'"([^"]+)"',line).group(1)
        elif any(x in line for x in ['clone(','fork(','vfork(']):kind='PROCESS_CREATE';resource='child process'
        if kind:events.append({'type':kind,'resource':resource,'pid':line.split()[0] if line.split()[0].isdigit() else None,'raw':line[:1200],'source':'strace'})
    return events
