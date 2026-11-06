"""Framework-neutral event sensors. Event text is never security authority."""
import json
import shlex
import time
from pathlib import Path
from typing import Protocol
from backend.orchestrator.hashing import manifest,changed

class AgentAdapter(Protocol):
    def events(self): ...

class WorkspaceWatchAdapter:
    def __init__(self,path):self.path=Path(path);self.previous=manifest(path)
    def poll(self):
        current=manifest(self.path);paths=changed(self.previous,current);self.previous=current
        return [{'kind':'file.changed','paths':paths,'source':'workspace watch'}] if paths else []

class ReplayAdapter:
    def __init__(self,path):self.path=Path(path)
    def events(self):
        for line in self.path.read_text().splitlines():
            event=json.loads(line)
            if not isinstance(event, dict):raise ValueError('Replay event must be an object')
            if not isinstance(event.get('kind'), str) or event['kind'] not in ('file.changed','dependency.intercepted','task.registered'):
                raise ValueError('Unsupported replay event')
            writes=event.get('writes',{})
            if not isinstance(writes,dict):raise ValueError('Replay writes must be an object')
            if any(not isinstance(name,str) or not isinstance(text,str) for name,text in writes.items()):
                raise ValueError('Replay write paths and contents must be text')
            yield event

def parse_dependency_command(command):
    argv=shlex.split(command) if isinstance(command,str) else list(command)
    if any(t in argv for t in [';','&&','||','|','>','<']):raise ValueError('Shell composition is not supported')
    if len(argv)>=3 and Path(argv[0]).name in ('python','python3') and argv[1:3]==['-m','pip']:argv=argv[2:]
    if len(argv)<2 or Path(argv[0]).name not in ('pip','pip3','npm') or argv[1] not in ('install','add','update','uninstall'):raise ValueError('Only dependency-changing pip/npm requests supported')
    return {'tool':Path(argv[0]).name,'action':argv[1],'argv':argv,'packages':[a for a in argv[2:] if not a.startswith('-')],'ecosystem':'npm' if argv[0]=='npm' else 'PyPI'}
