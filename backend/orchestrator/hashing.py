"""Creates deterministic file manifests and SHA-256 identifiers for evidence binding."""
import hashlib
import json
import os
import shutil
from pathlib import Path

EXCLUDE={'.git','.venv','node_modules','__pycache__','.pytest_cache','runtime','.mypy_cache','dist','.asent','reports','.aws','.ssh'}

def digest(value):
    # Canonical JSON serialization makes equivalent structures produce the same digest.
    if not isinstance(value,bytes): value=json.dumps(value,sort_keys=True,separators=(',',':'),default=str).encode()
    return hashlib.sha256(value).hexdigest()

def files(root):
    # Exclude generated/private runtime data and enforce snapshot size and symlink limits.
    root=Path(root)
    found=[];total=0
    for base,dirs,names in os.walk(root,followlinks=False):
        if any(Path(base,d).is_symlink() for d in dirs if d not in EXCLUDE):raise ValueError('Symlinked directories are unsupported in candidate snapshots')
        dirs[:]=sorted(d for d in dirs if d not in EXCLUDE)
        for name in sorted(names):
            if name in EXCLUDE:continue
            p=Path(base,name)
            if p.is_symlink(): raise ValueError('Symlinks are unsupported in candidate snapshots: '+str(p))
            if name.startswith('.env') or name.endswith(('.pyc','.sqlite3','.sqlite3-wal','.sqlite3-shm')): continue
            total+=p.stat().st_size
            if len(found)>=15000 or total>120*1024*1024: raise ValueError('Snapshot exceeds 15,000 files / 120 MiB budget')
            found.append(p.relative_to(root).as_posix())
    return found

def manifest(root): return {p:digest((Path(root)/p).read_bytes()) for p in files(root)}
# A snapshot identifies the complete eligible file manifest, not just a Git commit label.
def snapshot(root): return digest(manifest(root))
def copy_tree(src,dst):
    # Copy only files accepted by the same manifest rules used for hashing.
    src,dst=Path(src),Path(dst);dst.mkdir(parents=True,exist_ok=True)
    for name in files(src):
        p=dst/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src/name,p)
    return dst

def changed(old,new): return sorted(k for k in old.keys()|new.keys() if old.get(k)!=new.get(k))
