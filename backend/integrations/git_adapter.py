import os
import subprocess
from pathlib import Path, PurePosixPath

# Same budget as orchestrator.hashing.files: a commit larger than this cannot be snapshotted anyway.
EXPORT_MAX_FILES=15000
EXPORT_MAX_BYTES=120*1024*1024

def git(path,*args,decode_errors='strict'):
    env={**os.environ,'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,'GIT_TERMINAL_PROMPT':'0'}
    p=subprocess.run(['git','-c','core.hooksPath=/dev/null','-c','protocol.file.allow=always',*args],cwd=path,env=env,text=True,errors=decode_errors,capture_output=True,timeout=30)
    if p.returncode:raise RuntimeError(p.stderr.strip())
    return p.stdout.strip()

def init_repo(path):
    git(path,'init');git(path,'checkout','-b','baseline');git(path,'config','user.name','ASENT Local');git(path,'config','user.email','asent@localhost')
    git(path,'add','--all');git(path,'commit','-m','Trusted baseline')
    return git(path,'rev-parse','HEAD')

def diff(path,baseline):
    # Include new files in the candidate diff without committing them.
    # This display-only diff can include binary-ish files that Git presents as
    # text, so decode undecodable bytes safely instead of aborting analysis.
    git(path,'add','--all',decode_errors='replace')
    return git(path,'diff','--cached','--no-ext-diff',baseline,'--',decode_errors='replace')


def _git_env(path):
    # No system/global config, no prompts, and no discovery of a repository above `path`.
    return {**os.environ,'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,'GIT_TERMINAL_PROMPT':'0',
            'GIT_CEILING_DIRECTORIES':str(Path(path).resolve().parent)}

def _git_raw(path,*args,input=None):
    p=subprocess.run(['git','-c','core.hooksPath=/dev/null',*args],cwd=path,env=_git_env(path),input=input,capture_output=True,timeout=120)
    if p.returncode:raise RuntimeError(p.stderr.decode('utf-8','replace').strip())
    return p.stdout

def resolve_commit(repository,ref):
    """Full SHA of the commit `ref` names in the work tree at `repository`; ValueError otherwise.

    `repository` must be the top level of a non-bare repository itself (a directory inside some other
    repository is refused), and `ref` must not look like an option.
    """
    root=Path(repository)
    if not root.is_dir():raise ValueError(f'not a directory: {root}')
    try:top=_git_raw(root,'rev-parse','--show-toplevel').decode().strip()
    except RuntimeError:raise ValueError(f'not a git repository: {root}') from None
    if Path(top).resolve()!=root.resolve():raise ValueError(f'not a git repository top level: {root} (top level is {top})')
    if not isinstance(ref,str) or not ref.strip() or ref.startswith('-') or ':' in ref or '\0' in ref:
        raise ValueError(f'unsupported ref: {ref!r}')
    try:return _git_raw(root,'rev-parse','--verify','--quiet','--end-of-options',ref+'^{commit}').decode().strip()
    except RuntimeError:raise ValueError(f'unknown commit: {ref!r} (a shallow clone may not contain it)') from None

def export_commit(repository,sha,dest):
    """Write the exact blobs of commit `sha` into the new directory `dest` and return it.

    Read with `ls-tree` and `cat-file`, not `archive` or `checkout`: the repository's own attributes
    (`export-ignore`, `export-subst`, eol, filters) cannot hide or rewrite a file, and no hook runs.
    Symlinks, submodules, unsafe paths and over-budget trees raise ValueError (the gate: REVIEW).
    """
    dest=Path(dest)
    if dest.exists() and (not dest.is_dir() or any(dest.iterdir())):raise ValueError(f'export destination is not a new directory: {dest}')
    listing=_git_raw(repository,'ls-tree','-r','-l','-z','--full-tree',sha)
    entries=[];total=0
    for item in listing.split(b'\0'):
        if not item:continue
        meta,raw_name=item.split(b'\t',1);mode,kind,obj,size=meta.split()
        try:name=raw_name.decode('utf-8')
        except UnicodeDecodeError:raise ValueError(f'path is not UTF-8: {raw_name!r}') from None
        if mode==b'120000':raise ValueError(f'symlink in commit: {name} (symlinks are not analysed)')
        if mode==b'160000' or kind==b'commit':raise ValueError(f'submodule in commit: {name} (submodule content is not analysed)')
        parts=PurePosixPath(name).parts
        if kind!=b'blob' or name.startswith('/') or '..' in parts or '.git' in parts:raise ValueError(f'unsupported tree entry: {name}')
        entries.append((name,obj,mode==b'100755',int(size)));total+=int(size)
        if len(entries)>EXPORT_MAX_FILES or total>EXPORT_MAX_BYTES:
            raise ValueError(f'commit exceeds the export budget of {EXPORT_MAX_FILES} files / {EXPORT_MAX_BYTES} bytes')
    dest.mkdir(parents=True,exist_ok=True)
    if not entries:return dest
    data=_git_raw(repository,'cat-file','--batch',input=b''.join(obj+b'\n' for _,obj,_,_ in entries))
    position=0
    for name,obj,executable,size in entries:
        end=data.index(b'\n',position);header=data[position:end].split()
        if header!=[obj,b'blob',str(size).encode()]:raise ValueError(f'unexpected object for {name}: {header!r}')
        content=data[end+1:end+1+size];position=end+1+size+1
        target=dest/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(content)
        os.chmod(target,0o755 if executable else 0o644)
    return dest
