"""Read package metadata; never install packages during analysis."""
import json
from pathlib import Path
from zipfile import ZipFile
from email.parser import Parser
import httpx
from backend.config import ADVISORIES,ASSETS
from backend.orchestrator.hashing import digest

def metadata(name,version,ecosystem='PyPI'):
    url=f'https://pypi.org/pypi/{name}/{version}/json' if ecosystem=='PyPI' else f'https://registry.npmjs.org/{name}/{version}'
    try:
        r=httpx.get(url,timeout=8);r.raise_for_status();return {'available':True,'url':url,'response':r.json()}
    except Exception as e:return {'available':False,'url':url,'error':str(e)}

def read_artifact(node,workspace):
    rel=node.get('artifact','')
    # Artifacts must be local to the candidate or the supplied immutable artifact directory.
    if not rel or Path(rel).is_absolute() or '..' in Path(rel).parts:raise ValueError('Invalid artifact path')
    local=Path(workspace)/rel
    path=local if local.is_file() else ASSETS/rel
    if not path.is_file():raise ValueError('Artifact missing: '+rel)
    raw=path.read_bytes();sha=digest(raw)
    if sha!=node.get('sha256'):raise ValueError('Artifact hash mismatch: '+node['name'])
    sources={};meta={}
    if path.suffix=='.whl':
        with ZipFile(path) as z:
            if sum(n.file_size for n in z.infolist())>30_000_000:raise ValueError('Artifact decompression budget exceeded')
            for info in z.infolist():
                if info.filename.endswith('.py'):sources[info.filename]=z.read(info).decode('utf8','replace')
                if info.filename.endswith('.dist-info/METADATA'):
                    m=Parser().parsestr(z.read(info).decode());meta={'name':m['Name'],'version':m['Version'],'requires_dist':m.get_all('Requires-Dist',[])}
    elif path.suffix=='.py':sources[path.name]=raw.decode();meta={'name':node['name'],'version':node['version'],'format':'local laboratory source'}
    else:raise ValueError('Only Python wheel/source artifacts supported in this vertical slice')
    if meta.get('name','').lower().replace('_','-')!=node['name'].lower().replace('_','-') or meta.get('version')!=node['version']:raise ValueError('Artifact metadata does not match lock')
    if path.suffix=='.whl':
        query={'package':{'name':node['name'],'ecosystem':'PyPI'},'version':node['version']}
        record=ADVISORIES/('registry-'+digest(query)+'.json')
        registry=json.loads(record.read_text()) if record.exists() else metadata(node['name'],node['version'])
        response=registry.get('response',{})
        if 'response_sha256' in registry and digest(response)!=registry['response_sha256']:raise ValueError('Registry response digest mismatch')
        if not any(u.get('digests',{}).get('sha256')==sha for u in response.get('urls',[])):raise ValueError('Artifact not confirmed by exact registry release digest')
        meta['registry_digest_verified']=True
    return {'path':str(path),'sha256':sha,'metadata':meta,'sources':sources}
