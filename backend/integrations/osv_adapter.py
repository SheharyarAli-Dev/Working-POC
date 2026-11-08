"""Live queries and explicitly dated, digest-checked OSV JSON responses. No invented empty scan."""
import json
import os
from datetime import datetime,timezone
from pathlib import Path
import httpx
from backend.config import ADVISORIES
from backend.orchestrator.hashing import digest

class OSV:
    def __init__(self,cache=None):self.cache=Path(cache or ADVISORIES);self.cache.mkdir(parents=True,exist_ok=True)
    def query(self,name,version,ecosystem='PyPI',live=False,max_age_days=30):
        query={'package':{'name':name,'ecosystem':ecosystem},'version':version}
        path=self.cache/(digest(query)+'.json')
        error=None
        if live:
            try:
                with httpx.Client(timeout=8) as client:
                    pages=[];request=query;vulns=[]
                    for _ in range(20):
                        response=client.post('https://api.osv.dev/v1/query',json=request);response.raise_for_status();page=response.json();pages.append(page);vulns.extend(page.get('vulns',[]))
                        if not page.get('next_page_token'):break
                        request={**query,'page_token':page['next_page_token']}
                    else:raise ValueError('OSV pagination budget exceeded; incomplete evidence')
                    body={'vulns':vulns};body['pages']=pages
                value={'query':query,'retrieved_at':datetime.now(timezone.utc).isoformat(),'source':'https://api.osv.dev/v1/query','response':body,'response_sha256':digest(body)}
                path.write_text(json.dumps(value,indent=2))
                return {**value,'available':True,'mode':'LIVE','vulnerabilities':body.get('vulns',[])}
            except Exception as e:error=str(e)
        if path.exists():
            value=json.loads(path.read_text());age=(datetime.now(timezone.utc)-datetime.fromisoformat(value['retrieved_at'])).total_seconds()/86400
            if value.get('response_sha256')==digest(value['response']) and value.get('query')==query and age<=max_age_days:
                return {**value,'available':True,'mode':'DATED CACHE','age_days':round(age,2),'vulnerabilities':value['response'].get('vulns',[]),'live_error':error}
        registry=self.cache/('registry-'+digest(query)+'.json')
        if not live and registry.exists():
            value=json.loads(registry.read_text());age=(datetime.now(timezone.utc)-datetime.fromisoformat(value['retrieved_at'])).total_seconds()/86400
            if value.get('response_sha256')==digest(value.get('response')) and value.get('query')==query and age<=max_age_days:
                return {**value,'available':True,'mode':'PYPI ADVISORY METADATA (dated)','osv_available':False,'osv_error':error or 'OSV unavailable; explicit registry advisory fallback','vulnerabilities':value['response'].get('vulnerabilities',[]),'age_days':round(age,2)}
        return {'available':False,'mode':'UNAVAILABLE','query':query,'error':error or 'No current cached advisory response','vulnerabilities':None}
