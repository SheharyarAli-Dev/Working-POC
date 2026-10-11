from backend.threat_repo.repository import active
from backend.satra.seed_rules import RULES

def dictionary(knowledge):
    rows={r['id']:r for r in active(knowledge,'satra_rules')}
    # Imported knowledge is data. No arbitrary Python templates are executed.
    compiled=[];unsupported=[]
    for expected in RULES:
        r=rows.get(expected['id'])
        if not r or any(r['data'].get(k)!=expected.get(k) for k in ('pytest_template','counterfactual_template','expected_secure_behavior')):unsupported.append(expected['id'])
        else:compiled.append({**expected,**r['data'],'id':r['id'],'version':r['version'],'source_id':r['source_id']})
    return compiled,unsupported
