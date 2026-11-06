from backend.threat_repo.repository import active
from backend.satra.seed_rules import RULES

EXECUTABLE_INVOICEHUB_RULES={
    'AUTHZ.IDOR.001','AUTHN.001','AUTHZ.ADMIN.001','INPUT.PDF.001'
}

def dictionary(knowledge):
    rows={r['id']:r for r in active(knowledge,'satra_rules')}
    compiled=[];unsupported=[]
    # RULES is the public 11-entry SATRA catalog. The shared analyzer only
    # supports the four executable InvoiceHub seed records; the other catalog
    # families are not represented by executable threat-repository templates.
    for expected in RULES:
        if expected['id'] not in EXECUTABLE_INVOICEHUB_RULES:continue
        r=rows.get(expected['id'])
        if not r or r['data'].get('implementation')!='executable bounded InvoiceHub template' or not r['data'].get('pytest_template'):unsupported.append(expected['id'])
        else:compiled.append({**expected,**r['data'],'id':r['id'],'version':r['version'],'source_id':r['source_id']})
    return compiled,unsupported
