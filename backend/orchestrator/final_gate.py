ACCEPTABLE={'CAVR':{'VERIFIED'},'SATRA':{'ACCEPT'},'SABLE':{'PRESERVED'}}
BLOCKING={'CAVR':{'REJECTED'},'SATRA':{'REJECT'},'SABLE':{'REGRESSED'}}

def decide(applicable,evidence,snapshot,input_hashes):
    reasons=[];blocking=[];statuses={}
    for module in applicable:
        rows=[e for e in evidence if e.get('analyzer')==module and not e.get('stale')]
        e=rows[-1] if rows else None
        if not e: reasons.append(f'{module}: current evidence missing');statuses[module]='PENDING';continue
        status=e.get('status')
        if not isinstance(status,str) or not status:reasons.append(f'{module}: evidence status missing');statuses[module]='PENDING';continue
        statuses[module]=status
        if e.get('integrity_valid') is not True:reasons.append(f'{module}: evidence integrity missing or failed');continue
        if e.get('candidate_snapshot')!=snapshot or e.get('input_hash')!=input_hashes.get(module):reasons.append(f'{module}: stale input or candidate snapshot');continue
        if status in BLOCKING[module] or e.get('blocking'):blocking.append(f"{module}: {status}")
        elif status=='RESTRICTED' and module=='CAVR' and e.get('details',{}).get('restriction_enforced'):continue
        elif status not in ACCEPTABLE[module]:reasons.append(f"{module}: {status}")
    if blocking:return 'BLOCK',blocking+reasons,statuses
    if reasons:return 'REVIEW',reasons,statuses
    if not applicable:return 'REVIEW',['No supported security surfaces were established'],statuses
    return 'ACCEPT',['Every applicable module has current acceptable evidence for this exact candidate'],statuses
