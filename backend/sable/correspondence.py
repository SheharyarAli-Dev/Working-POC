"""Ranks successor resources from structural signals and refuses weak or ambiguous matches."""
from backend.sable.hcl_parser import unwrap

def rank(baseline,candidate,asset):
    # Score only same-type resources; these continuity signals are not calibrated probabilities.
    old=baseline['resources'][asset];attrs=old['attributes'];hyp=[];conflicts=[]
    direct_moves=[m['to'] for m in candidate['moves'] if m['from']==asset]
    if len(set(direct_moves))>1:conflicts.append('Conflicting explicit moves')
    for addr,node in candidate['resources'].items():
        if node['type']!=old['type']:continue
        # Each signal adds a fixed weight; resource names alone are deliberately ignored.
        score=1;signals=[{'signal':'resource type','weight':1}]
        def add(label,weight):
            nonlocal score
            score+=weight;signals.append({'signal':label,'weight':weight})
        if addr==asset:add('unchanged address',8)
        if addr in direct_moves:add('explicit moved block',10)
        if attrs.get('bucket') and attrs.get('bucket')==node['attributes'].get('bucket'):add('physical bucket identity',7)
        tag=attrs.get('tags',{}).get('Asset');newtag=node['attributes'].get('tags',{}).get('Asset')
        if tag and tag==newtag:add('stable Asset attribute',4)
        if attrs.get('tags',{}).get('Stage')==node['attributes'].get('tags',{}).get('Stage') and attrs.get('tags',{}).get('Stage'):add('lifecycle role',2)
        # Stable output semantics supports continuity independently of IAM grants.
        for key,val in baseline['outputs'].items():
            if isinstance(val,str) and val.startswith(asset+'.'):
                value=candidate['outputs'].get(key,'')
                if isinstance(value,str) and value.startswith(addr+'.'):add('same exported application reference',4)
                elif isinstance(value,str) and value.startswith('module.'):
                    output_key='.'.join(value.split('.')[:-1])+'.'+value.split('.')[-1]
                    resolved=candidate['outputs'].get(output_key,'')
                    module='.'.join(output_key.split('.')[:-1])+'.'
                    if isinstance(resolved,str) and module+resolved==addr+'.id':add('module output preserves application reference',4)
        incoming=[e['source'] for e in candidate['graph']['edges'] if e['target']==addr]
        hyp.append({'address':addr,'score':score,'signals':signals,'references':incoming,'module':node['module']})
    hyp.sort(key=lambda x:(-x['score'],x['address']))
    # Explicit move metadata conflicting with stable physical identity makes lineage ambiguous.
    physical=[h['address'] for h in hyp if any(s['signal']=='physical bucket identity' for s in h['signals'])]
    if direct_moves and physical and any(p not in direct_moves for p in physical):conflicts.append('Move evidence conflicts with physical asset identity')
    return hyp,conflicts

def choose(hyp,conflicts,minimum=6,margin=3):
    # Fail closed on conflicts, a low top score, or a near tie instead of guessing a successor.
    if conflicts:return None,'; '.join(conflicts)
    if not hyp or hyp[0]['score']<minimum:return None,'No successor reaches the fixed confidence threshold'
    if len(hyp)>1 and hyp[0]['score']-hyp[1]['score']<margin:return None,'Successor scores are too close for a unique attribution'
    return hyp[0]['address'],'Unique supported successor; resource-name similarity is not used'
