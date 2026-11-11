"""Ranks successor resources from structural signals and refuses weak or ambiguous matches."""
import re
from backend.sable.hcl_parser import unwrap
from backend.sable.policy_semantics import as_list, decode_policy

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

# ── Unambiguous obligation-misbinding amendment (unresolved-successor cases) ──

_CONTINUITY_SIGNALS={
    'explicit moved block','physical bucket identity','stable Asset attribute',
    'same exported application reference','module output preserves application reference',
    'unchanged address',
}

def _identity_tokens(value):
    # Lowercase alphanumeric tokens of a stable identity string; expressions carry no tokens.
    if not isinstance(value,str) or '${' in value:return frozenset()
    return frozenset(t for t in re.split(r'[^a-z0-9]+',value.lower()) if t)

def _family_evidence(old_attrs,new_attrs):
    """Identity-family membership: the candidate carries the baseline asset's own
    identity family via an equal or token-superset bucket name, or an equal or
    token-superset ``Asset`` tag. Token subsetting in the other direction is
    deliberately not evidence: a renamed-away asset is not proven by a candidate
    whose name merely shares the suffix."""
    old_bucket=_identity_tokens(old_attrs.get('bucket'))
    if old_bucket and old_bucket<=_identity_tokens(new_attrs.get('bucket')):return True
    old_asset=_identity_tokens((old_attrs.get('tags') or {}).get('Asset') if isinstance(old_attrs.get('tags'),dict) else None)
    new_tags=new_attrs.get('tags')
    if old_asset and old_asset<=_identity_tokens(new_tags.get('Asset') if isinstance(new_tags,dict) else None):return True
    return False

def _principal_allow_grants(candidate,principal):
    """Allow statements of inline role policies statically linked to ``principal``.

    Mirrors the linkage rules shared by both authorization evaluators: a policy is
    linked when its ``role`` equals the principal's ``.id``/``.name`` reference or
    literal name. Returns (resource_expression, module, actions) triples."""
    resources=candidate['resources']
    principal_node=resources.get(principal,{})
    principal_name=principal_node.get('attributes',{}).get('name')
    bindings=(f'{principal}.id',f'{principal}.name',principal_name)
    grants=[]
    for addr,node in resources.items():
        if node['type']!='aws_iam_role_policy':continue
        attrs=node['attributes']
        role=unwrap(attrs.get('role','')) if isinstance(attrs.get('role'),str) else attrs.get('role')
        if role not in bindings:continue
        doc=decode_policy(attrs.get('policy'))
        if not isinstance(doc,dict):continue
        for st in as_list(doc.get('Statement',[])):
            if not isinstance(st,dict) or st.get('Effect')!='Allow':continue
            refs=[r for r in as_list(st.get('Resource',[])) if isinstance(r,str) and r.strip()]
            acts=[a for a in as_list(st.get('Action',[])) if isinstance(a,str) and a.strip()]
            if not refs or not acts:continue
            grants+= [(r,node['module'],acts) for r in refs]
    return grants

def _resolve_grant_target(candidate,ref,module):
    """Resolve a grant Resource expression to one concrete candidate address, or None.
    Static resolution only: Terraform output/variable references stay unresolvable."""
    r=ref.strip()
    if r.endswith('/*'):r=r[:-2]
    elif r.endswith('/'):r=r[:-1]
    if r.startswith('${') and r.endswith('}'):
        expr=r[2:-1]
        # Qualify child-module references exactly like the integrated evaluator does.
        if module and expr.startswith('aws_'):expr=module+expr
        for addr in candidate['resources']:
            if expr==addr or expr.startswith(addr+'.'):return addr
        return None
    m=re.match(r'arn:aws:s3:::([^/]+)',r)
    if m:
        for addr,node in candidate['resources'].items():
            if node['type']=='aws_s3_bucket' and node['attributes'].get('bucket')==m.group(1):return addr
    return None

def unambiguous_misbinding(baseline,candidate,asset,principal,actions,hyp,conflicts):
    """Misbinding amendment for cases where successor resolution already failed closed.

    Returns evidence for a REGRESSED verdict only when ALL of the following hold;
    otherwise it returns None and the caller keeps UNKNOWN:
      1. successor resolution failed closed and there is no conflicting continuity
         evidence (conflicting evidence stays UNKNOWN);
      2. the principal's statically-linked inline role policies Allow the required
         actions on exactly one concrete candidate resource;
      3. exactly one candidate resource of the protected asset's type carries the
         baseline asset's own identity family (equal or token-superset bucket name
         or ``Asset`` tag), and that family candidate is NOT the policy-bound one;
      4. the policy-bound resource carries none of the protected asset's identity
         family and no correspondence signal (moved block, shared identity, exported
         reference, unchanged address) connects it to the protected asset.

    The verdict claims only that the obligation is misbound; the logical successor
    remains unresolved (None) and is never fabricated."""
    if conflicts:return None
    old=baseline['resources'].get(asset)
    if not old or principal not in candidate['resources']:return None
    family=[addr for addr,node in candidate['resources'].items()
            if node['type']==old['type'] and _family_evidence(old['attributes'],node['attributes'])]
    if len(family)!=1:return None
    family_addr=family[0]
    granted:dict[str,set]={}
    for ref,module,acts in _principal_allow_grants(candidate,principal):
        addr=_resolve_grant_target(candidate,ref,module)
        if addr is None:continue
        granted.setdefault(addr,set()).update(acts)
    if len(granted)!=1:return None
    target=next(iter(granted))
    if target==family_addr or set(actions)-granted[target]:return None
    target_node=candidate['resources'][target]
    if target_node['type']!=old['type']:return None
    if _family_evidence(old['attributes'],target_node['attributes']):return None
    target_hyp=next((h for h in hyp if h['address']==target),None)
    if target_hyp and any(s['signal'] in _CONTINUITY_SIGNALS for s in target_hyp['signals']):return None
    return {
        'misbound_target':target,
        'identity_family_candidate':family_addr,
        'required_actions':sorted(actions),
        'granted_actions':sorted(granted[target]),
        'reason':(
            f'Unambiguous obligation misbinding: the principal policy binds the required actions '
            f'to {target}, which carries no identity-family evidence of the protected asset {asset}, '
            f'while the only identity-family candidate {family_addr} is policy-unbound and no '
            f'continuity evidence (moved block, shared identity, exported reference) connects the '
            f'bound resource to the protected asset. The logical successor stays unresolved.'
        ),
    }
