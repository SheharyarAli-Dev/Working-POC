"""Checks a registered baseline obligation, tracks its Terraform successor, then evaluates access."""
from pathlib import Path
from backend.sable.hcl_parser import parse
from backend.sable.policy_semantics import evaluate
from backend.sable.correspondence import rank,choose
from backend.integrations.tooling import optional_scan
from backend.threat_repo.sable_rules import rules

def analyze(context,emit):
    """Verify baseline authority, infer a resource successor, then evaluate candidate access."""
    # Stop early if required SABLE rules or trusted-baseline evidence are unavailable.
    knowledge,missing=rules(context.knowledge)
    if missing:return 'UNKNOWN',{'reason':'Required SABLE knowledge disabled or unsupported','missing_rules':missing},missing
    # Compare the frozen baseline and this run's candidate; neither parser reads deployed AWS state.
    b=parse(context.baseline/'infra');c=parse(context.path/'infra')
    cfg=context.policy.get('infrastructure',{});asset=cfg.get('protected_asset');role=cfg.get('principal');actions=cfg.get('actions',[])
    details={'baseline_graph':b['graph'],'candidate_graph':c['graph'],'moves':c['moves'],'hypotheses':[],'obligation':{'principal':role,'protected_asset':asset,'actions':actions,'authority':'trusted baseline + registered policy'},'parse_errors':b['errors']+c['errors']}
    # Emit the exact registered obligation so the UI trace can show what is being preserved.
    emit('sable.baseline_loaded',details['obligation'])
    # Without a trusted prior resource there is no continuity claim to evaluate.
    if not b['resources']:
        return 'UNKNOWN',{**details,'reason':'No trusted baseline boundary: the registered continuity obligation cannot be verified'},['Trusted SABLE baseline missing or empty']
    if details['parse_errors'] or asset not in b['resources'] or role not in b['resources']:
        return 'UNKNOWN',{**details,'reason':'Baseline authority or HCL parsing is incomplete'},details['parse_errors'] or ['Baseline authority missing']
    base=evaluate(b,role,asset,actions);details['baseline_verification']=base
    if not base['known'] or not base['holds']:return 'UNKNOWN',{**details,'reason':'Baseline least-privilege obligation is not independently verified'},['Unverified baseline']
    # Identify the same protected asset before evaluating candidate permissions.
    hyp,conflicts=rank(b,c,asset);details['hypotheses']=hyp;details['conflicts']=conflicts
    # Preserve all ranked candidates in evidence so a reviewer can inspect ambiguity and signals.
    for h in hyp:emit('sable.successor_candidate',h)
    target,why=choose(hyp,conflicts,max(6,cfg.get('minimum_score',6),knowledge['SABLE-SUCCESSOR-001']['data'].get('minimum_score',6)),max(3,cfg.get('margin',3),knowledge['SABLE-SUCCESSOR-001']['data'].get('margin',3)));details['successor']=target;details['correspondence_reason']=why
    # Follow a renamed principal only when Terraform records one unambiguous moved-block successor.
    principal=role
    if role not in c['resources']:
        successors=[m['to'] for m in c['moves'] if m['from']==role]
        principal=successors[0] if len(successors)==1 else None
    if not target or not principal:return 'UNKNOWN',{**details,'reason':why if not target else 'Principal continuity unresolved'},[why]
    # Apply the registered baseline obligation to the selected successor in the candidate graph.
    security=evaluate(c,principal,target,actions);details['projected_authorization']=security
    emit('sable.obligation_projected',{'successor':target,**security})
    # Record each candidate bucket's local predicate; this is diagnostic, not a deployed-state scan.
    details['candidate_only']=[]
    for addr,n in c['resources'].items():
        if n['type']=='aws_s3_bucket':
            check=evaluate(c,principal,addr,actions);details['candidate_only'].append({'asset':addr,'local_predicate':check['holds'],'known':check['known']})
    details['optional_tools']=[optional_scan('terraform',context.path/'infra'),optional_scan('checkov',context.path/'infra')]
    if not security['known']:return 'UNKNOWN',{**details,'reason':security['reason']},security.get('unknown',[])
    status='PRESERVED' if security['holds'] else 'REGRESSED'
    return status,{**details,'reason':security['reason']},['Bounded inline IAM role/S3 object model; no deployed AWS state']
