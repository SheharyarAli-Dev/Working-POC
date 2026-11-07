"""Checks a registered baseline obligation, tracks its Terraform successor, then evaluates access."""
from pathlib import Path
from backend.sable.hcl_parser import parse
from backend.sable.policy_semantics import evaluate
from backend.sable.correspondence import rank,choose
from backend.integrations.tooling import optional_scan
from backend.threat_repo.sable_rules import rules
from backend.orchestrator.hashing import files

def analyze(context,emit):
    """Verify baseline authority, infer a resource successor, then evaluate candidate access."""
    # Gate runs evaluate every obligation of the base .asent/ config; demo runs keep one obligation.
    if getattr(context,'gate',False):return analyze_configured(context,emit)
    # Stop early if required SABLE rules or trusted-baseline evidence are unavailable.
    knowledge,missing=rules(context.knowledge)
    if missing:return 'UNKNOWN',{'reason':'Required SABLE knowledge disabled or unsupported','missing_rules':missing},missing
    return _evaluate(context,emit,knowledge,context.policy.get('infrastructure',{}),Path(context.baseline)/'infra',Path(context.path)/'infra')

def analyze_configured(context,emit):
    """Every obligation of the base config, each in its Terraform root. Worst result wins."""
    knowledge,missing=rules(context.knowledge)
    if missing:return 'UNKNOWN',{'mode':'configured','reason':'Required SABLE knowledge disabled or unsupported','missing_rules':missing,'obligations':[]},missing
    config=getattr(context,'config',None);cfg=config.module('SABLE') if config is not None and config.valid else None
    document=config.documents.get('sable_obligations') if cfg is not None else None
    if cfg is None or not cfg.enabled or not document:
        return 'UNKNOWN',{'mode':'configured','reason':'no usable SABLE section and obligations in the base .asent/ config','obligations':[]},['SABLE configuration unavailable']
    roots=list(cfg.terraform_dirs)
    tf=sorted({k for k in files(context.baseline) if k.endswith(('.tf','.tf.json'))}|{k for k in context.manifest if k.endswith(('.tf','.tf.json'))})
    outside=[k for k in tf if not any(k.startswith(r.rstrip('/')+'/') for r in roots)]
    if outside:
        return 'UNKNOWN',{'mode':'configured','reason':'Terraform outside the configured terraform_dirs is not analysed: '+', '.join(outside),'obligations':[]},['Unanalysed Terraform: '+', '.join(outside)]
    results=[];uncertainty=[]
    for item in document['obligations']:
        root=item.get('terraform_dir') or roots[0]
        status,details,unc=_evaluate(context,emit,knowledge,item,Path(context.baseline)/root,Path(context.path)/root)
        results.append({'id':item['id'],'terraform_dir':root,'status':status,'reason':details.get('reason'),'details':details})
        uncertainty+=[f"{item['id']}: {u}" for u in unc]
    statuses=[r['status'] for r in results]
    status='REGRESSED' if 'REGRESSED' in statuses else 'UNKNOWN' if any(s!='PRESERVED' for s in statuses) else 'PRESERVED'
    worst=[r for r in results if r['status']!='PRESERVED']
    reason='; '.join(f"{r['id']}: {r['status']}: {r['reason']}" for r in worst) or 'Every registered obligation is preserved'
    return status,{'mode':'configured','reason':reason,'obligations':results},uncertainty

def _evaluate(context,emit,knowledge,cfg,baseline_dir,candidate_dir):
    """One obligation (`cfg`: principal, protected_asset, actions, minimum_score, margin) in one Terraform root."""
    # Compare the frozen baseline and this run's candidate; neither parser reads deployed AWS state.
    b=parse(baseline_dir);c=parse(candidate_dir)
    asset=cfg.get('protected_asset');role=cfg.get('principal');actions=cfg.get('actions',[])
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
    details['optional_tools']=[optional_scan('terraform',candidate_dir),optional_scan('checkov',candidate_dir)]
    if not security['known']:return 'UNKNOWN',{**details,'reason':security['reason']},security.get('unknown',[])
    status='PRESERVED' if security['holds'] else 'REGRESSED'
    return status,{**details,'reason':security['reason']},['Bounded inline IAM role/S3 object model; no deployed AWS state']
