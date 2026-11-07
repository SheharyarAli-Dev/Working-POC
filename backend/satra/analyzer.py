import shutil
import tempfile
from pathlib import Path
from backend.config import ROOT
from backend.orchestrator.hashing import copy_tree
from backend.satra.diff_localizer import localize
from backend.satra.security_contract import build
from backend.threat_repo.satra_rules import dictionary
from backend.satra.pytest_runner import run_pytest
from backend.satra.counterfactuals import mutate_ownership
from backend.satra.test_validator import preflight,is_pass,killed,judge
from backend.satra.static_adapters import scan
from backend.integrations.ollama_adapter import generate_tests


def analyze(context,outdir,emit):
    # Gate runs take contract, trusted tests and counterfactual from the base .asent/ config;
    # the built-in demo scenarios keep this InvoiceHub path.
    if getattr(context,'gate',False):
        from backend.satra.gate_mode import analyze_configured
        return analyze_configured(context,outdir,emit)
    outdir=Path(outdir);outdir.mkdir(parents=True,exist_ok=True)
    rules,unsupported=dictionary(context.knowledge)
    details=localize(context.baseline,context.path);details['dictionary']=rules;details['contract']=build(context)
    if unsupported:return 'INCONCLUSIVE',{**details,'reason':'Required knowledge disabled or template semantics unsupported','missing_rules':unsupported},['Required independent tests cannot be waived by disabling knowledge']
    for r in details['regions']:emit('satra.region_localized',r)
    if details['contract'] is None:return 'INCONCLUSIVE',{**details,'reason':'No independently supported InvoiceHub security contract'},['Unsupported framework, missing policy/SRS authority, or route semantics']
    emit('satra.contract_created',details['contract'])
    details['static']=scan(context.path)
    executions={}
    def execute(label,path,selected='all',trusted=False):
        result=run_pytest(path,outdir/label,selected,trusted);executions[label]=result
        emit('satra.test_result',{'label':label,**{k:v for k,v in result.items() if k not in ('stdout','stderr','tests')}})
        return result
    baseline=execute('trusted_baseline',context.baseline,trusted=True)
    candidate=execute('trusted_candidate',context.path,trusted=True)
    ordinary=execute('ordinary_candidate',context.path)
    source=context.read('tests/test_security.py');valid,reason=preflight(source)
    with tempfile.TemporaryDirectory(prefix='asent-satra-mutant-') as d:
        d=Path(d);mutant=copy_tree(context.baseline,d/'mutant');made=mutate_ownership(mutant)
        independent=execute('trusted_counterfactual',mutant,'security',True) if made else {'available':False}
        feasible=is_pass(baseline) and killed(independent)
        original_mutant=execute('baseline_oracle_mutant',mutant,'security') if made else {'available':False}
        if valid:
            testbase=copy_tree(context.baseline,d/'test_baseline');testmutant=copy_tree(mutant,d/'test_mutant')
            for folder in [testbase,testmutant]:(folder/'tests/test_security.py').write_text(source)
            tb=execute('test_on_secure_baseline',testbase,'security');tm=execute('test_on_counterfactual',testmutant,'security');repeat=execute('test_baseline_repeat',testbase,'security')
            validation=judge(tb,tm,repeat,feasible)
            if validation['diagnosis']=='ORACLE_WEAKENED' and not killed(original_mutant):validation['diagnosis']='PRE_EXISTING_TEST_GAP'
        else:validation={'accepted':False,'diagnosis':'ORACLE_WEAKENED','reason':reason}
        details['oracle']={**validation,'valid_counterfactual':feasible,'baseline_original_killed':killed(original_mutant),'mutant_operator':'AST replace can_access_invoice body with return True','counterfactual_scope':'ownership read + delete'}
        emit('satra.counterfactual_result',details['oracle'])
        adaptive=generate_tests({'contract':details['contract'],'regions':details['regions'][:6],'diff':details['diff'][:5000]})
        details['adaptive']={k:v for k,v in adaptive.items() if k!='candidates'};details['adaptive']['validations']=[]
        for index,test in enumerate(adaptive.get('candidates',[])):
            text=test.get('source','');ok,why=preflight(text)
            result={'accepted':False,'reason':why,'source':text,'rule_id':test.get('rule_id')}
            if ok and test.get('rule_id')==details['contract']['rule_id']:
                for folder in [testbase,testmutant] if valid else []:(folder/'tests/test_security.py').write_text(text)
                if valid:
                    b=execute(f'adaptive_{index}_baseline',testbase,'security');m=execute(f'adaptive_{index}_mutant',testmutant,'security');r=execute(f'adaptive_{index}_repeat',testbase,'security')
                    result.update(judge(b,m,r,feasible))
                    if result['accepted']:
                        app=copy_tree(context.path,d/f'adaptive_candidate_{index}');(app/'tests/test_security.py').write_text(text)
                        result['candidate_result']=execute(f'adaptive_{index}_candidate',app,'security')
            details['adaptive']['validations'].append(result)
    details['executions']=executions;details['findings']=[]
    if not is_pass(baseline):status='INCONCLUSIVE';why='Trusted baseline does not satisfy independent obligations or execution is unavailable'
    elif not candidate.get('available') or candidate.get('exit_code') not in (0,1):status='INCONCLUSIVE';why='Candidate test execution is incomplete'
    elif not is_pass(candidate):
        status='REJECT';why='Candidate violates independent security or functional obligations';details['findings'].append({'family':'application security','diagnosis':'APPLICATION_REGRESSION','tests':[x['name'] for x in candidate.get('tests',[]) if x['status']=='FAIL']})
    elif not is_pass(ordinary):status='REJECT' if ordinary.get('exit_code')==1 else 'INCONCLUSIVE';why='Ordinary project tests do not provide a clean regression result'
    elif validation['diagnosis']=='INCONCLUSIVE':status='INCONCLUSIVE';why=validation['reason']
    elif not validation['accepted']:status='REJECT';why=validation['reason'];details['findings'].append({'family':'security test integrity',**validation})
    else:status='ACCEPT';why='Independent contract tests pass and the security oracle discriminates a valid counterfactual'
    for a in details['adaptive']['validations']:
        if a['accepted'] and not is_pass(a.get('candidate_result',{})):status='REJECT';why='An independently validated adaptive test fails on the candidate'
    details['reason']=why
    return status,details,['Bounded authentication, ownership, admin, upload and parameterized-login checks; other vulnerability families are not exhaustively covered']
