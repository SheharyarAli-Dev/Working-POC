"""Evaluates the supported inline-role/S3 policy subset and returns unknown outside that model."""
import json
import re
from backend.sable.hcl_parser import unwrap,load_hcl

def decode_policy(value):
    # Accept decoded JSON, JSON text, or the supported HCL expression form; other forms stay unknown.
    if isinstance(value,dict):return value
    value=unwrap(value)
    if isinstance(value,str) and value.startswith('jsonencode(') and value.endswith(')'):value=value[len('jsonencode('):-1]
    try:return json.loads(value)
    except (ValueError,TypeError):
        try:return load_hcl('value = '+value)['value']
        except Exception:return None

def as_list(v):return v if isinstance(v,list) else [v]

def unresolved_role_binding(value):
    # Treat Terraform expressions and resource references as unresolved without plan evaluation.
    if not isinstance(value,str) or not value.strip():return True
    value=unwrap(value).strip()
    return bool(
        '${' in value
        or re.search(r'\b(?:var|local|module|data|each|count)\s*\.',value)
        or re.search(r'\baws_[A-Za-z0-9_]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?\b',value)
        or any(token in value for token in '[]{}()?')
    )

def evaluate(model,principal,asset,actions):
    # This evaluator deliberately covers inline role policies for a narrow S3 object-access model.
    resources=model['resources'];grants=[];unknown=[];denies=[]
    expected='${'+asset+'.arn}/*'
    bucket=resources.get(asset,{}).get('attributes',{}).get('bucket')
    literal='arn:aws:s3:::'+bucket+'/*' if isinstance(bucket,str) and '${' not in bucket else None
    known_role_bindings={
        f'{addr}.{attribute}'
        for addr,node in resources.items() if node['type']=='aws_iam_role'
        for attribute in ('id','name')
    }
    for addr,node in resources.items():
        # Managed/attached policies are outside this analyzer's modeled semantics.
        if node['type'] not in ('aws_iam_role_policy','aws_iam_policy','aws_s3_bucket_policy','aws_iam_role_policy_attachment'):continue
        a=node['attributes']
        if node['type']!='aws_iam_role_policy':
            unknown.append(addr+': only inline role policies have full semantics in this slice');continue
        role_value=a.get('role')
        role=unwrap(role_value) if isinstance(role_value,str) else role_value
        principal_bindings=(principal+'.id',principal+'.name',resources.get(principal,{}).get('attributes',{}).get('name'))
        if role not in principal_bindings:
            if isinstance(role,str) and role in known_role_bindings:continue
            if unresolved_role_binding(role):unknown.append(addr+': role binding unresolved')
            continue
        policy=decode_policy(a.get('policy'))
        if not policy:unknown.append(addr+': policy expression unresolved');continue
        for st in as_list(policy.get('Statement',[])):
            if not isinstance(st,dict):unknown.append(addr+': invalid statement');continue
            if any(k in st for k in ['Condition','NotAction','NotResource']):unknown.append(addr+': unsupported conditional/negative policy semantics');continue
            # Normalize statement fields before comparing permissions with the registered obligation.
            effect=st.get('Effect');acts=as_list(st.get('Action',[]));targets=as_list(st.get('Resource',[]))
            if not acts or any(not isinstance(action,str) or not action.strip() for action in acts):
                unknown.append(addr+': Action must be a non-empty string or list of strings');continue
            if not targets or any(not isinstance(target,str) or not target.strip() for target in targets):
                unknown.append(addr+': Resource must be a non-empty string or list of strings');continue
            # Qualify local references in child modules.
            targets=[t.replace('${aws_','${'+node['module']+'aws_') for t in targets]
            record={'policy':addr,'actions':acts,'resources':targets,'effect':effect}
            if effect=='Deny':denies.append(record)
            elif effect=='Allow':grants.append(record)
            else:unknown.append(addr+': unknown Effect')
    # Any policy form outside the modeled subset prevents a confident allow/deny conclusion.
    if unknown:return {'known':False,'holds':False,'reason':'Unsupported policy semantics','unknown':unknown,'grants':grants}
    if denies:return {'known':False,'holds':False,'reason':'Explicit Deny requires expanded IAM semantics','unknown':['Explicit Deny statements present'],'grants':grants}
    actual_actions=set();bad_targets=[]
    for g in grants:
        actual_actions.update(g['actions'])
        bad_targets += [r for r in g['resources'] if r!=expected and (literal is None or r!=literal)]
    # Require the exact registered action set and no grant to an unapproved resource.
    holds=actual_actions==set(actions) and bool(grants) and not bad_targets and all(g['resources'] for g in grants)
    return {'known':True,'holds':holds,'expected_actions':actions,'actual_actions':sorted(actual_actions),'expected_resource':expected,'unexpected_resources':bad_targets,'grants':grants,'reason':'Exact modeled least privilege holds' if holds else 'Missing, widened or misbound role-to-asset authorization'}
