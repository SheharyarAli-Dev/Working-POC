"""Parses supported Terraform resources and local modules into a graph; unsupported forms stay unknown."""
import json
import re
from pathlib import Path
import hcl2
from hcl2.utils import SerializationOptions

def load_hcl(text):
    # Normalize HCL strings and blocks into a predictable Python structure for static analysis.
    return hcl2.loads(text,serialization_options=SerializationOptions(strip_string_quotes=True,explicit_blocks=False))
import networkx as nx

REF=re.compile(r'(?:module\.\w+\.)*(?:aws_[\w]+\.[\w]+)(?:\.[\w]+)?')

def unwrap(v):
    # Remove the parser's interpolation wrapper when it encloses a simple expression.
    if isinstance(v,str) and v.startswith('${') and v.endswith('}'):return v[2:-1]
    return v

def parse(root):
    # Build a bounded static graph from .tf files; unsupported constructs are recorded as errors.
    root=Path(root).resolve();resources={};moves=[];outputs={};errors=[];visited=set()
    def visit(folder,prefix='',depth=0):
        # Limit recursion and reject repeated folders so module cycles cannot expand indefinitely.
        if depth>5 or folder in visited:errors.append('Recursive/deep module unsupported');return
        visited.add(folder)
        for f in sorted(folder.glob('*.tf')):
            try:data=load_hcl(f.read_text())
            except Exception as e:errors.append(f'{f.name}: {e}');continue
            for block in data.get('resource',[]):
                for typ,names in block.items():
                    for name,attrs in names.items():
                        addr=prefix+typ+'.'+name
                        resources[addr]={'address':addr,'type':typ,'attributes':attrs,'module':prefix,'file':f.relative_to(root).as_posix()}
            for block in data.get('moved',[]):moves.append({'from':prefix+str(unwrap(block.get('from',''))),'to':prefix+str(unwrap(block.get('to','')))})
            for block in data.get('output',[]):
                for name,attrs in block.items():outputs[prefix+name]=unwrap(attrs.get('value'))
            for block in data.get('module',[]):
                for name,attrs in block.items():
                    # This slice expands only fixed local modules; dynamic instances need a Terraform plan.
                    src=attrs.get('source','')
                    if not isinstance(src,str) or not src.startswith('./'):errors.append('Only local modules supported: '+name);continue
                    dest=(folder/src).resolve()
                    if not dest.is_relative_to(root):errors.append('Module escapes root');continue
                    if any(k in attrs for k in ['count','for_each']):errors.append('Module instances need plan expansion: '+name);continue
                    visit(dest,prefix+'module.'+name+'.',depth+1)
    visit(root)
    # Resolve module exports to qualified resource references before graph/policy analysis.
    def resolve(value,scope='',seen=None):
        # Resolve module outputs recursively while tracking visited outputs to avoid cycles.
        seen=seen or set()
        if not isinstance(value,str):return value
        def substitute(match):
            token=match.group(0)
            key=scope+token if scope+token in outputs else token
            if key in outputs and key not in seen:
                child='.'.join(key.split('.')[:-1])+'.'
                val=outputs[key]
                if isinstance(val,str):
                    val=resolve(val,child,seen|{key})
                    if val.startswith('aws_'):val=child+val
                    return val
            return token
        return re.sub(r'module\.\w+(?:\.module\.\w+)*\.\w+',substitute,value)
    def walk(value,scope):
        if isinstance(value,dict):return {k:walk(v,scope) for k,v in value.items()}
        if isinstance(value,list):return [walk(v,scope) for v in value]
        return resolve(value,scope)
    for node in resources.values():node['attributes']=walk(node['attributes'],node['module'])
    outputs={k:resolve(v) for k,v in outputs.items()}
    # Edges point from a resource to resources referenced by its attributes.
    graph=nx.DiGraph()
    for addr,node in resources.items():graph.add_node(addr,type=node['type'])
    for addr,node in resources.items():
        for ref in REF.findall(json.dumps(node['attributes'])):
            options=[ref,node['module']+ref]
            for option in options:
                target=next((r for r in resources if option==r or option.startswith(r+'.')),None)
                if target:graph.add_edge(addr,target,relation='references');break
    return {'resources':resources,'moves':moves,'outputs':outputs,'errors':errors,'graph':{'nodes':[{'id':n,**d} for n,d in graph.nodes(data=True)],'edges':[{'source':a,'target':b,**d} for a,b,d in graph.edges(data=True)]}}
