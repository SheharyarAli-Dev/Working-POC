"""ASENT command line.

Local commands (no server): `init` writes a starter .asent/ for a project; `gate` decides one change
(base -> head) of a git repository and exits 0 ACCEPT, 1 BLOCK, 2 REVIEW.
Server commands (`run`, `watch`, `dependency`, `replay`, `research`, `report`, `capabilities`) call the
same HTTP gateway the dashboard uses.
"""
import argparse
import json
import os
import shlex
import sys
import time
from pathlib import Path
import httpx
from backend.integrations.research_loader import load as load_research

LOCAL_COMMANDS=('init','gate')

def init_command(args):
    from backend.project_config.starter import init_project
    try:report=init_project(Path(args.repository),force=args.force)
    except (FileExistsError,ValueError) as e:print(str(e),file=sys.stderr);return 2
    for name in report['files']:print(name)
    if report['not_copied']:print('Not approved (not an exact pin): '+', '.join(report['not_copied']))
    print('Starter written. Review every file in .asent/, then remove "_starter" from .asent/config.json; until then every gate decision is REVIEW.')
    return 0

def gate_command(args):
    from backend.gate.runner import run_gate
    code,report=run_gate(args.repository,args.base,args.head,args.output_dir,args.data_dir,args.keep_workdir)
    print(f"ASENT gate: {report['decision']} (exit {code}); report: {Path(args.output_dir)/'asent-report.json'}; summary: {Path(args.output_dir)/'asent-summary.md'}")
    for reason in report['reasons'][:20]:print('  - '+reason)
    if report.get('data_dir'):print('Work directory kept: '+report['data_dir'])
    return code

def main(argv=None):
    parser=argparse.ArgumentParser(prog='asent',description='ASENT assurance gate. Local: init. Server commands need scripts/start.sh first.')
    parser.add_argument('--url',default=os.environ.get('ASENT_URL','http://127.0.0.1:8000'))
    sub=parser.add_subparsers(dest='action',required=True)
    for action in ('run','watch'):
        p=sub.add_parser(action);p.add_argument('--scenario',default='safe');p.add_argument('--repository');p.add_argument('--repair',action='store_true');p.add_argument('--wait',action='store_true');p.add_argument('--srs');p.add_argument('--plan')
    p=sub.add_parser('dependency');p.add_argument('--run',required=True);p.add_argument('command',nargs=argparse.REMAINDER)
    p=sub.add_parser('replay');p.add_argument('bundle');p.add_argument('--wait',action='store_true');p.add_argument('--repair',action='store_true')
    p=sub.add_parser('research');p.add_argument('manifest');p.add_argument('--opt-in',action='store_true');p.add_argument('--wait',action='store_true')
    p=sub.add_parser('report');p.add_argument('run');p.add_argument('--output')
    sub.add_parser('capabilities')
    p=sub.add_parser('init',help='write a starter .asent/ (refused by the gate until reviewed)');p.add_argument('--repository',default='.');p.add_argument('--force',action='store_true')
    p=sub.add_parser('gate',help='decide base..head of a git repository without a server; exit 0 ACCEPT, 1 BLOCK, 2 REVIEW')
    p.add_argument('--repository',required=True);p.add_argument('--base',required=True);p.add_argument('--head',required=True)
    p.add_argument('--output-dir',default='.');p.add_argument('--data-dir',help='keep and reuse run data (verdict cache) here')
    p.add_argument('--keep-workdir',action='store_true',help='do not delete the temporary work directory')
    args=parser.parse_args(argv)
    if args.action=='init':return init_command(args)
    if args.action=='gate':return gate_command(args)
    with httpx.Client(base_url=args.url,timeout=180,trust_env=False) as client:
        def call(method,path,body=None):
            r=client.request(method,'/api'+path,json=body);r.raise_for_status();return r.json()
        if args.action in ('run','watch'):
            body={'scenario':args.scenario,'repository':str(Path(args.repository).resolve()) if args.repository else None,'mode':'watch' if args.action=='watch' else 'manual','auto_repair':args.repair}
            for key in ('srs','plan'):
                if getattr(args,key):body[key]=Path(getattr(args,key)).read_text()
            result=call('POST','/runs',body)
        elif args.action=='dependency':
            command=args.command[1:] if args.command[:1]==['--'] else args.command
            result=call('POST','/runs/'+args.run+'/dependency',{'command':shlex.join(command)})
            print(json.dumps(result,indent=2));return 0 if result['allowed'] else 3
        elif args.action=='replay':result=call('POST','/replay',{'bundle':str(Path(args.bundle).resolve()),'auto_repair':args.repair})
        elif args.action=='research':result=call('POST','/runs',load_research(args.manifest,args.opt_in))
        elif args.action=='report':
            result=call('GET','/runs/'+args.run+'/report')
            if args.output:Path(args.output).write_text(json.dumps(result,indent=2));print(args.output);return 0
        else:result=call('GET','/capabilities')
        if getattr(args,'wait',False):
            rid=result['run_id'];deadline=time.monotonic()+300
            while result['lifecycle'] not in ('COMPLETE','ERROR','INTERRUPTED') and time.monotonic()<deadline:
                time.sleep(.5);result=call('GET','/runs/'+rid)
            if result['lifecycle'] not in ('COMPLETE','ERROR','INTERRUPTED'):raise TimeoutError('Run remains active; inspect dashboard')
        print(json.dumps(result,indent=2))
    return 0

if __name__=='__main__':
    try:raise SystemExit(main())
    except (httpx.HTTPError,ValueError,FileNotFoundError,TimeoutError) as e:print(str(e),file=sys.stderr);raise SystemExit(2)
