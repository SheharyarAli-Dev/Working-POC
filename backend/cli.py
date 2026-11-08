"""ASENT command line.

Local commands (no server): `init` writes a starter .asent/ for a project; `gate` decides one change
(base -> head) of a git repository and exits 0 ACCEPT, 1 BLOCK, 2 REVIEW. With no arguments `gate`
gates the current repository: its top level, head HEAD, base its default branch (gate/defaults.py).
Every local command takes --json and then prints exactly one JSON document on stdout (for editors).
Server commands (`run`, `watch`, `dependency`, `replay`, `research`, `report --run`, `capabilities`) call the
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
from backend.config import VERSION
from backend.integrations.research_loader import load as load_research

LOCAL_COMMANDS=('init','gate','report','doctor','dashboard')

def emit_json(value):
    print(json.dumps(value,indent=2,default=str))

def init_command(args):
    from backend.project_config.starter import init_project
    try:report=init_project(Path(args.repository),force=args.force)
    except (FileExistsError,ValueError) as e:
        if args.json:emit_json({'error':str(e)})
        else:print(str(e),file=sys.stderr)
        return 2
    if args.json:emit_json({**report,'starter':True});return 0
    for name in report['files']:print(name)
    if report['not_copied']:print('Not approved (not an exact pin): '+', '.join(report['not_copied']))
    print('Starter written. Review every file in .asent/, then remove "_starter" from .asent/config.json; until then every gate decision is REVIEW.')
    return 0

def gate_command(args):
    from backend.gate.defaults import default_base,top_level
    from backend.gate.runner import run_gate
    repository,output_dir=args.repository,args.output_dir
    if repository is None:  # the current repository; its top level, so `asent gate` works from any subfolder
        repository=str(top_level(Path.cwd()) or Path.cwd())
        output_dir=output_dir or repository
    output_dir=output_dir or '.'
    base,how=(args.base,'--base') if args.base is not None else default_base(repository)
    code,report=run_gate(repository,base,args.head,output_dir,args.data_dir,args.keep_workdir)
    if args.json:emit_json(report);return code
    print(f"Gated {report['repository']}: base {base or 'none found'} ({how or 'no default branch'}) -> head {args.head}")
    print(f"ASENT gate: {report['decision']} (exit {code}); report: {Path(output_dir)/'asent-report.json'}; summary: {Path(output_dir)/'asent-summary.md'}")
    for reason in report['reasons'][:20]:print('  - '+reason)
    if report.get('data_dir'):print('Work directory kept: '+report['data_dir'])
    return code

def doctor_command(args):
    from backend.commands import doctor
    result=doctor.run_checks()
    if args.json:emit_json(result)
    else:print(doctor.render(result),end='')
    return 0 if result['ready'] else 1

def report_command(args):
    from backend.commands import report as local_report
    def fail(message):
        if args.json:emit_json({'error':message})
        else:print(message,file=sys.stderr)
        return 2
    if args.legacy_run is not None:
        return fail(f"`asent report RUN_ID` is now `asent report --run {args.legacy_run}` (a run report from the server). "
                    "`asent report` with no argument prints the last asent-report.json; --file PATH picks another one.")
    path=Path(args.file) if args.file else local_report.default_path()
    try:report=local_report.load(path)
    except local_report.ReportError as e:return fail(str(e))
    if args.json:emit_json(report)
    else:print(local_report.render(report,path),end='')
    return 0

def dashboard_port(text):
    from backend.commands.dashboard import port_type
    return port_type(text)

def dashboard_command(args):
    from backend.commands import dashboard
    if not dashboard.port_free(args.port):
        message=f"port {args.port} on {dashboard.HOST} is already in use (another dashboard?); choose one with --port"
        if args.json:emit_json({'error':message})
        else:print(message,file=sys.stderr)
        return 2
    about=dashboard.info(args.port)
    if args.json:print(json.dumps(about),flush=True)
    else:
        print(f"ASENT dashboard: {about['url']} (this machine only; Ctrl+C stops it). Data: {about['data_dir']}")
        if not about['ui_bundled']:
            print(f"This install has no dashboard UI, so it serves the API only at {about['api']} (see `asent doctor`).")
    dashboard.serve(args.port)
    return 0

def main(argv=None):
    parser=argparse.ArgumentParser(prog='asent',description='ASENT assurance gate. Local: init, gate, report, doctor, dashboard. Server commands need scripts/start.sh (or asent dashboard) first.')
    parser.add_argument('--url',default=os.environ.get('ASENT_URL','http://127.0.0.1:8000'))
    parser.add_argument('--version',action='store_true',help='print the ASENT version and exit')
    parser.add_argument('--json',dest='json_top',action='store_true',help='with --version: print it as JSON')
    json_flag=argparse.ArgumentParser(add_help=False)
    json_flag.add_argument('--json',action='store_true',help='print one JSON document on stdout instead of text')
    sub=parser.add_subparsers(dest='action')
    for action in ('run','watch'):
        p=sub.add_parser(action);p.add_argument('--scenario',default='safe');p.add_argument('--repository');p.add_argument('--repair',action='store_true');p.add_argument('--wait',action='store_true');p.add_argument('--srs');p.add_argument('--plan')
    p=sub.add_parser('dependency');p.add_argument('--run',required=True);p.add_argument('command',nargs=argparse.REMAINDER)
    p=sub.add_parser('replay');p.add_argument('bundle');p.add_argument('--wait',action='store_true');p.add_argument('--repair',action='store_true')
    p=sub.add_parser('research');p.add_argument('manifest');p.add_argument('--opt-in',action='store_true');p.add_argument('--wait',action='store_true')
    p=sub.add_parser('report',parents=[json_flag],help='print the last asent-report.json; --run ID reads a run report from the server')
    p.add_argument('legacy_run',nargs='?',help=argparse.SUPPRESS)  # the old `report RUN_ID`: refused with the new form
    p.add_argument('--file',help='report file (default: asent-report.json at the repository top level, else here)')
    p.add_argument('--run',help='dashboard run id: read its report from the server (needs scripts/start.sh or asent dashboard)')
    p.add_argument('--output',help='with --run: write the server report to this file')
    sub.add_parser('doctor',parents=[json_flag],help='check Python, git, Docker and the images; prints fixes, changes nothing')
    p=sub.add_parser('dashboard',parents=[json_flag],help='start the dashboard on 127.0.0.1 (this machine only)')
    p.add_argument('--port',type=dashboard_port,default=8000,help='port on 127.0.0.1 (default 8000)')
    sub.add_parser('capabilities')
    p=sub.add_parser('init',parents=[json_flag],help='write a starter .asent/ (refused by the gate until reviewed)');p.add_argument('--repository',default='.');p.add_argument('--force',action='store_true')
    p=sub.add_parser('gate',parents=[json_flag],help='decide base..head of a git repository without a server; exit 0 ACCEPT, 1 BLOCK, 2 REVIEW')
    p.add_argument('--repository',help='git repository top level (default: the repository containing the current folder)')
    p.add_argument('--base',help="base commit (default: origin/HEAD, else branch main, else master; none -> REVIEW)")
    p.add_argument('--head',default='HEAD',help='head commit (default: HEAD)')
    p.add_argument('--output-dir',help='where to write asent-report.json and asent-summary.md (default: the repository top level when --repository is not given, else the current folder)')
    p.add_argument('--data-dir',help='keep and reuse run data (verdict cache) here')
    p.add_argument('--keep-workdir',action='store_true',help='do not delete the temporary work directory')
    args=parser.parse_args(argv)
    if args.version:
        if args.json_top or getattr(args,'json',False):emit_json({'name':'asent','version':VERSION})
        else:print(f'asent {VERSION}')
        return 0
    if args.action is None:parser.error('a command is required (asent --help lists them)')
    if args.action=='init':return init_command(args)
    if args.action=='gate':return gate_command(args)
    if args.action=='doctor':return doctor_command(args)
    if args.action=='dashboard':return dashboard_command(args)
    if args.action=='report' and (args.run is None or args.legacy_run is not None):return report_command(args)
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

def entry():
    """The installed `asent` command (pyproject.toml [project.scripts]); same as `python -m backend.cli`."""
    try:raise SystemExit(main())
    except (httpx.HTTPError,ValueError,FileNotFoundError,TimeoutError) as e:print(str(e),file=sys.stderr);raise SystemExit(2)

if __name__=='__main__':entry()
