#!/usr/bin/env python3
"""Render deterministic, evidence-grounded ASENT defense narratives locally."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "frontend/public/defense-replays"
DB = ROOT / "runtime/asent.sqlite3"
W, H, FPS = 1280, 720, 12
SECONDS_PER_STAGE = 2.6
BG = (12, 21, 30)
PANEL = (23, 36, 48)
MUTED = (155, 175, 190)
WHITE = (238, 245, 248)
GREEN = (78, 210, 151)
AMBER = (244, 185, 75)
RED = (239, 105, 106)
BLUE = (91, 174, 238)
CYAN = (81, 218, 218)

FONT_DIR = Path('/usr/share/fonts/truetype/dejavu')
FONT = ImageFont.truetype(str(FONT_DIR / 'DejaVuSans.ttf'), 19)
SMALL = ImageFont.truetype(str(FONT_DIR / 'DejaVuSans.ttf'), 15)
TINY = ImageFont.truetype(str(FONT_DIR / 'DejaVuSans.ttf'), 13)
MED = ImageFont.truetype(str(FONT_DIR / 'DejaVuSans-Bold.ttf'), 23)
TITLE = ImageFont.truetype(str(FONT_DIR / 'DejaVuSans-Bold.ttf'), 36)


def load_data():
    if not DB.exists():
        return None, {}, []
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    runs = [json.loads(r['body']) for r in con.execute('SELECT body FROM runs ORDER BY rowid DESC')]
    completed = [r for r in runs if r.get('lifecycle') == 'COMPLETE']
    # A partial/errored attempt is not presented as a completed source run.
    # With no completed run, render the supported model without run evidence.
    run = completed[0] if completed else None
    evidences = {}
    if run:
        for row in con.execute('SELECT body,content_hash,stale FROM evidence WHERE run_id=? ORDER BY rowid', (run['run_id'],)):
            e = json.loads(row['body'])
            actual = hashlib.sha256(json.dumps(e, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
            # Storage digest uses the project's canonical JSON encoder; trust its stored check in exported files if
            # this implementation's serialization differs, but preserve the stale bit from SQLite.
            e['stale'] = bool(row['stale'])
            e['integrity_valid'] = actual == row['content_hash']
            evidences[e['analyzer']] = e
    con.close()
    scenarios = json.loads((ROOT / 'scenarios/catalog.json').read_text())
    rules = json.loads((ROOT / 'backend/threat_repo/seed/sable_rules.json').read_text())
    return run, evidences, (scenarios, rules)


def wrap(text, font, width):
    words, lines, line = text.split(), [], ''
    for word in words:
        test = (line + ' ' + word).strip()
        if font.getsize(test)[0] > width and line:
            lines.append(line); line = word
        else: line = test
    if line: lines.append(line)
    return lines


def draw_text(draw, xy, text, font=FONT, fill=WHITE, width=None, spacing=7):
    x, y = xy
    for line in (wrap(str(text), font, width) if width else [str(text)]):
        draw.text((x, y), line, font=font, fill=fill)
        y += font.size + spacing
    return y


def evidence_status(evidence, module):
    e = evidence.get(module)
    if not e: return 'MISSING', AMBER
    status = e.get('status', 'UNKNOWN')
    return status, RED if status in ('REJECTED', 'REJECT', 'REGRESSED') else (GREEN if status in ('VERIFIED', 'ACCEPT', 'PRESERVED') else AMBER)


def card_items(module, run, ev, model):
    title = run.get('title', 'InvoiceHub') if run else 'InvoiceHub bundled project'
    rid = run.get('run_id', 'no stored run') if run else 'no stored run'
    cavr, _ = evidence_status(ev, 'CAVR'); satra, _ = evidence_status(ev, 'SATRA'); sable, _ = evidence_status(ev, 'SABLE')
    if module == 'CAVR':
        e = ev.get('CAVR', {}); d = e.get('details', {}); node = next(iter(d.get('nodes', [])), {})
        contract = node.get('contract', {})
        static = node.get('static', {}); graph = node.get('causal_graph', {})
        trigger_count = len(static.get('triggers', []))
        event_count = len([n for n in graph.get('nodes', []) if n.get('kind') not in ('package', 'predicate')])
        required = ', '.join(f"{x.get('capability')} ({x.get('scope')})" for x in contract.get('required', [])) or 'not recorded'
        denied = ', '.join(contract.get('denied', [])) or 'not recorded'
        return [
            ('01  DEVELOPER CONTEXT', f'{title}  ·  InvoiceHub / local PDF extraction'),
            ('02  DEPENDENCY ARTIFACT', (f"{node.get('name','name not recorded')} {node.get('version','version not recorded')}  ·  {node.get('ecosystem','ecosystem not recorded')} · sha256 {node.get('sha256','not recorded')[:12]}…" if node else 'No dependency artifact object in selected evidence')),
            ('03  CAPABILITY CONTRACT', f'Required: {required} · denied: {denied}'),
            ('04  TRIGGER SELECTION', f"Stored static trigger candidates: {trigger_count}; selected runtime trigger: not recorded · {static.get('coverage','coverage not recorded')}"),
            ('05  NORMAL EXECUTION', f"Dynamic runtime evidence: {'present' if node.get('runtime') else 'not present'} · static result: {node.get('status','UNKNOWN')}"),
            ('06  CONTROLLED ACTIVATION', "Counterfactual runs belong to the CAVR deep stage of gate runs (docs/cavr-demo.md, M2 demo: real wheels); not executed in this stored run"),
            ('07  OBSERVED SECURITY EVENTS', f'Stored event nodes: {event_count}; CAVR violations: {len(node.get("violations",[]))}'),
            ('08  CAUSAL LINKAGE', f"Stored graph: {len(graph.get('nodes',[]))} node(s), {len(graph.get('edges',[]))} edge(s); linkage exists only when events are evidenced"),
            ('09  GATE DECISION', f'CAVR {cavr}  ·  non-success statuses remain visible'),
            ('10  BOUNDED ASSURANCE', (e.get('residual_uncertainty') or ['Source/capability model is bounded'])[0]),
        ]
    if module in ('SATRA', 'SATRA-RV'):
        e = ev.get('SATRA', {}); d = e.get('details', {})
        contract = d.get('contract', {})
        executions = d.get('executions', {})
        base_exec = executions.get('trusted_baseline', {})
        adaptive = d.get('adaptive', {})
        docker_note = ('Docker image unavailable; trusted test did not execute' if base_exec.get('backend') == 'docker' and base_exec.get('exit_code') not in (0, None) else 'Trusted deterministic checks recorded in stored execution evidence')
        if adaptive.get('model') and adaptive.get('tokens') is not None:
            adaptive_note = f"Ollama request recorded: {adaptive['model']} · validations: {len(adaptive.get('validations',[]))}"
        elif adaptive.get('validations'):
            adaptive_note = f"Adaptive validation records: {len(adaptive['validations'])} · model execution identity not recorded"
        else:
            adaptive_note = f"Ollama conditional/available by policy: {bool(adaptive.get('available'))} · no test validations recorded"
        contract_line = (f"{contract.get('route','route not recorded')} · {contract.get('subject','subject not recorded')} → HTTP {contract.get('expected_status','not recorded')}, state effect: {contract.get('state_effect','not recorded')}" if contract else 'No stored Security Change Contract')
        return [
            ('01  TRUSTED BASELINE', 'InvoiceHub trusted tree + registered authorization policy'),
            ('02  APPLICATION SECURITY DIFF', f"Changed surfaces: {', '.join((run or {}).get('changed_surfaces',{}).get('SATRA',[])) or 'none in selected run'} · stored diff is {'present' if d.get('diff') else 'empty'}"),
            ('03  SECURITY CHANGE CONTRACT', contract_line),
            ('04  TRUSTED DETERMINISTIC CHECKS', docker_note),
            ('05  CONDITIONAL ADAPTIVE TEST', adaptive_note),
            ('06  VALIDATED TEST', f'SATRA stored outcome: {satra} · oracle accepted: {d.get("oracle",{}).get("accepted",False)}'),
            ('07  REPAIR CANDIDATE', 'No repair candidate is evidenced in this selected run'),
            ('08  BEFORE / AFTER DIFFERENTIAL', f"Baseline exit {base_exec.get('exit_code','not recorded')} · counterfactual: {d.get('oracle',{}).get('diagnosis','not recorded')} · {d.get('oracle',{}).get('reason','') }"),
            ('09  ACCEPT / REJECT / INCONCLUSIVE', f'Actual module result: {satra}'),
            ('10  EVIDENCE LIMIT', (e.get('residual_uncertainty') or ['No SATRA uncertainty recorded'])[0]),
        ]
    if module == 'SABLE':
        e = ev.get('SABLE', {}); d = e.get('details', {}); hyp = next(iter(d.get('hypotheses', [])), {})
        base_nodes=len(d.get('baseline_graph',{}).get('nodes',[])); candidate_nodes=len(d.get('candidate_graph',{}).get('nodes',[]))
        tool_notes=[]
        for tool in d.get('optional_tools',[]):
            if 'exit_code' in tool:
                tool_notes.append(f"{tool.get('tool')} {tool.get('claim','tool')} result recorded (exit {tool['exit_code']})")
            elif tool.get('available'):
                tool_notes.append(f"{tool.get('tool')} available; no execution result recorded")
            else:
                tool_notes.append(f"{tool.get('tool')} unavailable")
        optional_note=' · '.join(tool_notes) or 'No Terraform/Checkov execution evidence recorded'
        return [
            ('01  TERRAFORM / HCL BASELINE', 'Trusted inline Terraform graph from stored SABLE evidence'),
            ('02  LOGICAL RESOURCE CHANGE', f'Selected run graph sizes: baseline {base_nodes} → candidate {candidate_nodes}; moves recorded: {len(d.get("moves",[]))}'),
            ('03  SUCCESSOR MAPPING', f"{d.get('successor') or hyp.get('address') or 'No unique successor'} · evidence score {hyp.get('score','not recorded')} · {d.get('correspondence_reason','')}"),
            ('04  ENCRYPTION AT REST', 'UNKNOWN · current SABLE model does not evaluate this obligation'),
            ('05  BLOCK PUBLIC ACCESS', 'UNKNOWN · current SABLE model does not evaluate this obligation'),
            ('06  SERVER ACCESS LOGGING', 'UNKNOWN · current SABLE model does not evaluate this obligation'),
            ('07  PRESERVATION / REGRESSION / UNKNOWN', f'Supported IAM obligation result: {sable}'),
            ('08  EVIDENCE DECISION', f'{optional_note} · inline IAM model only; no deployed AWS state'),
        ]
    return [
        ('01  MODULE EVIDENCE OBJECTS', f'CAVR {cavr}   ·   SATRA-RV {satra}   ·   SABLE {sable}'),
        ('02  VALIDITY / INVALIDATION', ' · '.join(f"{m}: {'missing' if m not in ev else ('stale' if ev[m].get('stale') else ('integrity valid' if ev[m].get('integrity_valid') else 'integrity invalid'))}" for m in ('CAVR','SATRA','SABLE'))),
        ('03  APPLICABLE BOUNDARIES', ', '.join((run or {}).get('applicable', [])) or 'No applicable module list stored'),
        ('04  CONVERGENCE', 'A missing, stale, invalid or inconclusive applicable result cannot silently become ACCEPT'),
        ('05  ASENT FINAL TRUST GATE', f"Actual stored decision: {(run or {}).get('final_decision','REVIEW')}"),
        ('06  REASONS', '; '.join((run or {}).get('reasons', [])) or 'No stored decision reason'),
        ('07  SOURCE RUN', rid),
    ]


def scene_image(module, scene_idx, scene_total, headline, detail, status, run, ev, progress, module_color, timeline_progress=None, mechanism_idx=0, motion=0.0):
    """A spatial, animated system diagram; annotations explain visible objects."""
    if module == 'SATRA-RV': module = 'SATRA'
    im=Image.new('RGB',(W,H),BG); d=ImageDraw.Draw(im)
    # Pillow 7 on the POC image lacks rounded_rectangle; crisp vector boxes work there too.
    def rr(xy,radius=0,**kw): d.rectangle(xy,**kw)
    for x in range(0,W,48): d.line((x,0,x,H),fill=(19,31,42))
    for y in range(0,H,48): d.line((0,y,W,y),fill=(19,31,42))
    d.rectangle((0,0,W,7),fill=module_color)
    d.text((48,24),'ASENT  /  SECURITY MECHANISM DEMONSTRATION',font=SMALL,fill=CYAN)
    d.text((48,51),module,font=TITLE,fill=WHITE)
    d.text((760,65),'CONTROLLED / LOCAL MODEL · LIVE EVIDENCE AUTHORITATIVE',font=TINY,fill=AMBER)
    d.text((48,108),headline,font=MED,fill=WHITE)
    rr((38,151,1242,608),18,fill=(14,27,38),outline=(43,63,77),width=2)
    ix=mechanism_idx; t=motion%1
    def box(x,y,w,h,title,sub='',c=BLUE,fill=(25,42,55)):
        rr((x,y,x+w,y+h),11,fill=fill,outline=c,width=2); d.text((x+12,y+10),title,font=SMALL,fill=c)
        if sub: draw_text(d,(x+12,y+35),sub,TINY,WHITE,w-24,3)
    def arrow(a,b,c=CYAN,label='',phase=t):
        import math
        x1,y1=a;x2,y2=b;d.line((x1,y1,x2,y2),fill=c,width=4); ang=math.atan2(y2-y1,x2-x1);q=12
        d.polygon([(x2,y2),(x2-q*math.cos(ang-.5),y2-q*math.sin(ang-.5)),(x2-q*math.cos(ang+.5),y2-q*math.sin(ang+.5))],fill=c)
        if label:d.text(((x1+x2)//2-35,(y1+y2)//2-22),label,font=TINY,fill=c)
        px=x1+(x2-x1)*phase;py=y1+(y2-y1)*phase;d.ellipse((px-7,py-7,px+7,py+7),fill=WHITE,outline=c,width=2)
    def proc(x,y,title='InvoiceHub',sub='isolated process'):
        rr((x,y,x+184,y+112),16,fill=(25,54,61),outline=CYAN,width=3)
        d.ellipse((x+14,y+18,x+50,y+54),outline=CYAN,width=3);d.arc((x+9,y+37,x+56,y+91),180,360,fill=CYAN,width=3)
        d.text((x+64,y+22),title,font=SMALL,fill=WHITE);d.text((x+64,y+49),sub,font=TINY,fill=MUTED);d.line((x+14,y+91,x+169,y+91),fill=(66,101,109),width=2)
    def pkg(x,y,name,version,digest):
        rr((x,y,x+164,y+104),9,fill=(43,54,66),outline=BLUE,width=2);d.polygon([(x+133,y),(x+164,y+25),(x+133,y+25)],fill=(78,104,122));d.text((x+12,y+9),'PACKAGE FILE',font=TINY,fill=BLUE);d.text((x+12,y+32),str(name)[:19],font=TINY,fill=WHITE);d.text((x+12,y+51),str(version)[:19],font=TINY,fill=WHITE);d.text((x+12,y+76),'sha256 '+(str(digest)[:12]+'…' if digest else 'not recorded'),font=TINY,fill=MUTED)
    def bucket(x,y):
        d.ellipse((x,y,x+180,y+34),fill=(48,55,83),outline=(182,144,255),width=2);d.rectangle((x,y+17,x+180,y+103),fill=(42,47,72),outline=(182,144,255),width=2);d.ellipse((x,y+83,x+180,y+119),fill=(42,47,72),outline=(182,144,255),width=2);d.text((x+18,y+46),'S3 · invoice_data',font=SMALL,fill=WHITE)
    if module=='CAVR':
        dep=next(iter(ev.get('CAVR',{}).get('details',{}).get('nodes',[])),{});name=dep.get('name','pdf-parser');version=dep.get('version','2.4.1');digest=dep.get('sha256')
        if ix==0:
            box(285,204,710,332,'DEVELOPER WORKSPACE','InvoiceHub',BLUE)
            for j,s in enumerate(['requirements.txt',f'{name}=={version}','import pdf_parser','extract_text(invoice.pdf)']):d.text((345,273+j*54),s,font=FONT if j<2 else SMALL,fill=CYAN if j==0 else WHITE)
        elif ix==1:
            box(140,296,250,114,'REGISTRY / RESOLVER','requested name → candidate',AMBER)
            pkgx=int(800-240*t);pkg(pkgx,302,name,version,digest);arrow((390,352),(800,352),AMBER,'resolved artifact',t)
        elif ix==2:
            pkgx=int(125+520*t);pkg(pkgx,307,name,version,digest)
            rr((834,219,1147,527),26,fill=(16,38,44),outline=CYAN,width=4);d.text((871,239),'ISOLATED RUNTIME',font=SMALL,fill=CYAN)
            proc(895,310,'InvoiceHub','process · PID 204')
            arrow((pkgx+164,358),(895,365),BLUE,'load package',t)
        else:
            rr((286,184,994,553),32,fill=(16,38,44),outline=CYAN,width=4)
            d.text((322,198),'INVOICEHUB  /  RUNNING PROCESS',font=MED,fill=CYAN)
            d.ellipse((537,260,743,466),fill=(25,54,61),outline=CYAN,width=5)
            d.ellipse((600,303,680,383),outline=CYAN,width=5);d.arc((580,354,700,446),180,360,fill=CYAN,width=5)
            d.text((515,474),'InvoiceHub · isolated process',font=SMALL,fill=WHITE)
            # Capability boundary reads as an environment ring with attached permits.
            for j,(s,c) in enumerate([('PDF READ  ✓',GREEN),('TEMP WRITE  ✓',GREEN),('NETWORK  ×',RED)]):
                rr((357+j*200,217,533+j*200,252),16,fill=(28,43,51),outline=c,width=2);d.text((370+j*200,227),s,font=TINY,fill=c)
            if ix>=4:
                rr((80,319,228,421),18,fill=(38,50,62),outline=GREEN,width=3);d.text((104,338),'PDF',font=MED,fill=GREEN);d.text((98,379),'invoice',font=TINY,fill=WHITE);arrow((228,369),(534,369),GREEN,'document',t)
                if ix>=4:d.text((768,342),'TEXT',font=SMALL,fill=GREEN);arrow((743,390),(844,390),GREEN,'extract',t)
            if ix>=5:
                d.ellipse((90,458,151,519),fill=(68,51,28),outline=AMBER,width=3);d.text((104,480),'KEY',font=TINY,fill=AMBER);arrow((151,488),(535,418),AMBER,'controlled trigger',t)
            if ix>=6:
                rr((1050,368,1208,464),18,fill=(49,29,33),outline=RED,width=3);d.text((1071,389),'NETWORK',font=SMALL,fill=RED);d.text((1074,421),'sink',font=TINY,fill=WHITE)
                arrow((743,390),(1050,412),RED,'denied attempt',t)
            if ix>=7:
                rr((80,506,475,557),14,fill=(39,37,29),outline=AMBER,width=2);d.text((101,523),f"CAVR  {evidence_status(ev,'CAVR')[0]} · controlled event model",font=SMALL,fill=AMBER)
                rr((823,506,1002,557),14,fill=(40,30,32),outline=RED,width=2);d.text((842,523),'EVENT TOKEN',font=SMALL,fill=RED)
                arrow((914,464),(914,506),AMBER,'observed',t)
    elif module=='SATRA':
        e=ev.get('SATRA',{});det=e.get('details',{});con=det.get('contract',{});ex=det.get('executions',{}).get('trusted_baseline',{});actual=('NO EXECUTION · exit '+str(ex.get('exit_code'))) if ex.get('backend')=='docker' and ex.get('exit_code') not in (None,0) else 'response not recorded'
        if ix<=1:
            box(111,198,1058,358,'TRUSTED REPOSITORY' if ix==0 else 'CANDIDATE CODE DIFF','InvoiceHub · app/security.py',BLUE if ix==0 else AMBER)
            lines=['def get_invoice(user, invoice_id):','    invoice = load(invoice_id)','    if invoice.owner_id != user.id:','        raise Forbidden(403)','    return invoice']
            for j,s in enumerate(lines):
                col=AMBER if j in (2,3) else WHITE;d.text((153,266+j*47),s,font=FONT,fill=col)
                if j in (2,3):d.line((142,288+j*47,690,288+j*47),fill=(81,74,53),width=1)
            if ix==1:
                rr((745,276,1098,424),10,fill=(28,39,51),outline=AMBER,width=2);d.text((770,299),'- owner check removed',font=SMALL,fill=RED);d.text((770,340),'+ candidate authorization change',font=SMALL,fill=GREEN);arrow((745,351),(662,351),GREEN,'patch',t)
        elif ix==2:
            box(115,223,440,132,'SECURITY CONTRACT',f"{con.get('route','GET /invoices/{id}')}  →  HTTP {con.get('expected_status',403)}",CYAN)
            box(725,223,440,132,'CANDIDATE BUILD','authorization diff enters build',AMBER);arrow((555,289),(725,289),AMBER,'code change',t)
        elif ix in (3,4,5):
            rr((196,190,1084,557),24,fill=(16,38,44),outline=CYAN,width=4);d.text((231,208),'DISPOSABLE SANDBOX  /  InvoiceHub API',font=MED,fill=CYAN);proc(558,274,'InvoiceHub API','candidate process')
            if ix>=4:
                box(249,435,205,76,'HTTP REQUEST','GET /invoices/17',BLUE);arrow((454,473),(558,377),BLUE,'owner=Bob',t)
            if ix>=5:
                box(803,435,239,76,'HTTP RESPONSE',actual,AMBER);arrow((742,377),(803,473),AMBER,'observed',t)
        elif ix==6:
            d.text((101,202),'SECURITY ORACLE',font=MED,fill=AMBER)
            box(113,273,432,147,'EXPECTED',f"HTTP {con.get('expected_status',403)}",GREEN)
            box(735,273,432,147,'OBSERVED',actual,AMBER);arrow((545,344),(735,344),AMBER,'compare',t)
            d.text((338,485),'LOCAL OLLAMA  ·  CONDITIONAL / NOT EXECUTED',font=SMALL,fill=AMBER)
        else:
            box(98,208,345,137,'BEFORE','same request · no response observed',AMBER)
            box(836,208,345,137,'AFTER','model patch · not stored',MUTED)
            arrow((443,277),(836,277),CYAN,'same request repeated',t)
            d.text((480,401),'MODEL PATCH',font=SMALL,fill=WHITE);d.text((435,434),'- owner check → + enforce owner match',font=TINY,fill=GREEN)
            rr((470,495,814,558),14,fill=(43,39,28),outline=AMBER,width=2);d.text((523,516),f"SATRA  {evidence_status(ev,'SATRA')[0]}",font=MED,fill=AMBER)
            d.text((851,514),'Docker attempt did not execute a test.',font=TINY,fill=AMBER)
    elif module=='SABLE':
        e=ev.get('SABLE',{});det=e.get('details',{});hyp=next(iter(det.get('hypotheses',[])),{});succ=det.get('successor') or hyp.get('address') or 'unresolved'
        # Let the bucket occupy the stage; Terraform and IAM appear only for the action that needs them.
        if ix==0:
            box(92,205,470,340,'TERRAFORM / HCL','', (182,144,255))
            for j,s in enumerate(['resource "aws_s3_bucket" "invoice_data" {','  bucket = "invoice-data"','}','resource "aws_iam_role_policy" "app" {','  action = "s3:GetObject"','  resource = bucket.arn','}']):d.text((118,259+j*40),s,font=SMALL if j<3 else TINY,fill=WHITE if j not in (0,3) else (200,175,255))
            d.text((681,305),'HCL → RESOURCE',font=SMALL,fill=(182,144,255));bucket(846,365)
        elif ix in (1,2):
            bucket(573,313)
            box(116,319,215,100,'IAM ROLE','application-role',CYAN)
            d.text((373,339),'s3:GetObject',font=MED,fill=CYAN);arrow((331,365),(573,365),CYAN,'allowed action',t)
            if ix==2:d.text((582,472),'ROLE → ACTION → BUCKET',font=SMALL,fill=CYAN)
        elif ix in (3,4):
            oldx=170; newx=820
            box(70,228,350,105,'TERRAFORM ADDRESS','aws_s3_bucket.invoice_data',AMBER)
            box(860,228,320,105,'NEW ADDRESS',str(succ)[:35],GREEN)
            d.text((456,220),'RESOURCE REFACTOR',font=SMALL,fill=(182,144,255))
            bx=int(oldx+(newx-oldx)*t) if ix==3 else newx
            bucket(bx,379)
            if ix==3:arrow((420,280),(860,280),GREEN,'lineage follows resource',t)
            else:
                d.line((420,280,860,280),fill=GREEN,width=3)
                for k in range(5):
                    px=420+(860-420)*((t+k*.2)%1);d.ellipse((px-4,276,px+4,284),fill=(220,255,231))
                d.text((485,324),'SAME LOGICAL RESOURCE · SUCCESSOR TRACE',font=TINY,fill=GREEN)
            if ix==4:
                box(70,401,215,78,'IAM ROLE','application-role',CYAN)
                arrow((285,440),(bx,440),CYAN,'s3:GetObject follows',t)
        elif ix==5:
            bucket(177,313)
            d.text((412,213),'BUCKET PROPERTIES',font=MED,fill=AMBER)
            for j,s in enumerate(['Encryption at rest','Block Public Access','Server access logging']):
                rr((414,266+j*78,1088,326+j*78),12,fill=(28,39,51),outline=(177,132,59),width=2);d.text((441,284+j*78),s,font=FONT,fill=WHITE);d.text((891,283+j*78),'UNKNOWN',font=MED,fill=AMBER)
            d.text((414,518),'OUTSIDE CURRENT SUPPORTED SLICE',font=TINY,fill=AMBER)
        else:
            bucket(141,337);box(387,318,315,110,'IAM RELATIONSHIP','application-role → s3:GetObject',CYAN);arrow((702,371),(895,371),CYAN,'checked')
            rr((905,292,1174,457),18,fill=(36,34,50),outline=(182,144,255),width=3)
            d.text((936,317),'SUPPORTED SABLE MODEL',font=SMALL,fill=(205,188,255));d.text((963,366),evidence_status(ev,'SABLE')[0],font=TITLE,fill=GREEN if evidence_status(ev,'SABLE')[0]=='PRESERVED' else AMBER)
            d.text((388,489),'Controlled local resource model · no external tool execution claimed',font=TINY,fill=AMBER)
    else:
        if ix in (0,1):
            proc(515,259,'InvoiceHub','package + runtime')
            if ix==0: pkg(252,272,'pdf-parser','2.4.1',next(iter(ev.get('CAVR',{}).get('details',{}).get('nodes',[])),{}).get('sha256'))
            else:
                box(809,293,197,67,'EVENT EVIDENCE','causal token',BLUE);arrow((699,315),(809,326),BLUE,'observed event',t)
        elif ix in (2,3):
            if ix==2:
                box(125,268,316,166,'CANDIDATE CODE','authorization change',CYAN)
                rr((734,207,1120,505),24,fill=(16,38,44),outline=CYAN,width=4);d.text((770,226),'DISPOSABLE SANDBOX',font=SMALL,fill=CYAN);proc(832,289,'InvoiceHub API','candidate process')
            else:
                box(188,301,239,83,'ORACLE EVIDENCE','request / response',CYAN)
                arrow((427,343),(623,343),CYAN,'comparison',t)
                rr((623,274,1058,420),18,fill=(30,42,48),outline=AMBER,width=2);d.text((666,300),'SATRA  '+evidence_status(ev,'SATRA')[0],font=MED,fill=AMBER);d.text((666,352),'Docker attempt: no test execution',font=SMALL,fill=WHITE)
        elif ix in (4,5):
            bucket(820,293);box(160,299,229,92,'IAM ROLE','application-role',CYAN);arrow((389,345),(820,345),CYAN,'s3:GetObject',t)
            if ix==5:
                for j,(m,c) in enumerate([('CAVR',BLUE),('SATRA',CYAN),('SABLE',(182,144,255))]):
                    x=164+j*330;st,_=evidence_status(ev,m);d.ellipse((x,464,x+68,532),fill=(26,38,49),outline=c,width=3);d.text((x+14,486),m,font=TINY,fill=c);d.text((x+86,483),st,font=SMALL,fill=WHITE);arrow((x+34,464),(640,425),c,'',t)
        else:
            rr((236,196,1044,551),34,fill=(25,38,49),outline=GREEN,width=5)
            d.text((431,224),'ASENT TRUST GATE',font=MED,fill=GREEN)
            for j,(m,c) in enumerate([('CAVR',BLUE),('SATRA',CYAN),('SABLE',(182,144,255))]):
                st,_=evidence_status(ev,m);d.text((353,291+j*45),m,font=SMALL,fill=c);d.text((510,291+j*45),st,font=SMALL,fill=WHITE)
            decision=(run or {}).get('final_decision','REVIEW');reason='; '.join((run or {}).get('reasons',[])) or 'No completed run decision stored';col=AMBER if decision=='REVIEW' else GREEN
            d.text((772,289),decision,font=TITLE,fill=col);draw_text(d,(772,338),reason,TINY,WHITE,225,3)
            d.text((362,473),'VALIDITY   ·   FRESHNESS   ·   APPLICABLE SCOPE',font=SMALL,fill=MUTED)
    rid=(run or {}).get('run_id','model-only');ts=max((e.get('created_at','') for e in ev.values()),default='module definitions only') or 'module definitions only'
    d.text((48,633),f'SOURCE {rid} · {ts} · controlled/local visualization; current live evidence authoritative',font=TINY,fill=MUTED)
    tp=progress if timeline_progress is None else timeline_progress;d.line((48,680,1230,680),fill=(48,68,81),width=2);d.line((48,680,48+int(1182*tp),680),fill=module_color,width=4)
    return im
def render_status(module, idx, ev, run):
    if module == 'CAVR':
        states=['PROJECT MODEL','ARTIFACT HASHED','CONTRACT STORED','NO TRIGGER SELECTED','NO RUNTIME EVIDENCE','CONTROLLED CASE NOT RUN','0 EVENT NODES','NO CAUSAL EVENT','', 'BOUNDED ASSURANCE']
        if idx == 8: return evidence_status(ev,'CAVR')[0]
        return states[idx]
    if module == 'SATRA':
        e=ev.get('SATRA',{}); d=e.get('details',{}); base=d.get('executions',{}).get('trusted_baseline',{}); adaptive=d.get('adaptive',{})
        if idx in (0,): return 'TRUSTED BASELINE'
        if idx in (1,): return 'DIFF EMPTY' if not d.get('diff') else 'SECURITY DIFF STORED'
        if idx in (2,): return 'CONTRACT STORED' if d.get('contract') else 'CONTRACT MISSING'
        if idx in (3,): return 'DOCKER UNAVAILABLE' if base.get('backend')=='docker' and base.get('exit_code') not in (0,None) else 'CHECK EVIDENCE'
        if idx == 4: return 'OLLAMA REQUEST EVIDENCED' if adaptive.get('model') and adaptive.get('tokens') is not None else ('ADAPTIVE RECORDS' if adaptive.get('validations') else 'CONDITIONAL / NOT RUN')
        if idx in (5,8): return evidence_status(ev,'SATRA')[0]
        if idx == 6: return 'NO REPAIR EVIDENCE'
        if idx == 7: return d.get('oracle',{}).get('diagnosis','UNKNOWN')
        if idx == 9: return 'BOUNDED ASSURANCE'
    if module == 'SABLE':
        if idx in (3,4,5): return 'UNKNOWN'
        if idx == 6: return evidence_status(ev,'SABLE')[0]
        if idx == 7: return 'BOUNDED LOCAL MODEL'
    if module == 'INTEGRATED' and idx == 4:
        return (run or {}).get('final_decision','REVIEW')
    if module == 'INTEGRATED' and idx in (0,1,2): return evidence_status(ev,('CAVR','SATRA','SABLE')[idx])[0]
    if module == 'INTEGRATED' and idx in (3,): return 'VALIDITY CHECKED'
    if module == 'INTEGRATED' and idx in (5,): return 'GATE REASONS STORED'
    if module == 'INTEGRATED' and idx in (6,): return 'SOURCE RUN'
    return 'MODEL STAGE'


def render_video(name, title, module, items, run, ev, module_color, output):
    total = len(items); duration = total * SECONDS_PER_STAGE
    display_module = 'SATRA-RV' if module == 'SATRA' else module
    cmd=['ffmpeg','-hide_banner','-loglevel','error','-y','-f','rawvideo','-pix_fmt','rgb24','-s',f'{W}x{H}','-r',str(FPS),'-i','-','-an','-c:v','libx264','-preset','veryfast','-crf','22','-pix_fmt','yuv420p','-movflags','+frag_keyframe+empty_moov+default_base_moof',str(output)]
    p=subprocess.Popen(cmd,stdin=subprocess.PIPE)
    try:
        for frame in range(round(duration*FPS)):
            scene=min(total-1,int(frame/(SECONDS_PER_STAGE*FPS))); within=(frame%(SECONDS_PER_STAGE*FPS))/(SECONDS_PER_STAGE*FPS)
            idx=scene; stage_module=module; stage_idx=idx; stage_color=module_color
            if module == 'FULL DEMONSTRATION':
                sections=[('CAVR',8,BLUE),('SATRA',8,CYAN),('SABLE',8,(182,144,255)),('INTEGRATED',7,GREEN)]
                offset=0
                for name_part,count,color in sections:
                    if scene < offset+count:
                        stage_module=name_part; stage_idx=scene-offset; stage_color=color; break
                    offset += count
            label,detail=items[idx]
            beat_labels={
                'CAVR':['DEVELOPER WORKSPACE','PACKAGE RESOLUTION','ARTIFACT ENTERS RUNTIME','CAPABILITY BOUNDARY','PDF THROUGH PROCESS','CONTROLLED TRIGGER','DENIED NETWORK EVENT','EVENT EVIDENCE'],
                'SATRA':['TRUSTED CODE','SECURITY DIFF','CANDIDATE BUILD','DISPOSABLE SANDBOX','REQUEST IN FLIGHT','OBSERVED RESPONSE','ORACLE COMPARISON','SAME REQUEST · BOUNDED RESULT'],
                'SABLE':['TERRAFORM → BUCKET','IAM AUTHORIZATION','ROLE · ACTION · BUCKET','RESOURCE REFACTOR','SUCCESSOR LINEAGE','BUCKET PROPERTIES','SUPPORTED IAM CHECK','STORED SABLE RESULT'],
                'INTEGRATED':['THREE EVIDENCE SOURCES','VALIDITY / FRESHNESS','APPLICABLE BOUNDARIES','EVIDENCE CONVERGENCE','ASENT TRUST GATE','REVIEW REASON','SOURCE RUN'],
            }
            if stage_module in beat_labels and stage_idx < len(beat_labels[stage_module]): label=beat_labels[stage_module][stage_idx]
            stage_status=render_status(stage_module,stage_idx,ev,run)
            stage_progress=(stage_idx+within)/(10 if stage_module in ('CAVR','SATRA') else (8 if stage_module=='SABLE' else 7))
            im=scene_image('SATRA-RV' if stage_module=='SATRA' else stage_module,scene,total,label.replace('_',' '),detail,stage_status,run,ev,stage_progress,stage_color,(scene+within)/total,stage_idx,within)
            p.stdin.write(im.tobytes())
    finally:
        p.stdin.close()
    if p.wait()!=0: raise RuntimeError(f'ffmpeg failed for {output}')
    probe=subprocess.run(['ffprobe','-v','error','-show_entries','format=duration,size','-of','json',str(output)],capture_output=True,text=True,check=True)
    meta=json.loads(probe.stdout)['format']
    return round(float(meta['duration']),2),int(meta['size'])


def main():
    global DB
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',choices=['all','cavr','satra','sable','integrated','full'],default='all')
    parser.add_argument('--db',type=Path,default=DB)
    args=parser.parse_args()
    DB=args.db.resolve()
    run,ev,models=load_data(); scenarios,rules=models
    scenario=(next((s for s in scenarios if run and s['id']==run.get('scenario')),None))
    if run: run['title']=run.get('title') or (scenario or {}).get('title','InvoiceHub')
    if run:
        # The DB stores the module body; validate integrity using the exact app digest implementation.
        sys.path.insert(0,str(ROOT))
        try:
            from backend.orchestrator.hashing import digest
            con=sqlite3.connect(DB)
            for e in ev.values():
                row=con.execute('SELECT content_hash FROM evidence WHERE id=?',(e['evidence_id'],)).fetchone()
                e['integrity_valid']=bool(row and digest({k:v for k,v in e.items() if k not in ('content_hash','integrity_valid','stale')})==row[0])
            con.close()
        except Exception: pass
    outdir=OUT;outdir.mkdir(parents=True,exist_ok=True)
    colors={'CAVR':BLUE,'SATRA':CYAN,'SABLE':(182,144,255),'INTEGRATED':GREEN}
    all_items={m:card_items(m,run,ev,models) for m in ('CAVR','SATRA','SABLE','INTEGRATED')}
    if not run:
        # Definitions are enough for an explicitly model-only controlled replay.
        print('No local run found; using module definitions only.',file=sys.stderr)
    requested=['cavr','satra','sable','integrated','full'] if args.mode=='all' else [args.mode]
    manifest_path=outdir/'manifest.json'
    try: manifest=json.loads(manifest_path.read_text())
    except Exception: manifest={'version':1,'replays':{}}
    manifest['version']=1
    for key in requested:
        if key=='full':
            items=sum((all_items[m][:7 if m=='INTEGRATED' else 8] for m in ('CAVR','SATRA','SABLE','INTEGRATED')),[])
            module='FULL DEMONSTRATION';title='Security mechanism sequence · evidence through the trust gate';color=GREEN
        else:
            module={'cavr':'CAVR','satra':'SATRA','sable':'SABLE','integrated':'INTEGRATED'}[key]
            items=all_items[module][:7 if module=='INTEGRATED' else 8];title={'cavr':'Capability assurance · trigger to decision','satra':'Security change validation · contract to differential','sable':'Infrastructure continuity · successor to evidence','integrated':'Cross-module convergence · evidence to trust gate'}[key];color=colors[module]
        filename=key+'.mp4'; target=outdir/filename
        tmp=outdir/(filename+'.tmp.mp4')
        duration,size=render_video(key,title,module,items,run,ev,color,tmp)
        os.replace(tmp,target)
        stamp=max((e.get('created_at','') for e in ev.values()),default='')
        description=('Animated controlled/local visualization from the selected ASENT run and evidence objects; live evidence remains authoritative.' if ev else 'Animated controlled/local visualization from ASENT module definitions; no run evidence was present.')
        manifest['replays'][key]={'file':filename,'title':title,'description':description,'duration_seconds':duration,'run_id':run.get('run_id') if run else None,'evidence_timestamp':stamp or None,'source':'local controlled visualization'}
        print(f'{target}: {duration:.2f}s, {size} bytes')
    tmpmanifest=manifest_path.with_suffix('.json.tmp')
    tmpmanifest.write_text(json.dumps(manifest,indent=2)+'\n')
    os.replace(tmpmanifest,manifest_path)

if __name__=='__main__': main()
