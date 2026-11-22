"""CAVR in an orchestrator run: every PyPI package is judged by the M1 pipeline (`pipeline.verify_request`).

    gate run (context.gate)   `gate_adapter.analyze_pipeline` with the gate's `gate_adapter.SETTINGS`
    demo / scenario run       the same `gate_adapter.analyze_pipeline`, with `DEMO_SETTINGS`, on the
                              requirements files of the run's frozen `.asent/` config; then
                              - each LOCAL lock node (a vendored controlled-reproduction module) goes
                                through the demo lab (`_lab_node`, labelled `engine: "demo-lab"`) until
                                PR 12 of docs/cavr-m2-plan.md replaces it;
                              - a PyPI lock node that no pipeline verdict judged is UNRESOLVED
                                (`LOCKED_NOT_VERIFIED`): it would otherwise be trusted unseen;
                              - any other ecosystem is UNRESOLVED.

There is no advisory rule here (Q1 option A): the pipeline asks OSV, and without an answer a package
is UNRESOLVED. A fault in the pipeline call is UNRESOLVED (`INTERNAL_ERROR`), never a pass.
The module result is REJECTED if any node is REJECTED, else UNRESOLVED if anything is not VERIFIED.

`DEMO_SETTINGS` has the shape of `gate_adapter.SETTINGS` (None = live PyPI and live OSV) and is kept
apart from it, so replacing the demo's outside world in tests never changes what a gate run asks.
"""
import json
import time
from pathlib import Path

from packaging.utils import canonicalize_name, canonicalize_version

from backend.cavr import gate_adapter
from backend.cavr.capability_contract import infer
from backend.cavr.causal_graph import build
from backend.cavr.policy import verify_runtime
from backend.cavr.sandbox import run_counterfactual
from backend.cavr.trigger_discovery import scan
from backend.integrations.registry_adapter import read_artifact
from backend.orchestrator.hashing import digest
from backend.threat_repo.package_records import packages, vulnerabilities
from backend.threat_repo.repository import active, seeds
from backend.threat_repo.source_sink_rules import correlate

DEMO_SETTINGS = {"transport": None, "osv": None, "advisory_cache_dir": None, "live_advisories": True, "deep": None}
LAB_BOUNDED = "Demo lab (LOCAL controlled reproductions only): selected Python source/capability model; does not prove arbitrary package safety"


def analyze(context, store, outdir, emit):
    if getattr(context, 'gate', False):
        return gate_adapter.analyze_pipeline(context, store, outdir, emit)
    return _analyze_demo(context, store, outdir, emit)


def _analyze_demo(context, store, outdir, emit):
    start = time.perf_counter()
    try:
        status, details, uncertainty = gate_adapter.analyze_pipeline(context, store, outdir, emit, settings=DEMO_SETTINGS)
    except Exception as exc:  # a fault in the pipeline is "unknown", never a pass
        reason = f"INTERNAL_ERROR: the pipeline failed: {type(exc).__name__}: {exc}"
        status, details, uncertainty = 'UNRESOLVED', {'engine': 'pipeline', 'reason': reason, 'pipeline': [], 'nodes': []}, [reason]
    nodes, statuses, uncertainty = list(details.get('nodes', [])), [status], list(uncertainty)
    try:
        lock = json.loads(context.read('dependencies.lock.json') or '{"packages":[]}')
    except ValueError:
        lock = None
    if not isinstance(lock, dict) or not isinstance(lock.get('packages', []), list):
        lock = {'packages': [], 'edges': []}
        uncertainty.append('dependencies.lock.json is not a JSON object with a "packages" list')
        statuses.append('UNRESOLVED')
    locked = []
    for entry in lock.get('packages', []):
        if isinstance(entry, dict) and all(isinstance(entry.get(k), str) and entry[k].strip() for k in ('name', 'version')):
            locked.append(entry)
            continue
        problem = {'name': entry.get('name') if isinstance(entry, dict) else None, 'version': None, 'engine': 'demo',
                   'status': 'UNRESOLVED', 'mapped': 'UNRESOLVED', 'rule': 'LOCK_ENTRY_INVALID',
                   'reason': f'dependencies.lock.json entry without a usable name and version: {entry!r}'[:300]}
        nodes.append(problem); statuses.append('UNRESOLVED'); uncertainty.append(problem['reason'])

    # Every release a pipeline verdict judged: the requested packages and every node of their trees.
    judged = set()
    for verdict_row in nodes:
        for item in [verdict_row, *verdict_row.get('tree_nodes', [])]:
            if item.get('name') and item.get('version'):
                judged.add((canonicalize_name(item['name']), canonicalize_version(item['version'])))
    lab_nodes = []
    for node in locked:
        ecosystem = node.get('ecosystem', 'PyPI')
        if ecosystem == 'LOCAL':
            lab_nodes.append(node)
            continue
        label = f"{node.get('name')}=={node.get('version')}"
        if ecosystem != 'PyPI':
            problem = {'name': node.get('name'), 'version': node.get('version'), 'engine': 'demo', 'status': 'UNRESOLVED',
                       'mapped': 'UNRESOLVED', 'rule': 'UNSUPPORTED_ECOSYSTEM', 'reason': f'{label}: unsupported dependency ecosystem {ecosystem!r}'}
        elif (canonicalize_name(node['name']), canonicalize_version(node['version'])) in judged:
            continue
        else:
            problem = {'name': node['name'], 'version': node['version'], 'engine': 'demo', 'status': 'UNRESOLVED',
                       'mapped': 'UNRESOLVED', 'rule': 'LOCKED_NOT_VERIFIED',
                       'reason': f'{label} is pinned in dependencies.lock.json but no requirement the pipeline verified reaches it'}
        nodes.append(problem); statuses.append('UNRESOLVED'); uncertainty.append(problem['reason'])

    if lab_nodes:
        lab_statuses, lab_notes = _lab(context, store, outdir, emit, lab_nodes, locked, nodes)
        statuses += lab_statuses
        uncertainty += lab_notes + [LAB_BOUNDED]

    final = 'REJECTED' if 'REJECTED' in statuses else 'UNRESOLVED' if any(s != 'VERIFIED' for s in statuses) else 'VERIFIED'
    reasons = [details.get('reason')] if status != 'VERIFIED' and details.get('reason') else []
    reasons += [n['reason'] for n in nodes if n.get('engine') in ('demo', 'demo-lab') and n.get('status') != 'VERIFIED' and n.get('reason')]
    details = {**details, 'engine': 'pipeline', 'nodes': nodes,
               'reason': '; '.join(reasons) if reasons else details.get('reason') or 'All locked dependency nodes verified',
               'dependency_tree': {'nodes': [{'id': n['name'], 'version': n['version']} for n in locked], 'edges': lock.get('edges', [])},
               'total_ms': round((time.perf_counter() - start) * 1000, 2)}
    return final, details, uncertainty


def _lab(context, store, outdir, emit, lab_nodes, locked, nodes):
    """The demo lab for LOCAL lock nodes (vendored controlled reproductions), as before PR 1 of the M2 plan.

    The earlier logic, for LOCAL `.py` sources only: hash-checked source, the older capability contract
    (`capability_contract.infer`), the required-rule coverage check, the trigger scan, the bounded
    counterfactual run and its runtime check. Any other LOCAL artifact (a wheel, with dependencies of its own)
    is UNRESOLVED `LOCAL_ARTIFACT_NOT_SUPPORTED`: the lab is not a package verifier. (The earlier analyzer's
    Requires-Dist check is not needed: a `.py` source has no Requires-Dist.) LOCAL
    sources are not registry packages, so no advisory applies. Appends to `nodes`; returns (statuses, notes).
    """
    statuses, uncertain = [], []
    policy = context.policy.get('dependencies', {}); allowed = policy.get('allowed', [])
    for node in lab_nodes:
        t = time.perf_counter(); record = {**node, 'engine': 'demo-lab', 'cache_hit': False}; status = 'VERIFIED'; notes = []
        emit('dependency.intercepted', {'package': node['name'], 'version': node['version'], 'source': 'exact candidate lock; no host installation'})
        if node['name'] not in allowed:
            nodes.append({**record, 'status': 'REJECTED', 'reason': 'Not permitted by registered project policy'}); statuses.append('REJECTED'); continue
        if not str(node.get('artifact', '')).endswith('.py'):
            reason = f"LOCAL_ARTIFACT_NOT_SUPPORTED: {node['name']}=={node['version']}: the demo lab reads only LOCAL .py sources, not {node.get('artifact')!r}"
            nodes.append({**record, 'status': 'UNRESOLVED', 'mapped': 'UNRESOLVED', 'rule': 'LOCAL_ARTIFACT_NOT_SUPPORTED', 'reason': reason})
            statuses.append('UNRESOLVED'); uncertain.append(reason); continue
        try:
            artifact = read_artifact(node, context.path)
        except Exception as e:
            nodes.append({**record, 'status': 'UNRESOLVED', 'reason': str(e)}); statuses.append('UNRESOLVED'); continue
        contract = infer(context, node); static = scan(artifact['sources'], context.knowledge)
        active_rules = {r['id']: r for c in ('behaviors', 'triggers') for r in active(context.knowledge, c)}
        for required in (r for r in seeds() if r['category'] in ('behaviors', 'triggers')):
            current = active_rules.get(required['id'])
            key_field = 'python_sinks' if required['category'] == 'behaviors' else 'match_calls'
            if not current or not set(required['data'].get(key_field, [])).issubset(current['data'].get(key_field, [])):
                notes.append('Required rule coverage unavailable: ' + required['id'])
        package_matches = packages(context.knowledge, node)
        known_vulns, range_unknown = vulnerabilities(context.knowledge, node)
        if range_unknown: notes.append('Unsupported advisory version ranges: ' + ', '.join(range_unknown))
        if known_vulns: status = 'REJECTED'
        if contract['confidence'] == 'insufficient': notes.append('Capability contract lacks task/call-site authority')
        advisory = {'available': True, 'mode': 'NOT APPLICABLE: local unregistered source', 'vulnerabilities': []}
        key = digest({'artifact': artifact['sha256'], 'subtree': {'packages': locked}, 'contract': contract['digest'], 'policy': context.policy,
                      'advisory': advisory['mode'], 'analyzer': 'demo-lab/1', 'package': node['name'], 'version': node['version'],
                      'threat_module_digest': context.knowledge['module_digests']['CAVR']})
        previous = store.cache_get(key)
        fast_ms = (time.perf_counter() - t) * 1000
        if previous and previous.get('status') == 'VERIFIED' and not notes and status == 'VERIFIED':
            record = {**previous, 'cache_hit': True, 'fast_gate_ms': fast_ms, 'deep_analysis_ms': 0, 'cache_key': key}
            emit('cavr.cache_hit', {'package': node['name'], 'cache_key': key}); nodes.append(record); statuses.append(record['status']); continue
        emit('cavr.fast_gate', {'package': node['name'], 'cache': 'MISS', 'duration_ms': fast_ms, 'artifact_hash': artifact['sha256']})
        for trigger in static['triggers']: emit('cavr.trigger_found', trigger)
        if static['parse_errors']: notes.append('Python source parse incomplete')
        runtime = None; violations = []; deep_ms = 0
        if static['triggers']:
            deep = time.perf_counter()
            if artifact['path'].endswith('.py'):
                runtime = run_counterfactual(artifact['path'], context.path/'fixtures/invoice.pdf', Path(outdir) / node['name'], emit)
                if runtime['available']:
                    for r in runtime['runs']: violations += verify_runtime(contract, r['events'], r['facts'].get('receiver_payloads'))
                    by_mode = {r['mode']: r for r in runtime['runs']}
                    if set(by_mode) >= {'normal', 'counterfactual'}:
                        normal, cf = by_mode['normal']['facts'], by_mode['counterfactual']['facts']
                        runtime['fixture_comparison'] = {'functional_equivalent': normal.get('functional_text') == cf.get('functional_text'), 'normal_canary_received': normal.get('canary_received'), 'counterfactual_canary_received': cf.get('canary_received'), 'deterministic_expectation_met': normal.get('canary_received') is False and cf.get('canary_received') is True and normal.get('functional_text') == cf.get('functional_text')}
                        if not runtime['fixture_comparison']['deterministic_expectation_met']:
                            notes.append('Controlled fixture did not demonstrate expected normal/counterfactual distinction')
                    if violations: status = 'REJECTED'
                else: notes.append(runtime.get('reason', 'Deep execution unavailable or failed'))
            else: notes.append('High-risk artifact requires an explicit bounded activation entry point')
            if any(not t['supported'] for t in static['triggers']): notes.append('Unexercised high-risk predicates remain')
            deep_ms = (time.perf_counter() - deep) * 1000
        elif static['sinks']:
            # A LOCAL source has no registry guard proof; every sink without a trigger needs an activation entry point.
            notes.append('Sensitive sinks require a supported activation entry point')
        if notes and status != 'REJECTED': status = 'UNRESOLVED'
        ev = [e for r in (runtime or {}).get('runs', []) for e in r.get('events', [])]
        payloads = [p for r in (runtime or {}).get('runs', []) for p in r.get('facts', {}).get('receiver_payloads', [])]
        record.update({'threat_matches': package_matches, 'known_vulnerabilities': known_vulns, 'threat_correlations': correlate(context.knowledge, ev, payloads, contract), 'threat_repo_version': context.knowledge['version'], 'status': status, 'mapped': status, 'sha256': artifact['sha256'], 'metadata': artifact['metadata'], 'contract': contract, 'dependency_use': context.dependency_context(), 'static': static, 'osv': advisory, 'runtime': runtime, 'violations': violations, 'causal_graph': build(node['name'], static['triggers'], ev, payloads), 'fast_gate_ms': round(fast_ms, 2), 'deep_analysis_ms': round(deep_ms, 2), 'cache_key': key, 'reason': 'Contract and selected static checks satisfied' if status == 'VERIFIED' else '; '.join(notes) or ('Affected by an enabled advisory' if known_vulns else 'Observed behavior violates task capability contract'), 'uncertainty': notes, 'escalation_reason': 'Security-sensitive predicate reaches sensitive sink' if static['triggers'] else 'No supported high-risk trigger found; no deep run required'})
        if status == 'VERIFIED': store.cache_put(key, record)
        nodes.append(record); statuses.append(status); uncertain += notes
    return statuses, uncertain
