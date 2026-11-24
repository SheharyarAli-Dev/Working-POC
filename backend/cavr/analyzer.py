"""CAVR in an orchestrator run: every PyPI package is judged by the M1 pipeline (`pipeline.verify_request`).

    gate run (context.gate)   `gate_adapter.analyze_pipeline` with the gate's `gate_adapter.SETTINGS`
    demo / scenario run       the same `gate_adapter.analyze_pipeline`, with `DEMO_SETTINGS`, on the
                              requirements files of the run's frozen `.asent/` config; then
                              - a PyPI lock node that no pipeline verdict judged is UNRESOLVED
                                (`LOCKED_NOT_VERIFIED`): it would otherwise be trusted unseen;
                              - a LOCAL lock node (a vendored file or wheel) is UNRESOLVED
                                (`LOCAL_NOT_SUPPORTED`): the pipeline verifies registry artifacts only, and
                                the demo lab that read LOCAL `.py` sources was deleted (Step M2-18, Q12);
                              - any other ecosystem is UNRESOLVED.

There is no advisory rule here (Q1 option A): the pipeline asks OSV, and without an answer a package
is UNRESOLVED. A fault in the pipeline call is UNRESOLVED (`INTERNAL_ERROR`), never a pass.
The module result is REJECTED if any node is REJECTED, else UNRESOLVED if anything is not VERIFIED.

`DEMO_SETTINGS` has the shape of `gate_adapter.SETTINGS` (None = live PyPI and live OSV) and is kept
apart from it, so replacing the demo's outside world in tests never changes what a gate run asks.
"""
import json
import time

from packaging.utils import canonicalize_name, canonicalize_version

from backend.cavr import gate_adapter

DEMO_SETTINGS = {"transport": None, "osv": None, "advisory_cache_dir": None, "live_advisories": True, "deep": None}


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
    for node in locked:
        ecosystem = node.get('ecosystem', 'PyPI')
        label = f"{node.get('name')}=={node.get('version')}"
        if ecosystem == 'LOCAL':
            problem = {'name': node['name'], 'version': node['version'], 'engine': 'demo', 'status': 'UNRESOLVED',
                       'mapped': 'UNRESOLVED', 'rule': 'LOCAL_NOT_SUPPORTED',
                       'reason': f'{label}: a LOCAL lock artifact ({node.get("artifact")!r}) is not a registry artifact '
                                 'the pipeline can verify'}
        elif ecosystem != 'PyPI':
            problem = {'name': node.get('name'), 'version': node.get('version'), 'engine': 'demo', 'status': 'UNRESOLVED',
                       'mapped': 'UNRESOLVED', 'rule': 'UNSUPPORTED_ECOSYSTEM', 'reason': f'{label}: unsupported dependency ecosystem {ecosystem!r}'}
        elif (canonicalize_name(node['name']), canonicalize_version(node['version'])) in judged:
            continue
        else:
            problem = {'name': node['name'], 'version': node['version'], 'engine': 'demo', 'status': 'UNRESOLVED',
                       'mapped': 'UNRESOLVED', 'rule': 'LOCKED_NOT_VERIFIED',
                       'reason': f'{label} is pinned in dependencies.lock.json but no requirement the pipeline verified reaches it'}
        nodes.append(problem); statuses.append('UNRESOLVED'); uncertainty.append(problem['reason'])

    final = 'REJECTED' if 'REJECTED' in statuses else 'UNRESOLVED' if any(s != 'VERIFIED' for s in statuses) else 'VERIFIED'
    reasons = [details.get('reason')] if status != 'VERIFIED' and details.get('reason') else []
    reasons += [n['reason'] for n in nodes if n.get('engine') == 'demo' and n.get('status') != 'VERIFIED' and n.get('reason')]
    details = {**details, 'engine': 'pipeline', 'nodes': nodes,
               'reason': '; '.join(reasons) if reasons else details.get('reason') or 'All locked dependency nodes verified',
               'dependency_tree': {'nodes': [{'id': n['name'], 'version': n['version']} for n in locked], 'edges': lock.get('edges', [])},
               'total_ms': round((time.perf_counter() - start) * 1000, 2)}
    return final, details, uncertainty

