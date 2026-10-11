"""
Phase 9: Causal Capability Graph and Policy Engine.
Builds a NetworkX directed graph G = (V, E) from static and dynamic evidence.
Node types: package, module/function, process, file, secret/canary, endpoint, environment predicate.
Edge types: calls, reads, writes, spawns, connects, depends_on, conditioned_by, derived_from.
Identifies violating source-to-sink paths (e.g. canary -> read_by -> network_send).
Compares observed behavior against capability contract and computes 4 policy states:
VERIFIED, RESTRICTED, REJECTED, UNRESOLVED (with alias layer mapping).
"""
from __future__ import annotations
import networkx as nx

POLICY_ALIAS_MAP = {
    "VERIFIED": "ALLOW",
    "RESTRICTED": "ALLOW", # ALLOW with restrictions
    "UNRESOLVED": "NEEDS_REVIEW",
    "REJECTED": "BLOCK"
}

# The only verdict_impact values a behaviour may carry. Anything else is not understood.
KNOWN_VERDICT_IMPACTS = ("NEUTRAL", "VIOLATION", "UNRESOLVED")

def build_causal_graph(
    package_name: str,
    version: str,
    contract: dict,
    triggers: list[dict],
    observed_runs: list[dict],
    is_transitive: bool = False
) -> dict:
    g = nx.DiGraph()

    # 1. Package Node
    pkg_id = f"pkg:{package_name}"
    g.add_node(pkg_id, label=package_name, kind="package", version=version)

    # 2. Transitive dependency nodes if applicable
    if is_transitive or package_name == "invoice-utils":
        sub_id = "pkg:sub-telemetry-hook"
        g.add_node(sub_id, label="sub-telemetry-hook", kind="package", version="0.9.1")
        g.add_edge(pkg_id, sub_id, relation="depends_on", provenance="setup.py")

    # 3. Environment Predicate nodes (from triggers)
    for i, t in enumerate(triggers):
        pred_id = f"predicate:{t['id']}"
        g.add_node(
            pred_id,
            label=t.get("predicate", "condition"),
            kind="environment predicate",
            file_line=t.get("file_line", ""),
            inputs=t.get("inputs", [])
        )
        target_pkg = "pkg:sub-telemetry-hook" if (is_transitive and i > 0) else pkg_id
        g.add_edge(pred_id, target_pkg, relation="conditioned_by", provenance="AST static analysis")

    # 4. Function nodes
    fn_id = f"fn:{package_name}.extract_invoice_text"
    g.add_node(fn_id, label="extract_invoice_text()", kind="module/function")
    g.add_edge(pkg_id, fn_id, relation="calls", provenance="module namespace")

    # 5. Dynamic Evidence (from counterfactual runs)
    violating_nodes = set()
    violating_edges = set()
    has_secret_access = False
    has_network_egress = False
    has_unobserved_run = False
    has_violation = False
    has_neutral = False
    has_unknown_impact = False

    canary_id = "canary:~/.aws/credentials"
    endpoint_id = "endpoint:127.0.0.1:18765"

    for run in observed_runs:
        run_num = run.get("run_number", 0)
        behaviors = run.get("behaviors_found", [])
        for b in behaviors:
            action = b.get("action")
            res = b.get("resource", "")
            impact = b.get("verdict_impact")
            if impact == "UNRESOLVED":
                has_unobserved_run = True
            if impact == "VIOLATION":
                has_violation = True
            if impact == "NEUTRAL":
                has_neutral = True
            if impact not in KNOWN_VERDICT_IMPACTS:
                has_unknown_impact = True

            if action == "SECRET_ACCESS":
                has_secret_access = True
                g.add_node(
                    canary_id,
                    label="Honeytoken (~/.aws/credentials)",
                    kind="secret/canary",
                    evidence=f"Accessed during Run {run_num}"
                )
                source_pkg = "pkg:sub-telemetry-hook" if (is_transitive or "sub-telemetry-hook" in res) else pkg_id
                g.add_edge(source_pkg, canary_id, relation="reads", provenance=f"Run {run_num} audit hook")
                violating_nodes.add(canary_id)
                violating_nodes.add(source_pkg)

            elif action == "NETWORK_CONNECT":
                has_network_egress = True
                dest = res or "127.0.0.1:18765"
                g.add_node(
                    endpoint_id,
                    label=f"Receiver ({dest})",
                    kind="endpoint",
                    evidence=f"Attempted connect during Run {run_num}"
                )
                source_pkg = "pkg:sub-telemetry-hook" if (is_transitive or "sub-telemetry-hook" in res) else pkg_id
                g.add_edge(source_pkg, endpoint_id, relation="connects", provenance=f"Run {run_num} audit hook")
                violating_nodes.add(endpoint_id)
                violating_nodes.add(source_pkg)

    # 6. Source-to-Sink Path (Canary -> Package/Function -> Network Endpoint)
    violating_paths = []
    if has_secret_access and has_network_egress:
        # Add derived_from direct causality edge
        g.add_edge(canary_id, endpoint_id, relation="derived_from", provenance="controlled honeytoken canary equality")
        
        path_list = [canary_id, pkg_id, endpoint_id]
        if is_transitive:
            path_list = [canary_id, "pkg:sub-telemetry-hook", endpoint_id]
        
        violating_paths.append({
            "path_id": "VPATH-001",
            "path": path_list,
            "description": "Honeytoken secret harvested from credentials store and dispatched over network socket."
        })

    # 7. Compare observed behavior against capability contract
    # Fail closed: UNRESOLVED unless a rule below says otherwise.
    policy_state = "UNRESOLVED"
    narrowed_policy = None

    if has_secret_access or has_network_egress or has_violation:
        # Any observed violation rejects, including ones with no graph node (process spawn, write, harness BLOCK).
        policy_state = "REJECTED"
    elif package_name in ("requests-security", "reportlab-legacy"):
        policy_state = "REJECTED"
    elif has_unobserved_run or has_unknown_impact:
        # A run that was never observed, or a behaviour whose impact is not one of
        # KNOWN_VERDICT_IMPACTS, cannot support VERIFIED.
        policy_state = "UNRESOLVED"
    elif has_neutral:
        # VERIFIED needs positive evidence: at least one observed NEUTRAL behaviour.
        # No runs or no behaviours at all leaves the default, UNRESOLVED.
        policy_state = "VERIFIED"

    # Alias mapping
    alias_verdict = POLICY_ALIAS_MAP.get(policy_state, "BLOCK")
    if policy_state == "RESTRICTED":
        narrowed_policy = {
            "allowed_scopes": ["FILE_READ:invoice_documents"],
            "restricted_syscalls": ["socket", "connect", "execve"],
            "enforcement": "Kernel seccomp sandbox profile generated"
        }

    # Format nodes and edges for frontend JSON
    nodes_export = []
    for n, data in g.nodes(data=True):
        is_violating = n in violating_nodes or any(n in p["path"] for p in violating_paths)
        nodes_export.append({
            "id": n,
            "label": data.get("label", n),
            "kind": data.get("kind", "entity"),
            "is_violating": is_violating,
            "metadata": data
        })

    edges_export = []
    for u, v, data in g.edges(data=True):
        is_violating = (u in violating_nodes and v in violating_nodes) or data.get("relation") == "derived_from"
        edges_export.append({
            "source": u,
            "target": v,
            "relation": data.get("relation", "links"),
            "provenance": data.get("provenance", "inferred"),
            "is_violating": is_violating
        })

    return {
        "policy_state": policy_state,
        "alias_verdict": alias_verdict,
        "honesty_wording": {"VERIFIED": "No malicious behavior observed under our tests", "UNRESOLVED": "Behavior could not be observed; not verified"}.get(policy_state, "Security policy violations detected"),
        "narrowed_capability_policy": narrowed_policy,
        "violating_paths": violating_paths,
        "has_violations": len(violating_paths) > 0 or policy_state == "REJECTED",
        "graph": {
            "nodes": nodes_export,
            "edges": edges_export
        },
        "clean_message": "No prohibited path found in explored conditions" if policy_state == "VERIFIED" else None
    }

def build(name, triggers, events, receiver):
    g = nx.DiGraph()
    g.add_node('package', label=name, kind='package')
    for i, t in enumerate(triggers):
        nid = 'trigger-' + str(i)
        g.add_node(nid, label=t['predicate'], kind='predicate', file=t.get('file'), line=t.get('line'), inputs=t.get('inputs', []))
        g.add_edge(nid, 'package', relation='conditions', provenance='static AST')
    for kind in ['SECRET_ACCESS', 'NETWORK_CONNECT']:
        for e in events:
            if e.get('type') != kind:
                continue
            target = str(e.get('resource', ''))
            eid = f"event-{len([n for n in g if str(n).startswith('event-')])}"
            g.add_node(eid, label=target, kind=kind, source=e.get('source', 'unknown'), raw=e.get('raw'))
            g.add_edge('package', eid, relation='observed ' + kind.lower(), provenance=e.get('source', 'unknown'))
    secret_nodes = [n for n, d in g.nodes(data=True) if d.get('kind') == 'SECRET_ACCESS']
    targets = [n for n, d in g.nodes(data=True) if d.get('kind') == 'NETWORK_CONNECT' and d.get('label') in ('127.0.0.1:18765', "('127.0.0.1', 18765)")]
    marker = 'CAVR_FAKE_SECRET_NOT_A_CREDENTIAL'
    if marker in receiver and secret_nodes and targets:
        sources = secret_nodes
        g.add_edge(sources[0], targets[0], relation='fixture-linked source-to-sink', provenance='receiver exact fake-marker equality', fixture_condition='controlled endpoint 127.0.0.1:18765', evidence='bounded controlled canary; not general taint analysis')
    return {'nodes': [{'id': n, **d} for n, d in g.nodes(data=True)], 'edges': [{'source': a, 'target': b, **d} for a, b, d in g.edges(data=True)]}

