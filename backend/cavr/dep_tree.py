"""C3b: the transitive dependency tree of one pinned requirement, and its subtree digest.

`build_tree(name, version, lockfile, quarantine_dir)` starts at the root and, for every node:

1. downloads the wheel and checks its SHA-256 (`pypi_client.fetch_artifact`),
2. reads the wheel's own METADATA (`wheel_meta.read_wheel`),
3. evaluates the marker of each `Requires-Dist` line for this interpreter,
4. pins each remaining child to the one version of it in the project lockfile.

How children are pinned (M1): a `Requires-Dist` line such as `leaf>=1` does not name one
version, so the version is taken from the project lockfile. A child that is not in the lockfile,
or whose locked version does not satisfy the line, makes the tree UNRESOLVED. Future work: ask
pip's own resolver with `pip install --dry-run --report` for resolver-accurate pins, so that a
project without a complete lockfile can still be resolved.

Extras are off for the root. A child that a parent asks for with extras (`mid[fast]`) gets
exactly those extras, because pip would install them.

Results: OK `TREE_BUILT`; REJECTED when any node is rejected by step 1 or 2; otherwise
UNRESOLVED when anything is unknown (`CHILD_NOT_PINNED`, `CHILD_PIN_CONFLICT`,
`LOCKFILE_INVALID`, `LOCKFILE_HASH_MISMATCH`, `PYTHON_INCOMPATIBLE`, `MARKER_INVALID`,
`TREE_BUDGET`, or the rule of a node that step 1 or 2 could not resolve). All reachable nodes
are still visited, so one REJECTED node is not hidden behind an UNRESOLVED one.

The subtree digest is the SHA-256 of the canonical JSON of the root, the sorted set of
(name, version, sha256) of every reachable node, and the sorted set of edges. A node is visited
once, so a dependency cycle ends; sorting makes the digest independent of visiting order.
"""
from __future__ import annotations
import re

from packaging.markers import InvalidMarker, Marker, UndefinedComparison, UndefinedEnvironmentName, default_environment
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name, canonicalize_version
from packaging.version import InvalidVersion, Version

from backend.cavr.pypi_client import fetch_artifact, request_problem
from backend.cavr.requirement_gate import lockfile_problems
from backend.cavr.wheel_meta import read_wheel
from backend.orchestrator.hashing import digest

MAX_NODES = 200
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ENVIRONMENT_KEYS = ("python_version", "python_full_version", "sys_platform", "platform_machine", "implementation_name")


def build_tree(name, version, lockfile, quarantine_dir, transport=None, environment=None, extras=()) -> dict:
    """Resolve, download and hash the whole tree under `name==version`.

    `lockfile` is the parsed project lockfile ({"packages": [{"name", "version", "ecosystem",
    "sha256"?}]}) or None when the project has none. `environment` overrides marker variables
    of the running interpreter (tests use it). Every result has the same keys.
    """
    fields = {"root": {"name": name if isinstance(name, str) else None, "version": version if isinstance(version, str) else None}}
    problem = request_problem(name, version)
    if problem:
        return _tree("UNRESOLVED", "INVALID_REQUEST", problem, **fields)
    root = (canonicalize_name(name), str(Version(version)))
    env = {**default_environment(), **(environment or {})}
    fields = {"root": {"name": root[0], "version": root[1]}, "environment": {key: env.get(key) for key in ENVIRONMENT_KEYS}}
    pins, problem = _pins(lockfile)
    if problem:
        return _tree("UNRESOLVED", "LOCKFILE_INVALID", "project lockfile is not usable: " + problem, **fields)

    loaded, expansions, problems = {}, {}, []
    # One node per release: `1.0` in the request and `1.0.0` in the lockfile are the same version.
    known = {(root[0], Version(root[1])): root}
    extras_for = {root: set(extras)}
    pending = [root]
    while pending:
        pending.sort()
        key = pending.pop(0)
        if key not in loaded:
            if len(loaded) >= MAX_NODES:
                problems.append(_problem(key, "tree", "UNRESOLVED", "TREE_BUDGET",
                                         f"the tree has more than {MAX_NODES} packages"))
                break
            loaded[key] = _load(key, pins, quarantine_dir, transport, env)
        node = loaded[key][0]
        if node is None:
            continue
        expansions[key] = _expand(key, node, extras_for[key], pins, env, known)
        for child, child_extras in expansions[key][3]:
            if child not in extras_for:
                extras_for[child] = set(child_extras)
                pending.append(child)
            elif not set(child_extras) <= extras_for[child]:
                # Seen before with fewer extras: its dependency lines must be evaluated again.
                extras_for[child] |= set(child_extras)
                if child not in pending:
                    pending.append(child)

    nodes, edges, excluded, failed = [], [], [], []
    for key in sorted(loaded):
        node, node_problems, failure = loaded[key]
        problems += node_problems
        if node is None:
            failed.append(failure)
            continue
        nodes.append({**node, "extras": sorted(extras_for[key])})
        node_edges, node_excluded, child_problems, _ = expansions[key]
        edges += node_edges
        excluded += node_excluded
        problems += child_problems
    problems.sort(key=lambda p: (p["node"], p["requirement"] or "", p["rule"]))
    fields.update(nodes=nodes, edges=sorted(edges, key=lambda e: (e["parent"], e["child"], e["requirement"])),
                  excluded=sorted(excluded, key=lambda e: (e["parent"], e["requirement"])), problems=problems,
                  failed_nodes=failed)

    worst = next((p for p in problems if p["result"] == "REJECTED"), None) or (problems[0] if problems else None)
    if worst:
        return _tree(worst["result"], worst["rule"], worst["reason"], **fields)
    fields["subtree_digest"] = subtree_digest(
        root, [(node["name"], node["version"], node["sha256"]) for node in nodes],
        [_split(edge["parent"]) + _split(edge["child"]) for edge in edges])
    return _tree("OK", "TREE_BUILT", f"{len(nodes)} packages downloaded and hashed, {len(edges)} dependency edges", **fields)


def subtree_digest(root, nodes, edges) -> str:
    """SHA-256 over the root, the set of (name, version, sha256) nodes and the set of
    (parent name, parent version, child name, child version) edges, each sorted.

    Versions go in in canonical form, so the digest does not depend on how a version was
    written (`1.0` or `1.0.0`)."""
    root = (root[0], _canonical(root[1]))
    nodes = {(name, _canonical(version), sha256) for name, version, sha256 in nodes}
    edges = {(parent, _canonical(parent_version), child, _canonical(child_version))
             for parent, parent_version, child, child_version in edges}
    return digest({"root": list(root), "nodes": sorted(nodes), "edges": sorted(edges)})


def _canonical(version: str) -> str:
    try:
        return canonicalize_version(Version(version))
    except InvalidVersion:
        return version


# --- internals ---------------------------------------------------------------

def _tree(outcome, rule, reason, root=None, environment=None, nodes=None, edges=None, excluded=None, problems=None,
          failed_nodes=None, subtree_digest=None) -> dict:
    return {"result": outcome, "rule": rule, "reason": reason, "root": root, "environment": environment or {},
            "nodes": nodes or [], "edges": edges or [], "excluded": excluded or [], "problems": problems or [],
            "failed_nodes": failed_nodes or [], "subtree_digest": subtree_digest}


def _label(key) -> str:
    return f"{key[0]}=={key[1]}"


def _split(label: str) -> tuple:
    name, _, version = label.partition("==")
    return (name, version)


def _problem(key, stage, outcome, rule, reason, requirement=None) -> dict:
    return {"node": _label(key), "stage": stage, "result": outcome, "rule": rule, "reason": reason, "requirement": requirement}


def _pins(lockfile):
    """({canonical name: [(Version, sha256 or None)]}, None), or (None, reason) for an unusable lockfile."""
    if lockfile is None:
        return {}, None
    problems = lockfile_problems(lockfile)
    if problems:
        return None, problems[0]
    pins = {}
    for entry in lockfile["packages"]:
        if entry["ecosystem"].lower() != "pypi":
            continue
        sha256 = entry.get("sha256")
        if sha256 is not None:
            sha256 = sha256.lower() if isinstance(sha256, str) else ""
            if not SHA256.match(sha256):
                return None, f"lockfile entry has a malformed sha256: {entry!r}"
        pins.setdefault(canonicalize_name(entry["name"]), []).append((Version(entry["version"]), sha256))
    return pins, None


def _load(key, pins, quarantine_dir, transport, env):
    """Download, hash and read one node.

    Returns (node, problems, None), or (None, problems, failure) when the node could not be
    used; `failure` keeps the full result of the step that stopped it, as evidence.
    """
    name, version = key
    artifact = fetch_artifact(name, version, quarantine_dir, transport=transport)
    if artifact["result"] != "OK":
        return (None, [_problem(key, "artifact", artifact["result"], artifact["rule"], artifact["reason"])],
                {"node": _label(key), "artifact": artifact, "metadata": None})
    metadata = read_wheel(artifact["path"], name, version)
    if metadata["result"] != "OK":
        return (None, [_problem(key, "metadata", metadata["result"], metadata["rule"], metadata["reason"])],
                {"node": _label(key), "artifact": artifact, "metadata": metadata})
    problems = []

    locked = [sha256 for locked_version, sha256 in pins.get(name, []) if locked_version == Version(version) and sha256]
    if locked and artifact["sha256"] not in locked:
        problems.append(_problem(key, "tree", "UNRESOLVED", "LOCKFILE_HASH_MISMATCH",
                                 f"{artifact['filename']} has SHA-256 {artifact['sha256']}; the project lockfile pins "
                                 f"{', '.join(locked)} (it may pin another file of this release)"))

    requires_python = metadata["requires_python"]
    if requires_python:
        try:
            fits = SpecifierSet(requires_python).contains(str(env["python_full_version"]).rstrip("+"), prereleases=True)
        except (InvalidSpecifier, InvalidVersion):
            fits = False
        if not fits:
            problems.append(_problem(key, "tree", "UNRESOLVED", "PYTHON_INCOMPATIBLE",
                                     f"{name} {version} requires Python {requires_python}; this is {env['python_full_version']}"))

    node = {"name": name, "version": version, "sha256": artifact["sha256"], "filename": artifact["filename"],
            "path": artifact["path"], "size": artifact["size"],
            "lockfile_sha256": artifact["sha256"] if locked and artifact["sha256"] in locked else None,
            "import_names": metadata["import_names"], "native_files": metadata["native_files"],
            "artifact": artifact, "metadata": metadata}
    return node, problems, None


def _expand(key, node, extras, pins, env, known):
    """The dependency lines of one node. Returns (edges, excluded, problems, [(child key, child extras)]).

    `known` maps (name, Version) to the node key already in use for that release.
    """
    edges, excluded, problems, children = [], [], [], []
    for requirement in node["metadata"]["requires_dist"]:
        raw, child_name = requirement["raw"], requirement["canonical_name"]
        if requirement["marker"]:
            try:
                marker = Marker(requirement["marker"])
                applies = any(marker.evaluate({**env, "extra": extra}) for extra in ["", *sorted(extras)])
            except (InvalidMarker, UndefinedComparison, UndefinedEnvironmentName, InvalidVersion) as exc:
                problems.append(_problem(key, "tree", "UNRESOLVED", "MARKER_INVALID",
                                         f"marker of {raw!r} cannot be evaluated: {exc}", raw))
                continue
            if not applies:
                excluded.append({"parent": _label(key), "requirement": raw, "marker": requirement["marker"]})
                continue
        locked = sorted({version for version, _ in pins.get(child_name, [])})
        fitting = [version for version in locked if SpecifierSet(requirement["specifier"]).contains(version, prereleases=True)]
        if not locked:
            problems.append(_problem(key, "tree", "UNRESOLVED", "CHILD_NOT_PINNED",
                                     f"{child_name} (required by {_label(key)} as {raw!r}) is not in the project lockfile", raw))
        elif not fitting:
            problems.append(_problem(key, "tree", "UNRESOLVED", "CHILD_PIN_CONFLICT",
                                     f"the lockfile pins {child_name} {', '.join(map(str, locked))}, which does not satisfy "
                                     f"{raw!r} (required by {_label(key)})", raw))
        elif len(fitting) > 1:
            problems.append(_problem(key, "tree", "UNRESOLVED", "CHILD_NOT_PINNED",
                                     f"the lockfile has more than one version of {child_name} that satisfies {raw!r}: "
                                     f"{', '.join(map(str, fitting))}", raw))
        else:
            child = known.setdefault((child_name, fitting[0]), (child_name, str(fitting[0])))
            edges.append({"parent": _label(key), "child": _label(child), "requirement": raw})
            children.append((child, requirement["extras"]))
    return edges, excluded, problems, children
