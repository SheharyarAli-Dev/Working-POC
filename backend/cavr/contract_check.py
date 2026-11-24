"""Observed events judged against the package's capability contract (PR 8 of docs/cavr-m2-plan.md). Fail closed.

`judge(events, contract)` takes the events of one sandbox run (`sandbox_events.normalise`, after
`subtract_baseline`) and the contract that `verify_request` inferred for the package (`capability_contract`: its
`allowed` entries {capability, scope, status} and `denied` entries {capability}). Every event is one of:

    no capability   CODE_LOAD and the structure types (sandbox_events.STRUCTURE); a bind to a loopback address
                    with port 0 (a local probe: nothing can connect to it, listen is refused by the profile)
    a capability    FILE_READ -> FILE_READ, or SECRET_READ / SENSITIVE_FILE_READ when the path is sensitive (even
                    with FILE_READ granted); FILE_WRITE -> FILE_WRITE, or PERSISTENCE_WRITE, and also the sensitive
                    one when any path it names is sensitive (O_RDWR, rename / link of a secret); PROCESS_EXEC;
                    NETWORK_CONNECT, NETWORK_LISTEN and any other bind -> NETWORK_CONNECT
    never allowed   CREDENTIAL_CHANGE, REFUSED_SYSCALL: no capability of the contract can allow them;
                    CANARY_EXFIL_ATTEMPT (PR 11): a canary value in a write, send or connect, in any step, also when
                    the call failed (under --network none every send fails): always a violation
    not checkable   CANARY_UNCHECKED (PR 11): a payload that could not be checked for canaries -> UNRESOLVED
                    CANARY_CHECK_INCOMPLETE, except a pip write to a file under /tmp/ or /site/lib/ in the install
                    step (pip's envelope, D3: those bytes are the verified wheel's, and the canaries are drawn after
                    its hash was checked)
    unknown         UNKNOWN, or a type this module has no rule for

An attempt counts like a success: a refused or failed call is judged as if it had worked.

    the capability is denied (or not granted)               -> violation
    it is granted with scope "*"                            -> within the contract
    it is granted with a scope (decision D5)                -> the scope is checked:
        NETWORK_CONNECT   "ip:port[, ip:port]" (IPv6 as [addr]:port): the event's address must be one of them
        PROCESS_EXEC      "/abs/path[, ...]": the exec'd path must be one of them
        file capabilities "/abs/dir[, ...]": the path (and the real path) must be inside one of them
        anything else (a label such as `invoice_documents`) -> UNRESOLVED SCOPE_NOT_CHECKABLE
    a file event whose path cannot be read -> UNRESOLVED EVENT_INCOMPLETE whatever is granted (it may be a secret);
    an event the scope or capability cannot be decided for -> UNRESOLVED EVENT_INCOMPLETE; except that a network,
        credential or refused-syscall event is a violation of a denied capability even when an address is missing
        (its capability does not depend on it). An incomplete file or exec event is never a violation: the path
        that could not be read might have been a code load or the step's own start.

The install step (pip on the verified wheels, no package code) is judged by its own envelope (decision D3), not by
the contract: it may load code, read non-sensitive files, write only under /tmp/ and /site/lib/, and bind loopback
port 0; anything else (an exec, a connect, a sensitive read, a credential change, a refused or unknown call, an
event that cannot be read) -> UNRESOLVED INSTALL_OUTSIDE_ENVELOPE. A pip that ignored the User-Agent replacement
(`sandbox_observe.PIP_CODE`) would exec `uname` and land here, never in a pass.

Result: VIOLATION (any violation; REJECTED for the caller) / UNRESOLVED (no violation, but an unknown, incomplete,
uncheckable or out-of-envelope event, or a contract that cannot be read) / OK. Required capabilities that no event
used are listed in `not_exercised` (one run cannot show them; NFR-6).
"""
from __future__ import annotations

import ipaddress
import posixpath

from backend.cavr import sandbox_events

CHECK_VERSION = "cavr-contract-check/3"
UNRESTRICTED = "*"
RUNTIME_CAPABILITIES = ("FILE_READ", "SECRET_READ", "SENSITIVE_FILE_READ", "FILE_WRITE", "PERSISTENCE_WRITE",
                        "PROCESS_EXEC", "NETWORK_CONNECT")
FILE_CAPABILITIES = ("FILE_READ", "SECRET_READ", "SENSITIVE_FILE_READ", "FILE_WRITE", "PERSISTENCE_WRITE")
NEVER_ALLOWED = ("CREDENTIAL_CHANGE", "REFUSED_SYSCALL")
NO_CAPABILITY = ("CODE_LOAD", *sandbox_events.STRUCTURE)
INSTALL_STEP = "install"
INSTALL_WRITES = ("/tmp/", "/site/lib/")
SHOWN = 20


def judge(events, contract) -> dict:
    """{version, result, rule, reason, violations, unresolved, not_exercised, judged, used}. Never raises."""
    try:
        grants, problem = read_contract(contract)
        if problem:
            return _result("UNRESOLVED", "CONTRACT_UNREADABLE", f"the contract cannot be read: {problem}")
        return _judge(list(events or []), grants, contract)
    except Exception as exc:  # a fault here is "unknown", never a pass
        return _result("UNRESOLVED", "INTERNAL_ERROR", f"the check failed: {type(exc).__name__}: {exc}")


def read_contract(contract):
    """({capability: scope or None for denied}, None) or (None, why it cannot be read)."""
    if not isinstance(contract, dict):
        return None, "no contract"
    if contract.get("result") != "OK":
        return None, f"the contract is {contract.get('result')!r} ({contract.get('rule')})"
    allowed, denied, vocabulary = contract.get("allowed"), contract.get("denied"), contract.get("vocabulary")
    if not (isinstance(allowed, list) and isinstance(denied, list) and isinstance(vocabulary, list) and vocabulary):
        return None, "allowed, denied and vocabulary must be lists"
    grants = {}
    for granted, entry in [(True, item) for item in allowed] + [(False, item) for item in denied]:
        capability = entry.get("capability") if isinstance(entry, dict) else None
        if not isinstance(capability, str) or capability not in vocabulary:
            return None, f"{capability!r} is not a capability of the vocabulary"
        if capability in grants:
            return None, f"{capability} is named more than once"
        if granted:
            scope = entry.get("scope")
            if not isinstance(scope, str) or not scope.strip():
                return None, f"{capability} is allowed without a scope"
            grants[capability] = scope.strip()
        else:
            grants[capability] = None
    missing = [name for name in RUNTIME_CAPABILITIES if name not in grants]
    if missing:
        return None, f"it says nothing about {', '.join(missing)}"
    return grants, None


def capability_of(event: dict):
    """(kind, [capabilities]): kind is "none", "capability", "never" or "unknown"; every capability must be granted.

    A write that names a sensitive path needs the write capability and the sensitive one: an O_RDWR open reads the
    file, and a rename / link of a secret (or a symlink to it) makes it readable under another name.
    """
    kind = event.get("type")
    if kind in NO_CAPABILITY:
        return "none", []
    if kind in NEVER_ALLOWED:
        return "never", [kind]
    if kind == "CANARY_EXFIL_ATTEMPT":
        return "never", ["CANARY_EXFIL"]
    if kind == "FILE_READ":
        return "capability", [event.get("sensitive") or "FILE_READ"]
    if kind == "FILE_WRITE":
        write = "PERSISTENCE_WRITE" if event.get("persistence") else "FILE_WRITE"
        return "capability", [write] + ([event["sensitive"]] if event.get("sensitive") else [])
    if kind == "PROCESS_EXEC":
        return "capability", ["PROCESS_EXEC"]
    if kind == "NETWORK_BIND" and _loopback_probe(event.get("address")):
        return "none", []
    if kind in ("NETWORK_CONNECT", "NETWORK_BIND", "NETWORK_LISTEN"):
        return "capability", ["NETWORK_CONNECT"]
    return "unknown", []


def _judge(events, grants, contract) -> dict:
    violations, unresolved, used = [], [], set()
    for event in events:
        if event.get("type") == "CANARY_EXFIL_ATTEMPT":  # before the install envelope: a leak is never "outside" only
            used.add("CANARY_EXFIL")
            violations.append(_entry(event, "CONTRACT_VIOLATION", f"a canary value ({', '.join(event.get('canaries') or [])}) "
                                     f"left the package in {event.get('syscall')} ({', '.join(event.get('canary_forms') or [])})",
                                     "CANARY_EXFIL"))
            continue
        if event.get("type") == "CANARY_UNCHECKED":
            if not (event.get("step") == INSTALL_STEP and _pip_file_write(event)):
                unresolved.append(_entry(event, "CANARY_CHECK_INCOMPLETE", f"a payload could not be checked for "
                                         f"canaries: {event.get('problem')}"))
            continue
        if event.get("step") == INSTALL_STEP:
            why = _outside_envelope(event)
            if why:
                unresolved.append(_entry(event, "INSTALL_OUTSIDE_ENVELOPE", why))
            continue
        kind, capabilities = capability_of(event)
        if kind == "none":
            continue
        if kind == "unknown":
            unresolved.append(_entry(event, "EVENT_TYPE_UNKNOWN", f"an event of type {event.get('type')!r} "
                                     f"({event.get('syscall')}) has no rule: {event.get('problem') or 'no rule'}"))
            continue
        if event.get("type") in ("FILE_READ", "FILE_WRITE") and not event.get("complete") and not event.get("sensitive"):
            # The path is not known, so neither is whether it is a secret: no grant (not even "*") can cover it.
            used.update(capabilities)
            unresolved.append(_entry(event, "EVENT_INCOMPLETE", f"a file event whose path cannot be read (it may be "
                                     f"sensitive): {event.get('problem')}", capabilities[0]))
            continue
        for capability in capabilities:
            used.add(capability)
            found = _one(event, kind, capability, grants)
            if found is not None:
                (violations if found["rule"] == "CONTRACT_VIOLATION" else unresolved).append(found)
                if found["rule"] == "CONTRACT_VIOLATION":
                    break  # one violation per event is evidence enough
    required = [entry["capability"] for entry in contract.get("allowed") or [] if entry.get("status") == "REQUIRED"]
    not_exercised = sorted(set(required) - used)
    judged = sum(1 for event in events if event.get("step") != INSTALL_STEP and capability_of(event)[0] != "none")
    fields = {"violations": violations, "unresolved": unresolved, "not_exercised": not_exercised, "judged": judged,
              "used": sorted(used), "install_events": sum(1 for event in events if event.get("step") == INSTALL_STEP)}
    if violations:
        first = violations[0]
        return _result("VIOLATION", "CONTRACT_VIOLATION", f"{len(violations)} event(s) outside the contract; first: "
                       f"{first['why']} ({_describe(first['event'])})", **fields)
    if unresolved:
        first = unresolved[0]
        return _result("UNRESOLVED", first["rule"], f"{len(unresolved)} event(s) could not be judged; first: "
                       f"{first['why']} ({_describe(first['event'])})", **fields)
    return _result("OK", "EVENTS_WITHIN_CONTRACT", f"{judged} event(s) judged, all within the contract"
                   + (f"; required but not exercised: {', '.join(not_exercised)}" if not_exercised else ""), **fields)


def _one(event, kind, capability, grants):
    """The violation or unresolved entry for one capability an event needs, or None when it is granted."""
    if kind == "never":
        return _entry(event, "CONTRACT_VIOLATION", f"{capability}: no capability can allow it", capability)
    scope = grants.get(capability)
    if scope is None:
        if event.get("complete") or event.get("type") in ("NETWORK_CONNECT", "NETWORK_BIND", "NETWORK_LISTEN"):
            return _entry(event, "CONTRACT_VIOLATION", f"{capability} is not granted by the contract", capability)
        return _entry(event, "EVENT_INCOMPLETE", f"{capability} is denied, but the event cannot be read: "
                      f"{event.get('problem')}", capability)
    if scope == UNRESTRICTED:
        return None
    verdict, why = in_scope(event, capability, scope)
    if verdict is True:
        return None
    if verdict is False:
        return _entry(event, "CONTRACT_VIOLATION", why, capability)
    return _entry(event, "SCOPE_NOT_CHECKABLE" if verdict == "label" else "EVENT_INCOMPLETE", why, capability)


def in_scope(event: dict, capability: str, scope: str):
    """(True, why) inside / (False, why) outside / ("label", why) a scope CAVR cannot check / ("incomplete", why)."""
    entries = [part.strip() for part in scope.split(",") if part.strip()]
    if capability == "NETWORK_CONNECT":
        endpoints = [_endpoint(part) for part in entries]
        if not endpoints or None in endpoints:
            return "label", f"NETWORK_CONNECT is granted for {scope!r}, which is not a list of ip:port endpoints"
        address = event.get("address")
        if not address or not event.get("complete"):
            return "incomplete", "NETWORK_CONNECT is scoped, and the event names no readable address"
        if address.get("family") == "AF_UNIX":
            return False, f"a Unix socket {address.get('path')!r} is outside the granted endpoints {scope!r}"
        try:
            found = (ipaddress.ip_address(address.get("host")), address.get("port"))
        except (TypeError, ValueError):
            return "incomplete", f"the address {address!r} cannot be read"
        return (True, "inside") if found in endpoints else (False, f"{address['host']}:{address['port']} is outside "
                                                                   f"the granted endpoints {scope!r}")
    if not all(part.startswith("/") for part in entries) or not entries:
        return "label", (f"{capability} is granted for the label {scope!r}, which CAVR cannot map to paths "
                         "(mapping labels to paths is future work)")
    path = event.get("path")
    if not path or not event.get("complete"):
        return "incomplete", f"{capability} is scoped, and the event's path cannot be read: {event.get('problem')}"
    if capability == "PROCESS_EXEC":
        return (True, "inside") if posixpath.normpath(path) in {posixpath.normpath(p) for p in entries} else \
            (False, f"exec of {path} is outside the granted programs {scope!r}")
    paths = [p for p in (event.get("paths") or [path]) + [event.get("real_path")] if p]
    outside = [p for p in paths if not any(_inside(p, root) for root in entries)]
    return (True, "inside") if not outside else (False, f"{outside[0]} is outside the granted {capability} scope {scope!r}")


def _outside_envelope(event: dict):
    """Why an install-step event is outside pip's envelope (D3), or None."""
    kind = event.get("type")
    if kind in NO_CAPABILITY:
        return None
    if not event.get("complete"):
        return f"pip's event cannot be read: {event.get('problem')}"
    if kind == "FILE_READ" and not event.get("sensitive"):
        return None
    if kind == "FILE_WRITE" and not event.get("sensitive"):
        paths = [p for p in (event.get("paths") or [event.get("path")]) + [event.get("real_path")] if p]
        if not paths:
            return "pip wrote to a path that cannot be read"
        outside = [p for p in paths if not (p == "/site/lib" or any(p.startswith(root) for root in INSTALL_WRITES))]
        return f"pip wrote {outside[0]}, outside /tmp and /site/lib" if outside else None
    if kind == "NETWORK_BIND" and _loopback_probe(event.get("address")):
        return None
    what = event.get("sensitive") or kind
    return f"pip did {what} ({event.get('syscall')} {event.get('path') or event.get('address') or ''})".rstrip()


def _pip_file_write(event) -> bool:
    """A write of pip's into a regular file of its install target or its temporary directories (D3)."""
    path = event.get("path")
    return (event.get("syscall") in sandbox_events.WRITE_DATA and isinstance(path, str)
            and any(path.startswith(root) for root in INSTALL_WRITES))


def _loopback_probe(address) -> bool:
    if not address or address.get("family") not in ("AF_INET", "AF_INET6") or address.get("port") != 0:
        return False
    try:
        return ipaddress.ip_address(address.get("host")).is_loopback
    except (TypeError, ValueError):
        return False


def _endpoint(text: str):
    """(ip, port) of `1.2.3.4:443` or `[2001:db8::1]:443`, or None."""
    host, sep, port = text.rpartition(":")
    if not sep or not port.isdigit() or not 0 < int(port) < 65536:
        return None
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        return ipaddress.ip_address(host), int(port)
    except ValueError:
        return None


def _inside(path: str, root: str) -> bool:
    path, root = posixpath.normpath(path), posixpath.normpath(root)
    return path == root or path.startswith(root.rstrip("/") + "/")


def _entry(event, rule, why, capability=None) -> dict:
    keep = ("type", "syscall", "step", "pid", "line", "path", "real_path", "sensitive", "persistence", "address", "dns",
            "argv", "ok", "errno", "complete", "problem", "raw")
    return {"rule": rule, "capability": capability, "why": why, "event": {key: event.get(key) for key in keep}}


def _describe(event: dict) -> str:
    target = event.get("path") or event.get("address") or (event.get("argv") or [None])[0] or ""
    outcome = "ok" if event.get("ok") else event.get("errno") or "?"
    return f"{event.get('step')} {event.get('syscall')} {target} = {outcome}, trace line {event.get('line')}"


def _result(result, rule, reason, violations=None, unresolved=None, not_exercised=None, judged=0, used=None,
            install_events=0) -> dict:
    return {"version": CHECK_VERSION, "result": result, "rule": rule, "reason": reason, "install_events": install_events,
            "violations": (violations or [])[:SHOWN], "violation_count": len(violations or []),
            "unresolved": (unresolved or [])[:SHOWN], "unresolved_count": len(unresolved or []),
            "not_exercised": not_exercised or [], "judged": judged, "used": used or []}
