"""Is a sandbox trace complete, and whose is each process in it? (PR 5 of docs/cavr-m2-plan.md). Fail closed.

The trace is strace's own stderr (`strace -f -q --always-show-pid`), the container's stderr stream. Only strace
writes to it: the harness points its inherited fd 2 at /dev/null as its first statement, and every process the
harness starts gets /dev/null as stdin and the container's stdout (untrusted output) as stdout and stderr. A
package process (UID 10001) cannot reach strace's fds through /proc either (strace runs as root).

`check_trace(data, nonce, steps)` says the trace is complete only when all of these hold:

    TRACE_EMPTY        there is at least one line
    TRACE_TRUNCATED    it ends with a newline; the last line is the harness's `+++ exited with 0 +++`; every
                       process created in it has exactly one exit line and no line after it
    TRACE_MALFORMED    every line is `<pid> <syscall>(...`, `<pid> <... x resumed>`, `<pid> +++ ... +++` or
                       `<pid> --- SIG... ---` (a Python traceback or any stray text is not)
    TRACE_NOT_HARNESS  the first line is the harness's execve: /usr/local/bin/python -I -S /opt/cavr/harness.py
    TRACE_UNKNOWN_PID  every PID is the harness's or was returned by clone / clone3 / fork / vfork of a known PID
    TRACE_UNFOLLOWED   every PID a known process's clone / fork / vfork returned has lines in the trace (a child
                       strace did not follow, e.g. CLONE_UNTRACED, would otherwise be invisible; the seccomp
                       profile also refuses CLONE_UNTRACED)
    TRACE_MARKERS      the harness's markers (failed stats of /.cavr/<nonce>/<phase>, from the harness's PID) are
                       exactly start, step:<s>:begin, step:<s>:end:0 for each step in order, end:ok; no harness
                       marker carries another nonce, and no other process stats a path with this run's nonce

Anything else in the trace is what the run did; judging it is PR 7 / PR 8. The result also maps each process to
the step whose child it descends from (`processes`), so later PRs can tell harness activity from package activity
by PID, never by name.
"""
from __future__ import annotations

import hashlib
import re

LINE = re.compile(r"^(\d+) +(.*)$")
EXIT = re.compile(r"^\+\+\+ (?:exited with (\d+)|killed by SIG[A-Z0-9]+(?: \(core dumped\))?|superseded by execve in pid \d+) \+\+\+$")
SIGNAL = re.compile(r"^--- .* ---$")
SYSCALL = re.compile(r"^[a-z_][a-z0-9_]*\(")
RESUMED = re.compile(r"^<\.\.\. ([a-z_][a-z0-9_]*) resumed>")
CREATED = re.compile(r"^(?:(?:clone|clone3|fork|vfork)\(.*|<\.\.\. (?:clone|clone3|fork|vfork) resumed>.*) = (\d+)(?: |$)")
MARKER = re.compile(r'^(?:newfstatat|statx|stat|lstat)\((?:AT_FDCWD, )?"/\.cavr/([^"/]*)/([^"]*)"')
HARNESS_EXEC = re.compile(r'^execve\("/usr/local/bin/python", \["/usr/local/bin/python", "-I", "-S", '
                          r'"/opt/cavr/harness\.py", .*\) = 0$')


def expected_markers(steps) -> list[str]:
    return ["start", *[m for name in steps for m in (f"step:{name}:begin", f"step:{name}:end:0")], "end:ok"]


def check_trace(data, nonce: str, steps) -> dict:
    """{complete, rule, reason, root_pid, processes, steps, lines, sha256}. Never raises."""
    try:
        raw = data if isinstance(data, bytes) else str(data).encode("utf-8", errors="surrogateescape")
        return _check(raw, nonce, list(steps))
    except Exception as exc:
        return _result(False, "TRACE_MALFORMED", f"the trace could not be read: {type(exc).__name__}: {exc}",
                       sha256=None)


def _check(raw: bytes, nonce: str, steps: list) -> dict:
    sha = hashlib.sha256(raw).hexdigest()
    bad = lambda rule, reason, **more: _result(False, rule, reason, sha256=sha, **more)  # noqa: E731
    text = raw.decode("utf-8", errors="replace")
    if not text.strip():
        return bad("TRACE_EMPTY", "the trace is empty")
    if not text.endswith("\n"):
        return bad("TRACE_TRUNCATED", "the trace does not end with a complete line")
    parsed = []
    for number, line in enumerate(text[:-1].split("\n"), 1):
        match = LINE.match(line)
        body = match.group(2) if match else ""
        if not match or not (EXIT.match(body) or SIGNAL.match(body) or SYSCALL.match(body) or RESUMED.match(body)):
            return bad("TRACE_MALFORMED", f"line {number} is not a strace line: {line[:120]!r}", lines=number)
        parsed.append((int(match.group(1)), body))
    lines = len(parsed)
    root, first = parsed[0]
    if not HARNESS_EXEC.match(first):
        return bad("TRACE_NOT_HARNESS", f"the first line is not the harness's execve: {first[:120]!r}", lines=lines)

    parent = {root: None}
    for pid, body in parsed:
        created = CREATED.match(body)
        if created and int(created.group(1)) > 0:
            parent.setdefault(int(created.group(1)), pid)
    known, grew = {root}, True
    while grew:  # a child's first line can come before its parent's clone returns, so resolve on the whole trace
        grew = False
        for child, mother in parent.items():
            if child not in known and mother in known:
                known.add(child)
                grew = True
    unknown = sorted({pid for pid, _ in parsed} - known)
    if unknown:
        return bad("TRACE_UNKNOWN_PID", f"PIDs {unknown[:5]} were not created by any process in the trace", lines=lines)

    exited, exit_code = {}, {}
    for index, (pid, body) in enumerate(parsed):
        if pid in exited:
            return bad("TRACE_TRUNCATED", f"PID {pid} has a line after its exit line", lines=lines)
        ended = EXIT.match(body)
        if ended:
            exited[pid] = index
            exit_code[pid] = int(ended.group(1)) if ended.group(1) is not None else None
    seen = {pid for pid, _ in parsed}
    unfollowed = sorted(set(parent) - seen)
    if unfollowed:  # e.g. clone(CLONE_UNTRACED): the child ran, but strace never saw it
        return bad("TRACE_UNFOLLOWED", f"PIDs {unfollowed[:5]} were created but have no line in the trace", lines=lines)
    missing = sorted(set(parent) - set(exited))
    if missing:
        return bad("TRACE_TRUNCATED", f"PIDs {missing[:5]} have no exit line", lines=lines)
    if exited.get(root) != lines - 1 or exit_code.get(root) != 0:
        return bad("TRACE_TRUNCATED", f"the last line is not the harness's `+++ exited with 0 +++` "
                   f"(harness exit: {exit_code.get(root, 'none')})", lines=lines)

    markers, step_pids, current = [], {}, None
    for pid, body in parsed:
        found = MARKER.match(body)
        if found and pid != root and found.group(1) == nonce:
            return bad("TRACE_MARKERS", f"PID {pid}, not the harness, used this run's marker nonce", lines=lines)
        if pid != root:
            continue
        if found:
            if found.group(1) != nonce:
                return bad("TRACE_MARKERS", f"a harness marker carries another nonce: {found.group(1)[:40]!r}", lines=lines)
            markers.append(found.group(2))
            step = re.match(r"^step:([^:]+):(begin|end:\d+)$", found.group(2))
            current = step.group(1) if step and step.group(2) == "begin" else None
            continue
        created = CREATED.match(body)
        if created and current is not None:
            step_pids.setdefault(current, []).append(int(created.group(1)))
    if markers != expected_markers(steps):
        return bad("TRACE_MARKERS", f"harness markers {markers} are not {expected_markers(steps)}", lines=lines)

    processes = {root: {"parent": None, "step": None, "role": "harness"}}
    owner = {pid: name for name, pids in step_pids.items() for pid in pids}
    for pid in sorted(known - {root}, key=lambda p: (_depth(p, parent), p)):
        mother = parent[pid]
        step = owner.get(pid) or processes.get(mother, {}).get("step")
        processes[pid] = {"parent": mother, "step": step, "role": "step" if step else "harness"}
    return _result(True, "TRACE_COMPLETE", f"complete: {lines} lines, {len(known)} processes, every marker in order",
                   sha256=sha, lines=lines, root_pid=root, processes=processes,
                   steps={name: step_pids.get(name, []) for name in steps})


def _depth(pid, parent) -> int:
    depth = 0
    while parent.get(pid) is not None and depth < 100000:
        pid, depth = parent[pid], depth + 1
    return depth


def _result(complete, rule, reason, sha256=None, lines=0, root_pid=None, processes=None, steps=None) -> dict:
    return {"complete": complete, "rule": rule, "reason": reason, "sha256": sha256, "lines": lines,
            "root_pid": root_pid, "processes": processes or {}, "steps": steps or {}}
