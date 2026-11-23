"""Sandbox trace -> typed events (PR 7 of docs/cavr-m2-plan.md). Fail closed.

`normalise(trace, processes, step_pids, steps)` reads the trace that `sandbox_trace.check_trace` accepted (complete,
or attributable in its partial mode) and turns every syscall line into one event. Failed syscalls are kept with
their errno: a connect that fails with ENETUNREACH is still a network attempt, an open of a secret that fails with
ENOENT is still a secret read attempt.

    FILE_READ          open for reading, or a metadata call (stat, access, readlink, xattr, statfs) on a path;
                       `sensitive` is SECRET_READ or SENSITIVE_FILE_READ for the paths in SECRET_PATHS / SYSTEM_PATHS
    FILE_WRITE         open for writing / creating / truncating, mkdir, rmdir, unlink, rename, link, symlink, chmod,
                       chown, utime, truncate, setxattr, mknod; `persistence` for the paths in PERSISTENCE_PATHS;
                       `sensitive` too when any path it names is (an O_RDWR open reads; a rename or link of a
                       secret, or a symlink to one, makes it readable under another name)
    CODE_LOAD          a read-only access whose path (and real path) is in CODE_LOCATIONS or RUNTIME_FILES and is not
                       sensitive: the interpreter, the image's libraries, the verified install target, CAVR's own
                       read-only mounts (decision D1). Recorded, needs no capability
    PROCESS_EXEC       execve / execveat, with path and argv (also when it fails)
    NETWORK_CONNECT    connect, sendto, sendmsg, sendmmsg, recvfrom, recvmsg, recvmmsg; `address` (IPv4, IPv6, Unix)
                       when the call names one; `dns` for port 53
    NETWORK_BIND       bind, with its address
    NETWORK_LISTEN     listen, accept, accept4
    CREDENTIAL_CHANGE  setuid / setgid / setre*id / setres*id / setfs*id / setgroups / capset (also when refused)
    REFUSED_SYSCALL    the dangerous syscalls the profile refuses or the kernel refuses to a traced process
                       (ptrace, process_vm_*, io_uring_*, userfaultfd, bpf, perf_event_open, mount, chroot, unshare,
                       setns, ...); an attempt is the event
    UNKNOWN            a traced syscall with no rule here, or a line whose arguments cannot be read

Structure (recorded, needs no capability, may appear in a clean baseline):

    HARNESS_START      the trace's first line, the harness's execve (checked by check_trace)
    STEP_START         the first execve of a step's first process with exactly the job's argv
    MARKER             the harness's own phase markers (stat of /.cavr/<nonce>/...)
    PROCESS            clone, clone3, fork, vfork, exit, exit_group, wait4, waitid, signal delivery, exit lines
    NO_EFFECT also     open of /dev/null; sendfile between two files (into a socket it is NETWORK_CONNECT)
    CWD_CHANGE         chdir, fchdir (followed: relative paths are resolved against each process's directory)
    SIGNAL             kill, tkill, tgkill, ...: in this container they reach only UID 10001 processes
    PROCESS_CONTROL    prctl
    NO_EFFECT          getters (getuid, getcwd, capget, getsockname, ...) and socket / socketpair / setsockopt

Paths: absolute paths are normalised (`.` and `..`, lexically); a path relative to AT_FDCWD is joined to the
directory strace prints with -y (`AT_FDCWD</tmp>`); relative to a directory fd, to that fd's path (`3</site/lib>`);
for calls without a dirfd (stat, mkdir, rename, ...), to the process's current directory, known from its last
`AT_FDCWD</...>`, getcwd, chdir or fchdir line (inherited by a child). After any process changes directory every other
process's directory is unknown until its own next such line (threads can share it). Symlinks the run creates
are followed (a package cannot hide `~/.aws` behind `/tmp/h -> /tmp/home`; /site/lib starts empty and pip writes
regular files only). A path through /proc/<pid>/{root,cwd,fd,task}, /proc/thread-self or /dev/fd is incomplete. An
event whose path, address or argv cannot be resolved, or whose string strace cut (`"..."...`), has `complete: False`
and a `problem`.

`subtract_baseline(events, baseline)` removes exactly the events a recorded empty-harness run produced (same step,
type, call, path, access, address, argv and outcome), each as many times as the baseline has it. `check_baseline`
refuses a baseline of another identity, or one with anything but CODE_LOAD and structure (BASELINE_NOT_CLEAN).
"""
from __future__ import annotations

import posixpath
import re
from collections import Counter

EVENTS_VERSION = "cavr-events/2"
HOME = "/tmp/home"  # the sandbox HOME (sandbox_harness.CHILD_ENV)
HOMES = (HOME, "/root", "/nonexistent")  # /nonexistent: the cavr user's home in /etc/passwd (Dockerfile useradd -d)
# Paths that reach another file by a kernel alias, not by its name: the open of /proc/self/root/tmp/home/.aws/... or
# /dev/fd/3/x names a secret that no lexical check would see. Such a path is incomplete (review of PRs 7-9).
ALIASES = re.compile(r"^/(?:proc/(?:[^/]+/(?:root|cwd|fd|task|map_files)|thread-self)|dev/fd)(?:/|$)")

STRUCTURE = ("HARNESS_START", "STEP_START", "MARKER", "PROCESS", "CWD_CHANGE", "SIGNAL", "PROCESS_CONTROL", "NO_EFFECT")
JUDGED = ("FILE_READ", "FILE_WRITE", "PROCESS_EXEC", "NETWORK_CONNECT", "NETWORK_BIND", "NETWORK_LISTEN",
          "CREDENTIAL_CHANGE", "REFUSED_SYSCALL", "UNKNOWN")
TYPES = ("CODE_LOAD", *STRUCTURE, *JUDGED)
CLEAN_BASELINE = ("CODE_LOAD", *STRUCTURE)

# Read-only code and CAVR's own read-only mounts (D1). A directory counts with everything under it.
CODE_LOCATIONS = ("/usr/local/", "/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/", "/usr/share/locale/",
                  "/usr/share/zoneinfo/", "/opt/cavr/", "/job/", "/pkg/", "/site/lib/")
# Exact files the interpreter and the C library read at start-up (measured in the empty-harness run, 2026-11-23).
RUNTIME_FILES = ("/etc/ld.so.cache", "/etc/ld.so.preload", "/etc/localtime", "/dev/null", "/proc/self/exe", "/site/lib",
                 "/site")

# Sensitive paths. `~/` is every home in HOMES and /home/<user>/.
SECRET_PATHS = (  # credentials -> SECRET_READ
    ("~/.ssh/", "SSH keys and known hosts"), ("~/.aws/", "AWS credentials and config"),
    ("~/.netrc", "machine passwords for HTTP / FTP"), ("~/.pypirc", "PyPI upload tokens"),
    ("~/.git-credentials", "git passwords"), ("~/.docker/config.json", "registry tokens"),
    ("~/.kube/config", "Kubernetes credentials"), ("~/.config/gcloud/", "Google Cloud credentials"),
    ("~/.azure/", "Azure credentials"), ("~/.gnupg/", "GPG private keys"),
)
SYSTEM_PATHS = (  # account and host secrets -> SENSITIVE_FILE_READ
    ("/etc/passwd", "user accounts"), ("/etc/shadow", "password hashes"), ("/etc/gshadow", "group password hashes"),
    ("/etc/sudoers", "privilege rules"), ("/etc/ssh/", "SSH host keys"),
)
PERSISTENCE_PATHS = ("~/.bashrc", "~/.bash_profile", "~/.profile", "~/.zshrc", "~/.config/autostart/",
                     "~/.config/systemd/", "~/.ssh/authorized_keys", "/etc/cron", "/var/spool/cron/", "/etc/systemd/",
                     "/etc/profile", "/etc/rc", "/etc/init.d/", "/etc/ld.so.preload")
PERSISTENCE_NAMES = ("sitecustomize.py", "usercustomize.py")  # and any *.pth: Python runs them at start-up

# Syscalls: (rule, path arguments). A path argument is (dirfd index or None, path index).
AT = ((0, 1),)
OPEN = {"open": ((None, 0),), "creat": ((None, 0),), "openat": AT, "openat2": AT}
METADATA = {"newfstatat": AT, "fstatat64": AT, "statx": AT, "faccessat": AT, "faccessat2": AT, "readlinkat": AT,
            "stat": ((None, 0),), "lstat": ((None, 0),), "stat64": ((None, 0),), "lstat64": ((None, 0),),
            "access": ((None, 0),), "readlink": ((None, 0),), "statfs": ((None, 0),), "statfs64": ((None, 0),),
            "getxattr": ((None, 0),), "lgetxattr": ((None, 0),), "listxattr": ((None, 0),), "llistxattr": ((None, 0),)}
WRITES = {"mkdir": ((None, 0),), "mkdirat": AT, "rmdir": ((None, 0),), "unlink": ((None, 0),), "unlinkat": AT,
          "rename": ((None, 0), (None, 1)), "renameat": ((0, 1), (2, 3)), "renameat2": ((0, 1), (2, 3)),
          "link": ((None, 0), (None, 1)), "linkat": ((0, 1), (2, 3)), "symlink": ((None, 1),), "symlinkat": ((1, 2),),
          "chmod": ((None, 0),), "fchmodat": AT, "fchmodat2": AT, "chown": ((None, 0),), "lchown": ((None, 0),),
          "fchownat": AT, "utimensat": AT, "futimesat": AT, "utime": ((None, 0),), "utimes": ((None, 0),),
          "truncate": ((None, 0),), "setxattr": ((None, 0),), "lsetxattr": ((None, 0),), "removexattr": ((None, 0),),
          "lremovexattr": ((None, 0),), "mknod": ((None, 0),), "mknodat": AT}
EXEC = {"execve": ((None, 0),), "execveat": AT}
NETWORK = {"connect": ("NETWORK_CONNECT", 1), "sendto": ("NETWORK_CONNECT", 4), "sendmsg": ("NETWORK_CONNECT", 1),
           "sendmmsg": ("NETWORK_CONNECT", None), "recvfrom": ("NETWORK_CONNECT", 4), "recvmsg": ("NETWORK_CONNECT", 1),
           "recvmmsg": ("NETWORK_CONNECT", None), "bind": ("NETWORK_BIND", 1), "listen": ("NETWORK_LISTEN", None),
           "accept": ("NETWORK_LISTEN", None), "accept4": ("NETWORK_LISTEN", None)}
# sendfile(out, in, ...) copies between two fds whose opens are already events; into a socket it is a network send.
COPIES = ("sendfile", "sendfile64")
CREDENTIALS = ("setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid", "setfsuid", "setfsgid",
               "setgroups", "capset", "setuid32", "setgid32", "setreuid32", "setregid32", "setresuid32", "setresgid32",
               "setfsuid32", "setfsgid32", "setgroups32")
REFUSED = ("ptrace", "process_vm_readv", "process_vm_writev", "io_uring_setup", "io_uring_enter", "io_uring_register",
           "userfaultfd", "bpf", "perf_event_open", "mount", "umount", "umount2", "pivot_root", "chroot", "swapon",
           "swapoff", "acct", "quotactl", "unshare", "setns", "open_tree", "move_mount", "fsopen", "fsmount", "fspick",
           "kexec_load", "init_module", "finit_module", "delete_module", "reboot")
PROCESS = ("clone", "clone3", "fork", "vfork", "exit", "exit_group", "wait4", "waitid")
SIGNALS = ("kill", "tkill", "tgkill", "rt_sigqueueinfo", "rt_tgsigqueueinfo", "pidfd_send_signal")
NO_EFFECT = ("getuid", "geteuid", "getgid", "getegid", "getresuid", "getresgid", "getgroups", "capget", "getuid32",
             "geteuid32", "getgid32", "getegid32", "getresuid32", "getresgid32", "getgroups32", "getcwd", "socket",
             "socketpair", "getsockname", "getpeername", "setsockopt", "getsockopt", "shutdown")
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")

LINE = re.compile(r"^(\d+) +(.*)$")
UNFINISHED = " <unfinished ...>"
RESUMED = re.compile(r"^<\.\.\. ([a-z_][a-z0-9_]*) resumed>(.*)$")
CALL = re.compile(r"^([a-z_][a-z0-9_]*)\(")
RESULT = re.compile(r"^\s*=\s*(-?\d+|\?|0x[0-9a-f]+)(?:<((?:[^>\\]|\\.)*)>)?(?:\s+([A-Z][A-Z0-9_]*))?(?:\s+\(.*\))?(?:\s+<.*>)?$")
FD = re.compile(r"^(AT_FDCWD|-?\d+)(?:<((?:[^>\\]|\\.)*)>)?$")
STRING = re.compile(r'^"((?:[^"\\]|\\.)*)"(\.\.\.)?$')
MARKER = re.compile(r'^"/\.cavr/[^"/]*/[^"]*"$')
HARNESS_EXEC = re.compile(r'^execve\("/usr/local/bin/python", \["/usr/local/bin/python", "-I", "-S", '
                          r'"/opt/cavr/harness\.py", ')


class Unreadable(Exception):
    pass


# --- parsing strace's printing ----------------------------------------------------------------------------------------

def split_call(text: str):
    """(name, [argument text], result text) of `name(a, b) = r`. Raises Unreadable."""
    match = CALL.match(text)
    if not match:
        raise Unreadable("not a syscall line")
    name, i, n = match.group(1), match.end(), len(text)
    args, depth, start = [], 0, i
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            if i >= n:
                raise Unreadable("a string does not end")
        elif c == "<" and _fd_bracket(text, i):
            while i < n and text[i] != ">":
                i += 2 if text[i] == "\\" else 1
            if i >= n:
                raise Unreadable("an fd path does not end")
        elif c == "/" and text.startswith("/*", i):
            end = text.find("*/", i)
            if end < 0:
                raise Unreadable("a comment does not end")
            i = end + 1
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0 and c == ")":
                if text[start:i].strip():
                    args.append(text[start:i].strip())
                return name, args, text[i + 1:]
            depth -= 1
            if depth < 0:
                raise Unreadable("brackets do not balance")
        elif c == "," and depth == 0:
            args.append(text[start:i].strip())
            start = i + 1
        i += 1
    raise Unreadable("the argument list does not end")


def _fd_bracket(text: str, i: int) -> bool:
    """`<` opens an fd path only right after an fd number or AT_FDCWD (strace -y)."""
    before = text[max(0, i - 8):i]
    return before.endswith("AT_FDCWD") or (i > 0 and text[i - 1].isdigit())


def c_string(body: str) -> str:
    """strace's C-escaped string body -> text (bytes that are not UTF-8 are kept as surrogates)."""
    out, i, n = bytearray(), 0, len(body)
    simple = {"n": 10, "t": 9, "r": 13, "v": 11, "f": 12, "a": 7, "b": 8, "\\": 92, '"': 34, "'": 39, "?": 63}
    while i < n:
        c = body[i]
        if c != "\\":
            out += c.encode("utf-8", errors="surrogateescape")
            i += 1
            continue
        nxt = body[i + 1] if i + 1 < n else ""
        if nxt in simple:
            out.append(simple[nxt])
            i += 2
        elif nxt == "x" and re.match(r"[0-9a-fA-F]{2}", body[i + 2:i + 4]):
            out.append(int(body[i + 2:i + 4], 16))
            i += 4
        elif re.match(r"[0-7]", nxt):
            digits = re.match(r"[0-7]{1,3}", body[i + 1:]).group(0)
            out.append(int(digits, 8) & 0xFF)
            i += 1 + len(digits)
        else:
            raise Unreadable(f"unknown escape \\{nxt}")
    return out.decode("utf-8", errors="surrogateescape")


def string_arg(token: str):
    """(text, cut) of a string argument, or (None, False) for NULL. Raises Unreadable for anything else."""
    if token == "NULL":
        return None, False
    match = STRING.match(token)
    if not match:
        raise Unreadable(f"not a string: {token[:60]!r}")
    return c_string(match.group(1)), bool(match.group(2))


def fd_arg(token: str):
    """(fd, path or None) of a -y fd argument."""
    match = FD.match(token)
    if not match:
        raise Unreadable(f"not an fd: {token[:60]!r}")
    return match.group(1), (c_string(match.group(2)) if match.group(2) is not None else None)


def result_of(text: str) -> dict:
    match = RESULT.match(text)
    if not match:
        raise Unreadable(f"no result: {text[:60]!r}")
    value, path, errno = match.group(1), match.group(2), match.group(3)
    ok = None if value == "?" else not value.startswith("-")
    return {"value": value, "ok": ok, "errno": errno if ok is False else None,
            "path": c_string(path) if path is not None else None}


def joined_lines(text: str):
    """(line number, pid, body) with every `<unfinished ...>` joined to its `<... resumed>` line."""
    pending, out = {}, []
    for number, line in enumerate(text.split("\n"), 1):
        match = LINE.match(line)
        if not match:
            continue  # check_trace accepted the trace; only a final empty line is left
        pid, body = int(match.group(1)), match.group(2)
        resumed = RESUMED.match(body)
        if resumed:
            start = pending.pop(pid, None)
            if start is None or start[1] != resumed.group(1):
                out.append((number, pid, body, f"`{resumed.group(1)} resumed` without its start"))
                continue
            out.append((start[0], pid, f"{start[1]}({start[2]}{resumed.group(2)}", None))
        elif body.endswith(UNFINISHED) and CALL.match(body):
            name = CALL.match(body).group(1)
            pending[pid] = (number, name, body[len(name) + 1:-len(UNFINISHED)])
        else:
            out.append((number, pid, body, None))
    for pid, (number, name, _) in pending.items():  # a call the run never finished (killed, deadline)
        out.append((number, pid, f"{name}(", "the call never returned"))
    return sorted(out, key=lambda item: item[0])


# --- paths -----------------------------------------------------------------------------------------------------------

def _home_forms(pattern: str) -> list[str]:
    if not pattern.startswith("~/"):
        return [pattern]
    return [home + pattern[1:] for home in HOMES]


def _matches(path: str, pattern: str) -> bool:
    for form in _home_forms(pattern):
        if form.endswith("/") and (path.startswith(form) or path == form[:-1]):
            return True
        if not form.endswith("/") and (path == form or (form in ("/etc/cron", "/etc/rc", "/etc/profile")
                                                         and path.startswith(form))):
            return True
    if pattern.startswith("~/"):  # /home/<user>/...
        parts = path.split("/")
        if len(parts) > 3 and parts[1] == "home":
            return _matches("/tmp/home/" + "/".join(parts[3:]), pattern)
    return False


def sensitivity(path: str | None):
    """SECRET_READ / SENSITIVE_FILE_READ and why, or (None, None)."""
    if not path:
        return None, None
    name = posixpath.basename(path)
    if name == ".env" or name.startswith(".env."):
        return "SECRET_READ", "a .env file (application secrets)"
    if re.fullmatch(r"/proc/[^/]+(?:/task/[^/]+)?/environ", path):
        return "SECRET_READ", "a process environment"
    for pattern, why in SECRET_PATHS:
        if _matches(path, pattern):
            return "SECRET_READ", why
    for pattern, why in SYSTEM_PATHS:
        if _matches(path, pattern):
            return "SENSITIVE_FILE_READ", why
    return None, None


def persistence(path: str | None) -> bool:
    if not path:
        return False
    name = posixpath.basename(path)
    return name.endswith(".pth") or name in PERSISTENCE_NAMES or any(_matches(path, p) for p in PERSISTENCE_PATHS)


def _ancestors() -> frozenset:
    found = set()
    for location in CODE_LOCATIONS:
        parts = location.strip("/").split("/")
        found.update("/" + "/".join(parts[:end]) for end in range(len(parts)))
    return frozenset(found | {"/"})


CODE_ANCESTORS = _ancestors()  # "/", "/usr", "/usr/share", "/opt", ...: a stat of one says nothing about its contents


def is_code(path: str | None, access: str = "read") -> bool:
    if not path:
        return False
    if path in RUNTIME_FILES or any(path.startswith(location) or path + "/" == location for location in CODE_LOCATIONS):
        return True
    return access == "metadata" and path in CODE_ANCESTORS


def _normal(path: str) -> str:
    out = posixpath.normpath(path)
    return "/" + out.lstrip("/") if out.startswith("//") else out


# --- events ----------------------------------------------------------------------------------------------------------

class _State:
    def __init__(self, processes, step_pids, steps):
        self.cwd = {}
        self.parent = {int(pid): info.get("parent") for pid, info in (processes or {}).items()}
        self.step = {int(pid): info.get("step") for pid, info in (processes or {}).items()}
        self.root = next((int(pid) for pid, info in (processes or {}).items() if info.get("parent") is None), None)
        self.first = {name: (pids[0] if pids else None) for name, pids in (step_pids or {}).items()}
        self.argv = {item["name"]: list(item["argv"]) for item in steps or []}
        self.started = set()
        self.links = {}  # symlinks this run created: link path -> absolute target (followed when resolving)

    def follow(self, path: str) -> str:
        """`path` with every symlink this run created in front of it replaced by its target (up to 40, as the kernel)."""
        for _ in range(40):
            link = next((l for l in sorted(self.links, key=len, reverse=True) if path == l or path.startswith(l + "/")), None)
            if link is None:
                return path
            path = _normal(self.links[link] + path[len(link):])
        return path

    def cwd_of(self, pid):
        """The process's directory, or None when it is not known. A process never seen yet takes its parent's (a
        child starts in its parent's directory); once a directory is marked unknown it is not inherited again."""
        if pid not in self.cwd and self.parent.get(pid) in self.cwd:
            self.cwd[pid] = self.cwd[self.parent[pid]]
        return self.cwd.get(pid)

    def forget_others(self, pid):
        """After `pid` changed directory: every other process's directory is unknown (a thread shares it)."""
        for other in set(self.parent) | set(self.cwd):
            if other != pid:
                self.cwd[other] = None


def normalise(trace: str, processes: dict, step_pids: dict, steps) -> dict:
    """{version, events, counts, incomplete, unknown}. Never raises: an unreadable line is an UNKNOWN event."""
    state = _State(processes, step_pids, steps)
    events = []
    for number, pid, body, problem in joined_lines(trace if isinstance(trace, str) else str(trace)):
        if problem:
            events.append(_event(state, number, pid, body, "UNKNOWN", None, problem=problem))
            continue
        try:
            events.append(_line_event(state, number, pid, body))
        except Unreadable as exc:
            events.append(_event(state, number, pid, body, "UNKNOWN", None, problem=f"cannot read the line: {exc}"))
        except Exception as exc:  # a line this code cannot handle is unknown, never a reason to lose the run's events
            events.append(_event(state, number, pid, body, "UNKNOWN", None,
                                 problem=f"cannot read the line: {type(exc).__name__}: {exc}"))
    counts = Counter(event["type"] for event in events)
    return {"version": EVENTS_VERSION, "events": events, "counts": dict(sorted(counts.items())),
            "incomplete": [event for event in events if not event["complete"]],
            "unknown": [event for event in events if event["type"] == "UNKNOWN"]}


def _event(state, number, pid, raw, kind, syscall, problem=None, **fields) -> dict:
    event = {"type": kind, "syscall": syscall, "pid": pid, "line": number, "step": state.step.get(pid) or "harness",
             "path": None, "real_path": None, "access": None, "sensitive": None, "sensitive_why": None,
             "persistence": False, "address": None, "dns": False, "argv": None, "ok": None, "errno": None,
             "complete": problem is None, "problem": problem, "raw": raw[:600]}
    event.update(fields)
    return event


def _line_event(state, number, pid, body) -> dict:
    if body.startswith(("+++ ", "--- ")):
        return _event(state, number, pid, body, "PROCESS", None)
    name, args, rest = split_call(body)
    result = result_of(rest)
    done = {"ok": result["ok"], "errno": result["errno"]}
    if number == 1 and pid == state.root and HARNESS_EXEC.match(body):
        state.started.add(pid)
        return _event(state, number, pid, body, "HARNESS_START", name, **done)
    if name in OPEN or name in METADATA or name in WRITES or name in EXEC or name in ("chdir", "fchdir"):
        return _file_event(state, number, pid, body, name, args, result)
    if name == "getcwd":
        if result["ok"] and args:
            path, cut = string_arg(args[0])
            if path and not cut and path.startswith("/"):
                state.cwd[pid] = _normal(path)
        return _event(state, number, pid, body, "NO_EFFECT", name, **done)
    if name in COPIES:
        target = fd_arg(args[0])[1] if args else None
        if target is None or not target.startswith("/"):
            return _event(state, number, pid, body, "NETWORK_CONNECT", name, problem=None if target else
                          "sendfile into an fd without a path", **done)
        return _event(state, number, pid, body, "NO_EFFECT", name, path=_normal(target), **done)
    if name in NETWORK:
        kind, index = NETWORK[name]
        return _network_event(state, number, pid, body, name, kind, args, index, done)
    for names, kind in ((CREDENTIALS, "CREDENTIAL_CHANGE"), (REFUSED, "REFUSED_SYSCALL"), (PROCESS, "PROCESS"),
                        (SIGNALS, "SIGNAL"), (NO_EFFECT, "NO_EFFECT"), (("prctl",), "PROCESS_CONTROL")):
        if name in names:
            return _event(state, number, pid, body, kind, name, **done)
    return _event(state, number, pid, body, "UNKNOWN", name, problem=f"no rule for the syscall {name}", **done)


def _resolve(state, pid, args, dirfd_index, path_index, empty_is_fd=False):
    """(normalised path, problem). Raises Unreadable when the arguments are not where the table says."""
    if path_index >= len(args):
        raise Unreadable("a path argument is missing")
    path, cut = string_arg(args[path_index])
    base = None
    if dirfd_index is not None:
        if dirfd_index >= len(args):
            raise Unreadable("a dirfd argument is missing")
        fd, base = fd_arg(args[dirfd_index])
        if fd == "AT_FDCWD" and base:
            state.cwd[pid] = _normal(base)
    if cut:
        return None, f"strace cut the path at {len(path or '')} characters"
    if path is None or (path == "" and empty_is_fd):
        if dirfd_index is not None and base and base.startswith("/"):
            return _normal(base), None
        return None, "the call names no path and its fd has none"
    if not path.startswith("/"):
        if dirfd_index is None:
            base = state.cwd_of(pid)
            if base is None:
                return None, "a relative path and the process's current directory is not known"
        elif not base or not base.startswith("/"):
            return None, "a path relative to a directory fd whose path strace could not print"
        path = posixpath.join(base, path)
    resolved = state.follow(_normal(path))
    if ALIASES.match(resolved):
        return resolved, f"{resolved} reaches a file through a /proc or /dev/fd alias, not by its name"
    return resolved, None


def _file_event(state, number, pid, body, name, args, result) -> dict:
    done = {"ok": result["ok"], "errno": result["errno"]}
    if name in ("chdir", "fchdir"):
        if name == "chdir":
            path, problem = _resolve(state, pid, args, None, 0)
        else:
            _, path = fd_arg(args[0]) if args else (None, None)
            path, problem = (_normal(path), None) if path and path.startswith("/") else (None, "fchdir to an fd without a path")
        if result["ok"]:
            state.forget_others(pid)  # threads may share the directory: everyone else's is unknown now
            state.cwd[pid] = path  # None when the new directory is not known
        return _event(state, number, pid, body, "CWD_CHANGE", name, path=path, problem=problem, **done)
    if name in EXEC:
        (dirfd, index), = EXEC[name]
        path, problem = _resolve(state, pid, args, dirfd, index, empty_is_fd=name == "execveat")
        argv, argv_problem = _argv(args[index + 1] if len(args) > index + 1 else "NULL")
        problem = problem or argv_problem
        step = state.step.get(pid)
        kind = "PROCESS_EXEC"
        if (pid not in state.started and step and state.first.get(step) == pid and argv == state.argv.get(step)
                and argv and path == argv[0] and problem is None):
            kind = "STEP_START"
        if result["ok"]:
            state.started.add(pid)
        return _event(state, number, pid, body, kind, name, path=path, argv=argv, problem=problem, access="exec", **done)

    table = OPEN if name in OPEN else METADATA if name in METADATA else WRITES
    access = "write" if name in WRITES else "metadata" if name in METADATA else "read"
    if name in OPEN:
        flags = args[2] if name in ("openat", "openat2") and len(args) > 2 else args[1] if len(args) > 1 else ""
        if name == "creat" or any(flag in flags for flag in WRITE_FLAGS):
            access = "write"
    paths, problem = [], None
    for dirfd, index in table[name]:
        resolved, why = _resolve(state, pid, args, dirfd, index, empty_is_fd=name in ("newfstatat", "statx", "utimensat"))
        paths.append(resolved)
        problem = problem or why
    real = result["path"] if result["path"] and result["path"].startswith("/") else None
    path = paths[0]
    extra = {"paths": paths} if len(paths) > 1 else {}
    target = _link_target(state, pid, name, args, paths, result) if name in ("symlink", "symlinkat") else None
    if target:
        extra["link_target"] = target
    if name in OPEN and path == "/dev/null" and real in (None, "/dev/null"):
        return _event(state, number, pid, body, "NO_EFFECT", name, path=path, access=access, **done)  # the null device
    # Every path the call names (both of a rename or link, the real path, a symlink's target) is checked: an O_RDWR
    # open reads, and renaming or linking a secret makes it readable under another name (review of PRs 7-9).
    level, why = next(((lv, w) for lv, w in (sensitivity(p) for p in paths + [real, target]) if lv), (None, None))
    if access == "write":
        return _event(state, number, pid, body, "FILE_WRITE", name, path=path, real_path=real, access=access,
                      sensitive=level, sensitive_why=why, persistence=any(persistence(p) for p in paths + [real]),
                      problem=problem, **extra, **done)
    if MARKER.match(args[1] if name in ("newfstatat", "statx") and len(args) > 1 else "") and pid == state.root:
        return _event(state, number, pid, body, "MARKER", name, path=path, access=access, problem=problem, **done)
    if level:
        return _event(state, number, pid, body, "FILE_READ", name, path=path, real_path=real, access=access,
                      sensitive=level, sensitive_why=why, problem=problem, **done)
    if problem is None and is_code(path, access) and (real is None or is_code(real)):
        return _event(state, number, pid, body, "CODE_LOAD", name, path=path, real_path=real, access=access, **done)
    return _event(state, number, pid, body, "FILE_READ", name, path=path, real_path=real, access=access,
                  problem=problem, **done)


def _link_target(state, pid, name, args, paths, result):
    """The absolute target of a symlink the call creates (recorded when it succeeds), or None when it cannot be read."""
    try:
        target, cut = string_arg(args[0])
    except (Unreadable, IndexError):
        return None
    if target is None or cut or not paths[0]:
        return None
    absolute = _normal(target if target.startswith("/") else posixpath.join(posixpath.dirname(paths[0]), target))
    absolute = state.follow(absolute)
    if result["ok"]:
        state.links[paths[0]] = absolute
    return absolute


def _argv(token: str):
    if token == "NULL":
        return [], None
    if not (token.startswith("[") and token.endswith("]")):
        return None, "argv is not a list"
    inner = token[1:-1].strip()
    if not inner:
        return [], None
    try:
        _, items, _ = split_call("x(" + inner + ") = 0")
    except Unreadable as exc:
        return None, f"argv cannot be read: {exc}"
    argv = []
    for item in items:
        if item == "...":
            return None, "strace shortened argv"
        try:
            text, cut = string_arg(item)
        except Unreadable as exc:
            return None, f"argv cannot be read: {exc}"
        if cut:
            return None, "strace cut an argv string"
        argv.append(text)
    return argv, None


ADDRESS = {"family": re.compile(r"sa_family=(AF_[A-Z0-9_]+)"), "port": re.compile(r"sin6?_port=htons\((\d+)\)"),
           "ipv4": re.compile(r'inet_addr\("([0-9.]+)"\)'), "ipv6": re.compile(r'inet_pton\(AF_INET6, "([0-9a-fA-F:.]+)"'),
           "unix": re.compile(r'sun_path=(@?)"((?:[^"\\]|\\.)*)"(\.\.\.)?')}


def address_of(token: str):
    """({family, host, port, path}, problem) of a sockaddr, or (None, None) when the call names none."""
    if token in ("NULL", "", None) or "sa_family=" not in token:
        return None, None
    named = ADDRESS["family"].search(token)
    if not named:  # e.g. `sa_family=0x2a /* AF_??? */`
        return {"family": None, "host": None, "port": None, "path": None}, "the address family cannot be read"
    family = named.group(1)
    if family in ("AF_INET", "AF_INET6"):
        host = ADDRESS["ipv4" if family == "AF_INET" else "ipv6"].search(token)
        port = ADDRESS["port"].search(token)
        if not host or not port:
            return {"family": family, "host": None, "port": None, "path": None}, "the address cannot be read"
        return {"family": family, "host": host.group(1), "port": int(port.group(1)), "path": None}, None
    if family == "AF_UNIX":
        found = ADDRESS["unix"].search(token)
        if not found:
            return {"family": family, "host": None, "port": None, "path": None}, "the socket path cannot be read"
        if found.group(3):
            return {"family": family, "host": None, "port": None, "path": None}, "strace cut the socket path"
        return {"family": family, "host": None, "port": None, "path": found.group(1) + c_string(found.group(2))}, None
    return {"family": family, "host": None, "port": None, "path": None}, None


def _network_event(state, number, pid, body, name, kind, args, index, done) -> dict:
    address, problem = (None, None)
    if index is not None and index < len(args):
        token = args[index]
        if name in ("sendmsg", "recvmsg"):
            found = re.search(r"msg_name=(\{[^}]*\})", token)
            token = found.group(1) if found else "NULL"
        address, problem = address_of(token)
    dns = bool(address and address.get("port") == 53)
    return _event(state, number, pid, body, kind, name, address=address, dns=dns, problem=problem, **done)


# --- the baseline ----------------------------------------------------------------------------------------------------

def event_key(event: dict) -> tuple:
    """What makes two events of two runs the same event. A marker's nonce is new every run (check_trace has checked it)."""
    address = event.get("address") or {}
    path = event["path"]
    if event["type"] == "MARKER" and path:
        path = re.sub(r"^/\.cavr/[^/]*/", "/.cavr/<nonce>/", path)
    return (event["step"], event["type"], event["syscall"], path, event["real_path"], event["access"],
            tuple(sorted(address.items())), tuple(event["argv"] or ()), event["ok"], event["errno"], event["complete"])


def make_baseline(identity: str, normalised: dict) -> dict:
    """The record of one empty-harness run: its identity and its events' keys (with counts)."""
    keys = Counter(event_key(event) for event in normalised["events"])
    types = Counter(event["type"] for event in normalised["events"])
    return {"version": EVENTS_VERSION, "identity": identity, "types": dict(sorted(types.items())),
            "keys": [[list(key), count] for key, count in sorted(keys.items(), key=lambda item: repr(item[0]))],
            "not_clean": [_short(event) for event in normalised["events"]
                          if event["type"] not in CLEAN_BASELINE or not event["complete"]][:20]}


def check_baseline(baseline, identity: str) -> tuple[bool, str, str]:
    """(usable, rule, reason). BASELINE_INVALID / BASELINE_IDENTITY_MISMATCH / BASELINE_NOT_CLEAN / BASELINE_OK."""
    if not isinstance(baseline, dict) or baseline.get("version") != EVENTS_VERSION or not isinstance(baseline.get("keys"), list):
        return False, "BASELINE_INVALID", "the baseline record cannot be read"
    if baseline.get("identity") != identity:
        return False, "BASELINE_IDENTITY_MISMATCH", "the baseline was recorded for another image, harness, profile or strace"
    dirty = [key for key, _ in baseline["keys"] if not (isinstance(key, list) and len(key) == 11)
             or key[1] not in CLEAN_BASELINE or key[10] is not True]
    if dirty or baseline.get("not_clean"):
        first = (baseline.get("not_clean") or [{}])[0]
        return False, "BASELINE_NOT_CLEAN", (f"the empty-harness run has {max(len(dirty), len(baseline.get('not_clean') or []))} "
                                             f"events that are not code loads or structure (first: {first.get('type')} "
                                             f"{first.get('syscall')} {first.get('path') or first.get('address')}); it is not used")
    return True, "BASELINE_OK", f"{sum(count for _, count in baseline['keys'])} baseline events, all code loads or structure"


def subtract_baseline(events: list, baseline: dict) -> list:
    """`events` minus the baseline's, by key and count. The baseline must have passed `check_baseline`."""
    left = Counter({_tuple(key): count for key, count in baseline["keys"]})
    out = []
    for event in events:
        key = event_key(event)
        if left[key] > 0:
            left[key] -= 1
            continue
        out.append(event)
    return out


def _tuple(key):
    return tuple(tuple(tuple(pair) for pair in part) if index == 6 else tuple(part) if index == 7 else part
                 for index, part in enumerate(key))


def _short(event: dict) -> dict:
    return {key: event.get(key) for key in ("type", "syscall", "step", "path", "address", "argv", "ok", "errno", "line")}
