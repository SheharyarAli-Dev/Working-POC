"""PR 7 of docs/cavr-m2-plan.md: every attempted sensitive syscall becomes an event (`sandbox_events`).

Unit tests read real traces recorded on Docker (`tests/test_cavr_data/traces/events-*.txt`, made by
`record_events.py` in that directory; image, profile, harness and date in each .json) and small hand-made traces for
the edge cases a recording cannot show. Docker tests (CAVR_DOCKER=1) check the same things on a live run.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

import pytest

from backend.cavr import sandbox_events as events, sandbox_observe
from backend.cavr.sandbox_trace import check_trace
from tests.test_cavr_support import build_wheel, cavr_containers, requires_docker, sandbox_identity

TRACES = Path(__file__).parent / "test_cavr_data" / "traces"
JUDGED = set(events.JUDGED)


def recorded(stem):
    meta = json.loads((TRACES / f"{stem}.json").read_text())
    trace = (TRACES / f"{stem}.txt").read_text()
    checked = check_trace(trace.encode(), meta["nonce"], [step["name"] for step in meta["steps"]])
    assert checked["complete"], checked["reason"]
    return events.normalise(trace, checked["processes"], checked["steps"], meta["steps"]), meta


@pytest.fixture(scope="module")
def probe():
    return recorded("events-probe")[0]["events"]


@pytest.fixture(scope="module")
def benign():
    return recorded("events-benign")


@pytest.fixture(scope="module")
def baseline():
    normalised, _ = recorded("events-baseline")
    return events.make_baseline("identity", normalised)


def imports(found, kind=None):
    return [e for e in found if e["step"] == "imports" and (kind is None or e["type"] == kind)]


# hand-made traces: PID 9 is the harness, PID 10 the step `imports`
STEPS = [{"name": "imports", "argv": ["/usr/local/bin/python", "-c", "pass"], "env": {}}]
PROCESSES = {9: {"parent": None, "step": None, "role": "harness"}, 10: {"parent": 9, "step": "imports", "role": "step"},
             11: {"parent": 10, "step": "imports", "role": "step"}}


def made(*lines, step_pids=None):
    text = "".join(f"{line}\n" for line in lines)
    return events.normalise(text, PROCESSES, step_pids or {"imports": [10]}, STEPS)["events"]


def one(*lines, **kwargs):
    found = made(*lines, **kwargs)
    return found[-1]


# --- network attempts ----------------------------------------------------------------------------------------------------

def test_failed_connect_enetunreach_is_a_network_attempt(probe):
    found = [e for e in imports(probe, "NETWORK_CONNECT") if (e["address"] or {}).get("host") == "198.51.100.24"]
    assert len(found) == 1 and found[0]["ok"] is False and found[0]["errno"] == "ENETUNREACH"
    assert found[0]["address"] == {"family": "AF_INET", "host": "198.51.100.24", "port": 443, "path": None}
    assert found[0]["complete"] and found[0]["syscall"] == "connect"


def test_ipv6_and_unix_addresses_are_parsed(probe):
    addresses = [e["address"] for e in imports(probe, "NETWORK_CONNECT")]
    assert {"family": "AF_INET6", "host": "2001:db8::1", "port": 443, "path": None} in addresses
    assert {"family": "AF_UNIX", "host": None, "port": None, "path": "/run/cavr-probe.sock"} in addresses


def test_dns_lookup_is_a_network_attempt_to_port_53(probe):
    dns = [e for e in imports(probe, "NETWORK_CONNECT") if e["dns"] and e["syscall"] == "connect"]
    assert dns and all(e["address"]["port"] == 53 and e["ok"] is False for e in dns)  # getaddrinfo's nameserver
    assert any(e["path"] == "/etc/resolv.conf" for e in imports(probe, "FILE_READ"))


def test_sendto_with_an_address_is_a_network_attempt(probe):
    sent = [e for e in imports(probe, "NETWORK_CONNECT") if e["syscall"] == "sendto"]
    assert sent[0]["address"]["host"] == "203.0.113.5" and sent[0]["dns"] and sent[0]["errno"] == "ENETUNREACH"


def test_refused_sendmsg_is_still_a_network_attempt(probe):
    sent = [e for e in imports(probe, "NETWORK_CONNECT") if e["syscall"] == "sendmsg"]
    assert sent[0]["address"]["host"] == "203.0.113.6" and sent[0]["errno"] == "EPERM"  # not in the profile


def test_bind_is_its_own_event_with_its_address(benign):
    found = [e for e in benign[0]["events"] if e["type"] == "NETWORK_BIND"]
    assert [(e["step"], e["address"]["host"], e["address"]["port"]) for e in found] == [("install", "::1", 0)]


def test_sendfile_into_a_file_copies_and_into_a_socket_sends():
    assert one('10 sendfile(4</site/lib/x.py>, 3</tmp/y>, [0], 8) = 8')["type"] == "NO_EFFECT"
    sent = one('10 sendfile(4<TCP:[1:2]>, 3</tmp/y>, [0], 8) = -1 EPIPE (Broken pipe)')
    assert sent["type"] == "NETWORK_CONNECT" and sent["ok"] is False


# --- file reads, secrets and code ------------------------------------------------------------------------------------------

def test_read_of_aws_credentials_is_a_secret_read(probe):
    found = [e for e in imports(probe, "FILE_READ") if e["path"] == "/tmp/home/.aws/credentials"]
    assert found[0]["sensitive"] == "SECRET_READ" and found[0]["errno"] == "ENOENT"  # an attempt counts
    ok = one('10 openat(AT_FDCWD</tmp>, "/tmp/home/.aws/credentials", O_RDONLY) = 3</tmp/home/.aws/credentials>')
    denied = one('10 openat(AT_FDCWD</tmp>, "/root/.aws/config", O_RDONLY) = -1 EACCES (Permission denied)')
    assert (ok["sensitive"], ok["ok"]) == ("SECRET_READ", True) and (denied["sensitive"], denied["errno"]) == ("SECRET_READ", "EACCES")


@pytest.mark.parametrize("path, level", [
    ("/tmp/home/.ssh/id_rsa", "SECRET_READ"), ("/root/.ssh", "SECRET_READ"), ("/home/alice/.aws/credentials", "SECRET_READ"),
    ("/project/.env", "SECRET_READ"), ("/tmp/.env.local", "SECRET_READ"), ("/proc/1/environ", "SECRET_READ"),
    ("/proc/self/environ", "SECRET_READ"), ("/tmp/home/.netrc", "SECRET_READ"), ("/tmp/home/.docker/config.json", "SECRET_READ"),
    ("/etc/passwd", "SENSITIVE_FILE_READ"), ("/etc/shadow", "SENSITIVE_FILE_READ"), ("/etc/ssh/ssh_host_rsa_key", "SENSITIVE_FILE_READ"),
    ("/etc/hostname", None), ("/tmp/home/.sshx", None), ("/tmp/environment", None), ("/etc/passwd-", None), ("/tmp/env", None),
])
def test_sensitive_path_table(path, level):
    assert events.sensitivity(path)[0] == level


def test_stat_of_a_sensitive_path_is_a_sensitive_read_attempt(probe):
    found = [e for e in imports(probe, "FILE_READ") if e["path"] == "/tmp/home/.ssh/id_rsa"]
    assert found[0]["access"] == "metadata" and found[0]["sensitive"] == "SECRET_READ" and found[0]["ok"] is False  # D4


def test_etc_passwd_is_a_sensitive_read(probe):
    found = [e for e in imports(probe, "FILE_READ") if e["path"] == "/etc/passwd"]
    assert found[0]["sensitive"] == "SENSITIVE_FILE_READ" and found[0]["ok"] is True


def test_a_symlink_to_a_secret_is_caught_by_its_real_path():
    found = one('10 openat(AT_FDCWD</tmp>, "/tmp/innocent", O_RDONLY) = 3</tmp/home/.aws/credentials>')
    assert found["type"] == "FILE_READ" and found["sensitive"] == "SECRET_READ" and found["real_path"] == "/tmp/home/.aws/credentials"
    code = one('10 openat(AT_FDCWD</tmp>, "/usr/local/lib/x.py", O_RDONLY) = 3</tmp/home/.ssh/id_rsa>')
    assert code["type"] == "FILE_READ" and code["sensitive"] == "SECRET_READ"  # a code path whose real file is a secret


def test_code_reads_are_code_load_not_file_read(benign):
    found = benign[0]["events"]
    own = [e for e in imports(found) if e["path"] == "/site/lib/benign/__init__.py"]
    assert own and all(e["type"] == "CODE_LOAD" for e in own)
    assert any(e["type"] == "CODE_LOAD" and e["path"].startswith("/usr/local/lib/python3.12/") for e in imports(found))
    assert one('10 openat(AT_FDCWD</tmp>, "/usr/local/lib/python3.12/json/__init__.py", O_RDONLY) = 3</usr/local/lib/python3.12/json/__init__.py>')["type"] == "CODE_LOAD"
    assert one('10 openat(AT_FDCWD</tmp>, "/etc/os-release", O_RDONLY) = 3</usr/lib/os-release>')["type"] == "FILE_READ"
    assert one('10 newfstatat(AT_FDCWD</tmp>, "/usr", {st_mode=S_IFDIR|0755}, 0) = 0')["type"] == "CODE_LOAD"
    assert one('10 openat(AT_FDCWD</tmp>, "/usr", O_RDONLY|O_DIRECTORY) = 3</usr>')["type"] == "FILE_READ"  # a listing of /usr


def test_a_write_into_a_code_location_is_a_file_write():
    found = one('10 openat(AT_FDCWD</tmp>, "/site/lib/benign/evil.py", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 3</site/lib/benign/evil.py>')
    assert found["type"] == "FILE_WRITE" and found["path"] == "/site/lib/benign/evil.py"


def test_dev_null_is_no_effect():
    assert one('10 openat(AT_FDCWD</tmp>, "/dev/null", O_WRONLY|O_CLOEXEC) = 3</dev/null>')["type"] == "NO_EFFECT"


# --- writes, exec, credentials, refused ----------------------------------------------------------------------------------

def test_writes_creat_rename_unlink_mkdir_are_file_writes(probe):
    writes = {(e["syscall"], e["path"]) for e in imports(probe, "FILE_WRITE")}
    assert {("openat", "/tmp/rel.txt"), ("openat", "/tmp/rel2.txt"), ("rename", "/tmp/rel.txt"), ("unlink", "/tmp/rel4.txt"),
            ("mkdir", "/tmp/d")} <= writes
    renamed = next(e for e in imports(probe, "FILE_WRITE") if e["syscall"] == "rename")
    assert renamed["paths"] == ["/tmp/rel.txt", "/tmp/rel4.txt"]
    assert one('10 creat("/tmp/x", 0644) = 3</tmp/x>')["type"] == "FILE_WRITE"


@pytest.mark.parametrize("path, expected", [
    ("/tmp/home/.bashrc", True), ("/tmp/home/.ssh/authorized_keys", True), ("/etc/cron.d/job", True), ("/etc/rc.local", True),
    ("/site/lib/evil.pth", True), ("/tmp/x/sitecustomize.py", True), ("/etc/systemd/system/x.service", True),
    ("/etc/profile.d/x.sh", True), ("/tmp/notes.txt", False), ("/etc/cronx", True),
])
def test_persistence_paths(path, expected):
    assert events.persistence(path) is expected


def test_append_to_bashrc_is_a_persistence_write_attempt(probe):
    found = [e for e in imports(probe, "FILE_WRITE") if e["path"] == "/tmp/home/.bashrc"]
    assert found[0]["persistence"] and found[0]["errno"] == "ENOENT"


def test_execve_of_a_shell_is_process_exec(probe):
    found = imports(probe, "PROCESS_EXEC")
    assert [(e["path"], e["argv"], e["ok"]) for e in found] == [("/bin/sh", ["/bin/sh", "-c", "true"], True)]
    failed = one('11 execve("/usr/bin/curl", ["curl", "x"], 0x7f /* 8 vars */) = -1 ENOENT (No such file or directory)')
    assert failed["type"] == "PROCESS_EXEC" and failed["ok"] is False


def test_step_launch_is_not_a_package_exec(benign):
    found, meta = benign
    starts = [e for e in found["events"] if e["type"] == "STEP_START"]
    assert [e["step"] for e in starts] == ["install", "imports"]
    assert [e["argv"] for e in starts] == [step["argv"] for step in meta["steps"]]
    other = made('10 execve("/usr/local/bin/python", ["/usr/local/bin/python", "-c", "import os"], 0x7f /* 8 vars */) = 0')
    assert other[-1]["type"] == "PROCESS_EXEC"  # not the job's argv
    second = made('10 execve("/usr/local/bin/python", ["/usr/local/bin/python", "-c", "pass"], 0x7f /* 8 vars */) = 0',
                  '10 execve("/usr/local/bin/python", ["/usr/local/bin/python", "-c", "pass"], 0x7f /* 8 vars */) = 0')
    assert [e["type"] for e in second] == ["STEP_START", "PROCESS_EXEC"]  # only the first exec starts the step
    child = one('11 execve("/usr/local/bin/python", ["/usr/local/bin/python", "-c", "pass"], 0x7f /* 8 vars */) = 0')
    assert child["type"] == "PROCESS_EXEC"  # not the step's first process


def test_credential_change_even_when_it_fails(probe):
    found = imports(probe, "CREDENTIAL_CHANGE")
    assert [(e["syscall"], e["errno"]) for e in found] == [("setuid", "EPERM")]


def test_refused_dangerous_syscalls_are_events(probe):
    found = {e["syscall"]: e for e in imports(probe, "REFUSED_SYSCALL")}
    assert found["ptrace"]["errno"] == "EPERM" and found["bpf"]["errno"] == "EPERM"
    for name in ("io_uring_setup(0, NULL)", "unshare(CLONE_NEWUSER)", "mount(\"none\", \"/tmp\", \"tmpfs\", 0, NULL)"):
        assert one(f"10 {name} = -1 EPERM (Operation not permitted)")["type"] == "REFUSED_SYSCALL"


def test_clone_with_and_without_clone_thread_is_structure(probe):
    clones = [e for e in imports(probe) if e["syscall"] in ("clone", "clone3")]
    raw = " ".join(e["raw"] for e in clones)
    assert "CLONE_THREAD" in raw and "SIGCHLD" in raw and all(e["type"] == "PROCESS" for e in clones)
    child = [e for e in probe if e["path"] == "/tmp/child.txt"]
    assert child and child[0]["step"] == "imports"  # the forked child's events belong to the step


# --- paths -----------------------------------------------------------------------------------------------------------------

def test_relative_path_resolved_against_cwd(probe):
    paths = {e["path"] for e in imports(probe) if e["path"]}
    assert {"/tmp/.env", "/tmp/rel.txt", "/tmp/rel2.txt", "/tmp/child.txt"} <= paths
    after = made('10 chdir("/site") = 0', '10 mkdir("lib/x", 0777) = 0', '10 newfstatat(AT_FDCWD</site>, "y", 0x1, 0) = -1 ENOENT (No such file or directory)')
    assert [e["path"] for e in after] == ["/site", "/site/lib/x", "/site/y"]
    relative = made('10 chdir("../opt") = 0', '10 mkdir("z", 0777) = 0')
    assert relative[0]["complete"] is False and relative[1]["complete"] is False  # no known directory yet


def test_a_child_inherits_the_directory_and_another_process_forgets_it():
    found = made('10 getcwd("/tmp", 1024) = 5', '11 mkdir("a", 0777) = 0', '10 chdir("/site") = 0', '11 mkdir("b", 0777) = 0',
                 '10 mkdir("c", 0777) = 0')
    assert [e["path"] for e in found[1:]] == ["/tmp/a", "/site", None, "/site/c"]
    assert found[3]["complete"] is False  # after 10's chdir, 11 (perhaps a thread) has no known directory


def test_dirfd_relative_path(probe):
    found = [e for e in imports(probe) if e["path"] == "/tmp/rel3.txt"]
    assert found and found[0]["syscall"] == "openat" and "3</tmp>" in found[0]["raw"]
    assert one('10 fchdir(3</site/lib>) = 0')["path"] == "/site/lib"


def test_unresolvable_dirfd_is_incomplete():
    found = one('10 openat(3, "x", O_RDONLY) = -1 ENOENT (No such file or directory)')
    assert found["complete"] is False and "directory fd" in found["problem"]
    socket = one('10 openat(3<socket:[1]>, "x", O_RDONLY) = -1 ENOTDIR (Not a directory)')
    assert socket["complete"] is False


def test_truncated_path_is_incomplete():
    found = one('10 openat(AT_FDCWD</tmp>, "/tmp/home/.aw"..., O_RDONLY) = 3</tmp/home/.aws/credentials>')
    assert found["complete"] is False and "cut" in found["problem"]
    assert found["sensitive"] == "SECRET_READ"  # the real path still shows what it was


def test_a_4000_character_path_is_kept_whole(probe):
    long = [e for e in imports(probe) if e["path"] and len(e["path"]) > 4000]
    assert long and long[0]["path"] == "/" + "a" * 4000 and long[0]["complete"] and long[0]["errno"] == "ENAMETOOLONG"


def test_escaped_strings_are_decoded():
    found = one(r'10 openat(AT_FDCWD</tmp>, "/tmp/a\"b\\c\n\x41\101", O_RDONLY) = -1 ENOENT (No such file or directory)')
    assert found["path"] == '/tmp/a"b\\c\nAA'


# --- unknown and unreadable ------------------------------------------------------------------------------------------------

def test_unknown_syscall_is_an_unknown_event():
    found = one('10 inotify_add_watch(3, "/tmp", IN_ALL_EVENTS) = -1 EPERM (Operation not permitted)')
    assert found["type"] == "UNKNOWN" and "no rule" in found["problem"]


@pytest.mark.parametrize("line", ['10 openat(AT_FDCWD</tmp>, "/tmp/x, O_RDONLY) = 3', '10 connect(3, {sa_family=AF_INET', '10 rename("/a") = 0',
                                  '10 <... connect resumed>) = 0'])
def test_unreadable_line_is_an_unknown_event(line):
    found = one(line)
    assert found["type"] == "UNKNOWN" and found["complete"] is False


def test_an_unfinished_call_is_joined_to_its_resumption(probe):
    shells = imports(probe, "PROCESS_EXEC")
    assert shells[0]["complete"] and "unfinished" not in shells[0]["raw"]
    never = made('10 connect(3<socket:[1]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("10.0.0.1")}, 16 <unfinished ...>')
    assert never[0]["type"] == "UNKNOWN" and "never returned" in never[0]["problem"]


def test_every_recorded_syscall_has_a_rule(probe, benign):
    for found in (probe, benign[0]["events"]):
        assert [e["raw"][:80] for e in found if e["type"] == "UNKNOWN"] == []
        assert [e["raw"][:80] for e in found if not e["complete"]] == []


# --- the baseline ----------------------------------------------------------------------------------------------------------

def test_recorded_baseline_is_clean(baseline):
    assert events.check_baseline(baseline, "identity")[:2] == (True, "BASELINE_OK")
    assert set(baseline["types"]) <= set(events.CLEAN_BASELINE)


def test_benign_import_has_no_file_write_and_nothing_judged_after_the_baseline(benign, baseline):
    left = events.subtract_baseline(benign[0]["events"], baseline)
    assert [e for e in imports(left) if e["type"] in JUDGED] == []
    assert [e for e in imports(benign[0]["events"]) if e["type"] == "FILE_WRITE"] == []  # -B: no .pyc either


def test_baseline_subtraction_is_exact_and_counted():
    line = '10 openat(AT_FDCWD</tmp>, "/etc/hostname", O_RDONLY) = 3</etc/hostname>'
    base = events.make_baseline("identity", {"events": made(line)})
    base["not_clean"] = []  # a FILE_READ is not allowed in a real baseline; here only the arithmetic is tested
    run = made(line, line, line.replace("O_RDONLY) = 3</etc/hostname>", "O_RDONLY) = -1 EACCES (Permission denied)"))
    left = events.subtract_baseline(run, base)
    assert len(left) == 2 and [e["ok"] for e in left] == [True, False]  # one of the two identical reads, and the failure


def test_baseline_of_another_identity_is_refused(baseline):
    assert events.check_baseline(baseline, "other")[1] == "BASELINE_IDENTITY_MISMATCH"
    assert events.check_baseline({"version": "x"}, "identity")[1] == "BASELINE_INVALID"
    assert events.check_baseline(None, "identity")[1] == "BASELINE_INVALID"


@pytest.mark.parametrize("line", [
    '10 openat(AT_FDCWD</tmp>, "/tmp/home/.aws/credentials", O_RDONLY) = -1 ENOENT (No such file or directory)',
    '10 connect(3<socket:[1]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = -1 ENETUNREACH (Network is unreachable)',
    '11 execve("/bin/sh", ["/bin/sh"], 0x7f /* 8 vars */) = 0',
    '10 setuid(0) = -1 EPERM (Operation not permitted)',
    '10 ptrace(PTRACE_TRACEME) = -1 EPERM (Operation not permitted)',
    '10 inotify_add_watch(3, "/tmp", IN_ALL_EVENTS) = -1 EPERM (Operation not permitted)',
    '10 openat(AT_FDCWD</tmp>, "/tmp/x", O_WRONLY|O_CREAT, 0644) = 3</tmp/x>',
    '10 openat(3, "x", O_RDONLY) = 4</usr/local/lib/x>',
])
def test_a_baseline_with_anything_but_code_and_structure_is_not_clean(baseline, line):
    dirty = events.make_baseline("identity", {"events": events.normalise("".join(
        f"{raw}\n" for raw in [*_baseline_lines(), line]), PROCESSES, {"imports": [10]}, STEPS)["events"]})
    usable, rule, reason = events.check_baseline(dirty, "identity")
    assert (usable, rule) == (False, "BASELINE_NOT_CLEAN") and "not code loads or structure" in reason


def _baseline_lines():
    return ['10 openat(AT_FDCWD</tmp>, "/usr/local/lib/python3.12/os.py", O_RDONLY) = 3</usr/local/lib/python3.12/os.py>']


# --- the partial trace (D6) ----------------------------------------------------------------------------------------------

def _benign_trace():
    meta = json.loads((TRACES / "events-benign.json").read_text())
    return (TRACES / "events-benign.txt").read_text(), meta


def test_partial_trace_of_a_killed_run_is_attributable():
    trace, meta = _benign_trace()
    cut = trace[:len(trace) * 2 // 3]
    cut = cut[:cut.rfind("\n") + 25]  # ends inside a line, as a killed run's output does
    steps = [step["name"] for step in meta["steps"]]
    assert check_trace(cut.encode(), meta["nonce"], steps)["complete"] is False
    partial = check_trace(cut.encode(), meta["nonce"], steps, partial=True)
    assert (partial["complete"], partial["attributable"], partial["rule"]) == (False, True, "TRACE_PARTIAL")
    assert partial["processes"] and partial["steps"]["install"]


def test_partial_mode_still_refuses_unknown_pids_and_foreign_markers():
    trace, meta = _benign_trace()
    steps = [step["name"] for step in meta["steps"]]
    head = trace[:trace.find("\n", 20000) + 1]
    stray = head + '4242  openat(AT_FDCWD</tmp>, "/tmp/x", O_RDONLY) = 3</tmp/x>\n'
    assert check_trace(stray.encode(), meta["nonce"], steps, partial=True)["rule"] == "TRACE_UNKNOWN_PID"
    root = head.split()[0]
    foreign = head + f'{root}     newfstatat(AT_FDCWD</tmp>, "/.cavr/{"f" * 32}/start", 0x1, 0) = -1 ENOENT (No such file or directory)\n'
    assert check_trace(foreign.encode(), meta["nonce"], steps, partial=True)["rule"] == "TRACE_MARKERS"
    assert check_trace(b"not a trace\n", meta["nonce"], steps, partial=True)["attributable"] is False


def test_failed_step_trace_is_attributable_with_the_failed_step():
    trace, meta = _benign_trace()
    nonce = meta["nonce"]
    failed = trace.replace(f"/.cavr/{nonce}/step:imports:end:0", f"/.cavr/{nonce}/step:imports:end:1") \
                  .replace(f"/.cavr/{nonce}/end:ok", f"/.cavr/{nonce}/end:fail")
    root = trace.split()[0]
    failed = re.sub(rf"(?m)^{root} +\+\+\+ exited with 0 \+\+\+$", f"{root}     +++ exited with 4 +++", failed)
    steps = [step["name"] for step in meta["steps"]]
    assert check_trace(failed.encode(), nonce, steps)["complete"] is False
    partial = check_trace(failed.encode(), nonce, steps, partial=True)
    assert partial["attributable"] and partial["rule"] == "TRACE_PARTIAL"
    skipped = failed.replace(f"/.cavr/{nonce}/step:install:end:0", f"/.cavr/{nonce}/step:install:end:7")
    assert check_trace(skipped.encode(), nonce, steps, partial=True)["rule"] == "TRACE_MARKERS"  # a step ran after a failure


def test_a_complete_trace_is_attributable():
    trace, meta = _benign_trace()
    checked = check_trace(trace.encode(), meta["nonce"], [step["name"] for step in meta["steps"]])
    assert checked["complete"] and checked["attributable"]


# --- live runs (Docker) ----------------------------------------------------------------------------------------------------

def _observe(tmp_path, name, code, hash_override=None):
    sandbox_identity()
    quarantine = tmp_path / "quarantine"
    quarantine.mkdir()
    wheel = build_wheel(quarantine, name, "1.0", files={f"{name}/__init__.py": code})
    node = {"name": name, "version": "1.0", "filename": wheel.name, "path": str(wheel),
            "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()}
    if hash_override:
        original = sandbox_observe.stage_wheels

        def staged(nodes, quarantine_dir, stage_dir):
            out = original(nodes, quarantine_dir, stage_dir)
            (Path(stage_dir) / sandbox_observe.HASH_FILE).write_text(f"{name}==1.0 --hash=sha256:{hash_override}\n")
            return out
        sandbox_observe.stage_wheels = staged
        try:
            result = sandbox_observe.observe([node], [name], quarantine_dir=quarantine)
        finally:
            sandbox_observe.stage_wheels = original
    else:
        result = sandbox_observe.observe([node], [name], quarantine_dir=quarantine)
    evidence = result["evidence"]
    normalised = events.normalise(result["trace"], evidence["processes"], evidence["step_pids"], evidence["job_steps"])
    return result, normalised["events"]


def _baseline_run():
    steps = [sandbox_observe.step("imports", sandbox_observe.IMPORT_ARGV)]
    result = sandbox_observe.run_harness(steps, tmpfs=[sandbox_observe.SITE_TMPFS])
    assert result["rule"] == "DEEP_NOT_JUDGED", result["reason"]
    evidence = result["evidence"]
    return events.normalise(result["trace"], evidence["processes"], evidence["step_pids"], evidence["job_steps"])


@requires_docker
def test_two_empty_harness_runs_give_the_same_events():
    sandbox_identity()
    first, second = _baseline_run(), _baseline_run()
    assert Counter(map(events.event_key, first["events"])) == Counter(map(events.event_key, second["events"]))
    assert events.check_baseline(events.make_baseline("id", first), "id")[1] == "BASELINE_OK"
    assert cavr_containers() == []


@requires_docker
def test_package_that_calls_chdir_is_traced_not_refused(tmp_path):
    code = ("import os\nos.chdir('/site')\nos.stat('lib')\nfd = os.open('/site/lib', os.O_RDONLY)\nos.fchdir(fd)\n"
            "os.listdir('.')\n")
    result, found = _observe(tmp_path, "mover", code)
    assert result["rule"] == "DEEP_NOT_JUDGED", result["reason"]
    moves = [(e["syscall"], e["path"], e["ok"]) for e in found if e["type"] == "CWD_CHANGE"]
    assert moves == [("chdir", "/site", True), ("fchdir", "/site/lib", True)]
    assert any(e["path"] == "/site/lib" and e["syscall"] == "newfstatat" for e in imports(found))
    assert [e for e in found if not e["complete"]] == []


@requires_docker
def test_y_prints_the_path_of_every_fd(tmp_path):
    code = "import os\nfd = os.open('/tmp', os.O_RDONLY)\ntry:\n    os.open('nope', os.O_RDONLY, dir_fd=fd)\nexcept OSError:\n    pass\n"
    result, found = _observe(tmp_path, "dirfd", code)
    hit = [e for e in imports(found) if e["path"] == "/tmp/nope"]
    assert hit and hit[0]["complete"] and re.search(r"openat\(\d+</tmp>, \"nope\"", hit[0]["raw"])


@requires_docker
def test_benign_wheel_import_produces_zero_file_write_events(tmp_path):
    result, found = _observe(tmp_path, "quiet", "def run():\n    return 1\n")
    assert result["rule"] == "DEEP_NOT_JUDGED"
    assert [e["path"] for e in imports(found, "FILE_WRITE")] == []
    assert [e for e in found if e["type"] == "UNKNOWN" or not e["complete"]] == []


# What pip 25.0.1 still reads in /etc with its User-Agent builder replaced (measured 2026-11-23): its global pip.conf
# (--isolated skips only the user's), the mime.types search of the stdlib `mimetypes`, and OpenSSL's config and CA
# bundle (real paths of /usr/lib/ssl/...). No /etc listing, no os-release, no account file.
INSTALL_ETC_READS = {"/etc/pip.conf", "/etc/xdg/pip/pip.conf", "/etc/mime.types", "/etc/httpd/mime.types",
                     "/etc/httpd/conf/mime.types", "/etc/apache/mime.types", "/etc/apache2/mime.types",
                     "/etc/ssl/openssl.cnf", "/etc/ssl/certs/ca-certificates.crt"}


def _install_etc(found):
    return {p for e in found if e["step"] == "install" and e["type"] != "CODE_LOAD"
            for p in (e["path"], e["real_path"]) if p and p.startswith("/etc")}


@requires_docker
def test_install_step_has_no_exec_and_reads_only_the_measured_etc_files(tmp_path):
    result, found = _observe(tmp_path, "plain", "VALUE = 1\n")
    assert result["rule"] == "DEEP_NOT_JUDGED"
    install = [e for e in found if e["step"] == "install"]
    assert [e["argv"][:3] for e in install if e["type"] == "PROCESS_EXEC"] == []
    assert [e["path"] for e in install if e["sensitive"]] == []
    assert _install_etc(found) == INSTALL_ETC_READS
    assert not any(e["path"] == "/etc" for e in install)  # no listing of /etc (pip's `distro` scan is gone)


@requires_docker
def test_install_step_still_refuses_a_wrong_hash_without_exec_or_other_etc_reads(tmp_path):
    result, found = _observe(tmp_path, "tampered", "VALUE = 1\n", hash_override="0" * 64)
    assert result["rule"] == "SANDBOX_EXIT_NONZERO" and result["evidence"]["trace_attributable"] is True
    assert "THESE PACKAGES DO NOT MATCH THE HASHES" in result["output"]["text"]
    install = [e for e in found if e["step"] == "install"]
    assert install and [e for e in install if e["type"] == "PROCESS_EXEC"] == []
    assert _install_etc(found) <= INSTALL_ETC_READS
    assert not [e for e in found if e["step"] == "imports"]  # the import never ran
    assert cavr_containers() == []


def test_the_old_normalizer_is_gone():
    """Q12: `normalizer.py` (audit-hook events, used by nothing) is replaced by `sandbox_events` and deleted."""
    assert not (Path(events.__file__).parent / "normalizer.py").exists()


def test_a_markers_nonce_is_not_part_of_its_key():
    """Each run has a new marker nonce; two empty runs must still give the same baseline keys (measured on Docker)."""
    one_run, other = ({"step": "harness", "type": "MARKER", "syscall": "newfstatat", "path": f"/.cavr/{n * 32}/start",
                       "real_path": None, "access": "metadata", "address": None, "argv": None, "ok": False,
                       "errno": "ENOENT", "complete": True} for n in "ab")
    assert events.event_key(one_run) == events.event_key(other)
    read = {**one_run, "type": "FILE_READ"}
    assert events.event_key(read) != events.event_key({**other, "type": "FILE_READ"})  # only markers lose the nonce


# --- review of PRs 7-9: sensitive paths behind writes, aliases and the run's own symlinks --------------------------------

@pytest.mark.parametrize("line", [
    '10 openat(AT_FDCWD</tmp>, "/tmp/home/.aws/credentials", O_RDWR|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
    '10 rename("/tmp/home/.aws/credentials", "/tmp/x") = -1 ENOENT (No such file or directory)',
    '10 link("/tmp/home/.ssh/id_rsa", "/tmp/k") = -1 ENOENT (No such file or directory)',
    '10 linkat(AT_FDCWD</tmp>, "/etc/shadow", AT_FDCWD</tmp>, "/tmp/s", 0) = -1 EPERM (Operation not permitted)',
    '10 truncate("/tmp/home/.netrc", 0) = -1 ENOENT (No such file or directory)',
    '10 symlink("/tmp/home/.aws/credentials", "/tmp/c") = 0',
])
def test_a_write_that_names_a_sensitive_path_is_also_sensitive(line):
    found = one(line)
    assert found["type"] == "FILE_WRITE" and found["sensitive"] in ("SECRET_READ", "SENSITIVE_FILE_READ"), found


@pytest.mark.parametrize("path", ["/proc/self/root/tmp/home/.aws/credentials", "/proc/1/cwd/x", "/proc/self/fd/3",
                                  "/proc/12/task/12/root/etc/passwd", "/proc/thread-self/root/tmp/home/.ssh/id_rsa",
                                  "/dev/fd/3/x", "/proc/self/map_files/1-2"])
def test_a_path_through_a_proc_or_fd_alias_is_incomplete(path):
    found = one(f'10 openat(AT_FDCWD</tmp>, "{path}", O_RDONLY) = -1 ENOENT (No such file or directory)')
    assert found["complete"] is False and "alias" in found["problem"]


def test_proc_self_exe_and_environ_are_not_aliases():
    assert one('10 readlinkat(AT_FDCWD</tmp>, "/proc/self/exe", "/usr/local/bin/python3.12", 4096) = 25')["type"] == "CODE_LOAD"
    assert one('10 openat(AT_FDCWD</tmp>, "/proc/self/environ", O_RDONLY) = 3</proc/10/environ>')["sensitive"] == "SECRET_READ"


def test_a_symlink_the_run_made_is_followed_by_later_paths():
    found = made('10 symlink("/tmp/home", "/tmp/h") = 0',
                 '10 openat(AT_FDCWD</tmp>, "/tmp/h/.aws/credentials", O_RDONLY) = -1 ENOENT (No such file or directory)',
                 '10 symlink("home", "/tmp/rel") = 0', '10 newfstatat(AT_FDCWD</tmp>, "/tmp/rel/.ssh/id_rsa", 0x1, 0) = -1 ENOENT (No such file or directory)')
    assert found[0]["link_target"] == "/tmp/home"
    assert (found[1]["path"], found[1]["sensitive"]) == ("/tmp/home/.aws/credentials", "SECRET_READ")
    assert found[2]["link_target"] == "/tmp/home"  # relative to the link's directory
    assert (found[3]["path"], found[3]["sensitive"]) == ("/tmp/home/.ssh/id_rsa", "SECRET_READ")


def test_a_symlink_in_the_install_target_is_not_a_code_load():
    found = made('10 symlink("/tmp/home/.aws/credentials", "/site/lib/demo/data") = 0',
                 '10 newfstatat(AT_FDCWD</tmp>, "/site/lib/demo/data", 0x1, 0) = -1 ENOENT (No such file or directory)')
    assert found[0]["sensitive"] == "SECRET_READ"
    assert found[1]["type"] == "FILE_READ" and found[1]["sensitive"] == "SECRET_READ"


def test_a_failed_symlink_creates_no_link():
    found = made('10 symlink("/tmp/home", "/tmp/h") = -1 EEXIST (File exists)',
                 '10 openat(AT_FDCWD</tmp>, "/tmp/h/x", O_RDONLY) = -1 ENOENT (No such file or directory)')
    assert found[1]["path"] == "/tmp/h/x"


@pytest.mark.parametrize("path, level", [("/nonexistent/.ssh/id_rsa", "SECRET_READ"), ("/proc/1/task/7/environ", "SECRET_READ")])
def test_more_sensitive_paths(path, level):
    assert events.sensitivity(path)[0] == level


def test_an_unknown_address_family_is_incomplete_not_an_exception():
    found = one('10 connect(3<socket:[1]>, {sa_family=0x2a /* AF_??? */, sa_data="x"}, 16) = -1 EAFNOSUPPORT (Address family not supported by protocol)')
    assert found["type"] == "NETWORK_CONNECT" and found["complete"] is False


def test_a_line_the_code_cannot_handle_is_unknown_and_the_rest_is_kept(monkeypatch):
    original = events._line_event

    def flaky(state, number, pid, body):
        if "boom" in body:
            raise ValueError("unexpected")
        return original(state, number, pid, body)
    monkeypatch.setattr(events, "_line_event", flaky)
    found = made('10 openat(AT_FDCWD</tmp>, "/tmp/boom", O_RDONLY) = 3</tmp/boom>', '10 setuid(0) = -1 EPERM (Operation not permitted)')
    assert [e["type"] for e in found] == ["UNKNOWN", "CREDENTIAL_CHANGE"] and "ValueError" in found[0]["problem"]
