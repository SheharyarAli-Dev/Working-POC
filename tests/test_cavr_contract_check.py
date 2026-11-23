"""PR 8 of docs/cavr-m2-plan.md: observed events judged against the capability contract (`contract_check.judge`)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.cavr import contract_check, sandbox_events
from backend.cavr.capability_contract import _capabilities, vocabulary
from backend.cavr.sandbox_trace import check_trace

TRACES = Path(__file__).parent / "test_cavr_data" / "traces"
VOCABULARY = vocabulary()
STEPS = [{"name": "install", "argv": ["/usr/local/bin/python", "-c", "pip"], "env": {}},
         {"name": "imports", "argv": ["/usr/local/bin/python", "-c", "import x"], "env": {}}]
PROCESSES = {9: {"parent": None, "step": None}, 10: {"parent": 9, "step": "install"}, 11: {"parent": 9, "step": "imports"},
             12: {"parent": 11, "step": "imports"}}


def contract(**allowed):
    """A readable contract: `allowed` maps capability -> scope (status OPTIONAL); everything else is denied."""
    allow = [{"capability": name, "scope": scope, "status": "OPTIONAL"} for name, scope in allowed.items()]
    deny = [{"capability": name, "source": "default deny"} for name in VOCABULARY if name not in allowed]
    return {"result": "OK", "rule": "CONTRACT_INFERRED", "allowed": allow, "denied": deny, "vocabulary": VOCABULARY}


def ev(*lines, pid=11):
    text = "".join(f"{pid} {line}\n" for line in lines)
    return sandbox_events.normalise(text, PROCESSES, {"install": [10], "imports": [11]}, STEPS)["events"]


def recorded(stem):
    meta = json.loads((TRACES / f"{stem}.json").read_text())
    trace = (TRACES / f"{stem}.txt").read_text()
    checked = check_trace(trace.encode(), meta["nonce"], [step["name"] for step in meta["steps"]])
    return sandbox_events.normalise(trace, checked["processes"], checked["steps"], meta["steps"])["events"]


def baseline():
    found = recorded("events-baseline")
    return sandbox_events.make_baseline("id", {"events": found})


CONNECT = 'connect(3<socket:[1]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("198.51.100.24")}, 16) = -1 ENETUNREACH (Network is unreachable)'
SECRET = 'openat(AT_FDCWD</tmp>, "/tmp/home/.aws/credentials", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)'
READ = 'openat(AT_FDCWD</tmp>, "/data/in.pdf", O_RDONLY) = 3</data/in.pdf>'
WRITE = 'openat(AT_FDCWD</tmp>, "/tmp/out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</tmp/out.txt>'
EXEC = 'execve("/bin/sh", ["/bin/sh", "-c", "id"], 0x7f /* 8 vars */) = 0'
BASHRC = 'openat(AT_FDCWD</tmp>, "/tmp/home/.bashrc", O_WRONLY|O_APPEND, 0666) = -1 ENOENT (No such file or directory)'


# --- each capability: denied, allowed, scoped ----------------------------------------------------------------------------

@pytest.mark.parametrize("line, capability", [(CONNECT, "NETWORK_CONNECT"), (SECRET, "SECRET_READ"), (READ, "FILE_READ"),
                                               (WRITE, "FILE_WRITE"), (EXEC, "PROCESS_EXEC"), (BASHRC, "PERSISTENCE_WRITE"),
                                               ('openat(AT_FDCWD</tmp>, "/etc/passwd", O_RDONLY) = 3</etc/passwd>', "SENSITIVE_FILE_READ")])
def test_denied_capability_is_a_violation(line, capability):
    checked = contract_check.judge(ev(line), contract())
    assert checked["result"] == "VIOLATION" and checked["violations"][0]["capability"] == capability
    assert checked["violations"][0]["event"]["raw"].endswith(line[-30:])  # the event is the evidence


def test_failed_attempt_counts_like_a_success():
    failed, worked = ev(CONNECT), ev(CONNECT.replace("= -1 ENETUNREACH (Network is unreachable)", "= 0"))
    assert failed[0]["ok"] is False and worked[0]["ok"] is True
    assert contract_check.judge(failed, contract())["result"] == contract_check.judge(worked, contract())["result"] == "VIOLATION"


@pytest.mark.parametrize("line, capability", [(CONNECT, "NETWORK_CONNECT"), (SECRET, "SECRET_READ"), (READ, "FILE_READ"),
                                               (WRITE, "FILE_WRITE"), (EXEC, "PROCESS_EXEC")])
def test_unrestricted_grant_allows(line, capability):
    assert contract_check.judge(ev(line), contract(**{capability: "*"}))["result"] == "OK"


def test_scoped_network_grant_matching_and_non_matching_endpoint():
    granted = contract(NETWORK_CONNECT="198.51.100.24:443, [2001:db8::1]:443")
    assert contract_check.judge(ev(CONNECT), granted)["result"] == "OK"
    other = CONNECT.replace("htons(443)", "htons(80)")
    assert contract_check.judge(ev(other), granted)["result"] == "VIOLATION"
    six = 'connect(3<socket:[1]>, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:db8::1", &sin6_addr), sin6_scope_id=0}, 28) = -1 ENETUNREACH (Network is unreachable)'
    assert contract_check.judge(ev(six), granted)["result"] == "OK"
    unix = 'connect(3<socket:[1]>, {sa_family=AF_UNIX, sun_path="/var/run/docker.sock"}, 110) = -1 ENOENT (No such file or directory)'
    assert contract_check.judge(ev(unix), granted)["result"] == "VIOLATION"
    no_address = 'sendto(3<socket:[1]>, "x", 1, 0, NULL, 0) = -1 EDESTADDRREQ (Destination address required)'
    assert contract_check.judge(ev(no_address), granted)["rule"] == "EVENT_INCOMPLETE"


def test_scoped_file_grant_by_path_prefix():
    granted = contract(FILE_READ="/data, /srv/in")
    assert contract_check.judge(ev(READ), granted)["result"] == "OK"
    outside = READ.replace("/data/in.pdf", "/etc/hostname")
    assert contract_check.judge(ev(outside), granted)["result"] == "VIOLATION"
    escape = 'openat(AT_FDCWD</tmp>, "/data/../etc/hostname", O_RDONLY) = 3</etc/hostname>'
    assert contract_check.judge(ev(escape), granted)["result"] == "VIOLATION"  # normalised: /etc/hostname
    lookalike = READ.replace("/data/in.pdf", "/database/x")
    assert contract_check.judge(ev(lookalike), granted)["result"] == "VIOLATION"  # /database is not inside /data
    via_link = 'openat(AT_FDCWD</tmp>, "/data/link", O_RDONLY) = 3</etc/hostname>'
    assert contract_check.judge(ev(via_link), granted)["result"] == "VIOLATION"  # the real path is outside


def test_scoped_exec_grant_by_program():
    granted = contract(PROCESS_EXEC="/usr/bin/gs")
    assert contract_check.judge(ev(EXEC.replace("/bin/sh", "/usr/bin/gs")), granted)["result"] == "OK"
    assert contract_check.judge(ev(EXEC), granted)["result"] == "VIOLATION"


@pytest.mark.parametrize("capability, scope, line", [("FILE_READ", "invoice_documents", READ), ("FILE_WRITE", "scratch_tmp", WRITE),
                                                     ("NETWORK_CONNECT", "approved endpoints", CONNECT)])
def test_label_scope_is_unresolved(capability, scope, line):
    checked = contract_check.judge(ev(line), contract(**{capability: scope}))
    assert (checked["result"], checked["rule"]) == ("UNRESOLVED", "SCOPE_NOT_CHECKABLE")
    assert "future work" in checked["reason"] or "not a list" in checked["reason"]


def test_the_demo_policy_labels_make_file_events_unresolved_and_the_rest_a_violation():
    policy = json.loads(Path("demo_project/InvoiceHub/.asent/cavr/policy.json").read_text())
    fields, problem = _capabilities(policy, None, VOCABULARY)
    assert problem is None
    real = {"result": "OK", "allowed": fields["allowed"], "denied": fields["denied"], "vocabulary": VOCABULARY}
    assert contract_check.judge(ev(READ), real)["rule"] == "SCOPE_NOT_CHECKABLE"   # FILE_READ:invoice_documents
    assert contract_check.judge(ev(WRITE), real)["rule"] == "SCOPE_NOT_CHECKABLE"  # FILE_WRITE:scratch_tmp
    assert contract_check.judge(ev(CONNECT), real)["result"] == "VIOLATION"        # NETWORK_CONNECT:none
    assert contract_check.judge(ev(SECRET), real)["result"] == "VIOLATION"


def test_sensitive_read_needs_secret_read_even_with_file_read_star():
    checked = contract_check.judge(ev(SECRET), contract(FILE_READ="*"))
    assert checked["result"] == "VIOLATION" and checked["violations"][0]["capability"] == "SECRET_READ"
    stat = ev('newfstatat(AT_FDCWD</tmp>, "/tmp/home/.ssh/id_rsa", 0x7f, 0) = -1 ENOENT (No such file or directory)')
    assert contract_check.judge(stat, contract(FILE_READ="*"))["result"] == "VIOLATION"  # D4: a probe is an attempt


def test_credential_change_and_refused_syscall_always_violate():
    everything = contract(**{name: "*" for name in VOCABULARY})
    for line in ("setuid(0) = -1 EPERM (Operation not permitted)", "ptrace(PTRACE_TRACEME) = -1 EPERM (Operation not permitted)",
                 "unshare(CLONE_NEWUSER) = -1 EPERM (Operation not permitted)"):
        checked = contract_check.judge(ev(line), everything)
        assert checked["result"] == "VIOLATION" and "no capability can allow it" in checked["reason"]


def test_code_load_and_structure_need_no_capability():
    found = ev('openat(AT_FDCWD</tmp>, "/usr/local/lib/python3.12/json/__init__.py", O_RDONLY) = 3</usr/local/lib/python3.12/json/__init__.py>',
               'clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD, child_tidptr=0x7f) = 12', 'getuid() = 10001',
               'kill(12, SIGTERM) = 0', 'bind(3<socket:[1]>, {sa_family=AF_INET6, sin6_port=htons(0), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = 0')
    checked = contract_check.judge(found, contract())
    assert checked["result"] == "OK" and checked["judged"] == 0


def test_a_bind_that_is_not_a_loopback_probe_needs_network():
    found = ev('bind(3<socket:[1]>, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("0.0.0.0")}, 16) = 0')
    assert contract_check.judge(found, contract())["result"] == "VIOLATION"
    listen = ev("listen(3<socket:[1]>, 5) = -1 EPERM (Operation not permitted)")
    assert contract_check.judge(listen, contract())["result"] == "VIOLATION"


def test_unknown_event_type_is_unresolved():
    found = ev('inotify_add_watch(3, "/tmp", IN_ALL_EVENTS) = -1 EPERM (Operation not permitted)')
    assert contract_check.judge(found, contract())["rule"] == "EVENT_TYPE_UNKNOWN"
    invented = [{**ev(READ)[0], "type": "TELEPATHY"}]
    assert contract_check.judge(invented, contract(FILE_READ="*"))["rule"] == "EVENT_TYPE_UNKNOWN"


@pytest.mark.parametrize("bad", [None, "contract", {**contract(), "result": "UNRESOLVED"}, {**contract(), "allowed": "FILE_READ"},
                                 {**contract(), "denied": [{"capability": "TELEPATHY"}]},
                                 {**contract(FILE_READ="*"), "denied": contract()["denied"] + [{"capability": "FILE_READ"}]},
                                 {**contract(), "denied": [d for d in contract()["denied"] if d["capability"] != "SECRET_READ"]},
                                 {**contract(), "allowed": [{"capability": "FILE_READ", "scope": ""}]},
                                 {**contract(), "vocabulary": []}])
def test_unreadable_contract_is_unresolved(bad):
    checked = contract_check.judge(ev(READ), bad)
    assert (checked["result"], checked["rule"]) == ("UNRESOLVED", "CONTRACT_UNREADABLE")


def test_violation_wins_over_unknown():
    found = ev('inotify_add_watch(3, "/tmp", IN_ALL_EVENTS) = -1 EPERM (Operation not permitted)', CONNECT)
    checked = contract_check.judge(found, contract())
    assert checked["result"] == "VIOLATION" and checked["unresolved_count"] == 1


def test_incomplete_file_event_is_unresolved_but_an_incomplete_connect_still_violates():
    cut = ev('openat(AT_FDCWD</tmp>, "/tmp/home/.aw"..., O_RDONLY) = -1 ENOENT (No such file or directory)')
    assert cut[0]["complete"] is False
    unreadable_dirfd = ev('openat(3, "x", O_RDONLY) = -1 ENOENT (No such file or directory)')
    assert contract_check.judge(unreadable_dirfd, contract())["rule"] == "EVENT_INCOMPLETE"
    connect = ev('connect(3<socket:[1]>, {sa_family=AF_INET, sin_port=htons(443)}, 16) = -1 ENETUNREACH (Network is unreachable)')
    assert connect[0]["complete"] is False
    assert contract_check.judge(connect, contract())["result"] == "VIOLATION"


def test_required_not_observed_is_not_exercised():
    required = contract(FILE_READ="*")
    required["allowed"][0]["status"] = "REQUIRED"
    checked = contract_check.judge(ev('getuid() = 10001'), required)
    assert checked["result"] == "OK" and checked["not_exercised"] == ["FILE_READ"] and "not exercised" in checked["reason"]
    assert contract_check.judge(ev(READ), required)["not_exercised"] == []


# --- the install step's envelope (D3) ------------------------------------------------------------------------------------

def test_install_step_envelope_inside():
    found = ev(WRITE, 'mkdir("/site/lib/x", 0777) = 0', 'openat(AT_FDCWD</tmp>, "/etc/pip.conf", O_RDONLY) = -1 ENOENT (No such file or directory)',
               'bind(3<socket:[1]>, {sa_family=AF_INET6, sin6_port=htons(0), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = 0',
               'openat(AT_FDCWD</tmp>, "/site/lib/evil.pth", O_WRONLY|O_CREAT, 0644) = 3</site/lib/evil.pth>', pid=10)
    assert contract_check.judge(found, contract())["result"] == "OK"  # pip installing a .pth: it runs (and is judged) at import


@pytest.mark.parametrize("line", [
    'openat(AT_FDCWD</tmp>, "/tmp/home/x", O_WRONLY|O_CREAT, 0644) = 3</tmp/home/x>'.replace("/tmp/home/x", "/var/x"),
    CONNECT, SECRET, 'execve("/usr/bin/uname", ["uname", "-rs"], 0x7f /* 8 vars */) = 0',
    'execve("/usr/local/bin/lsb_release", ["lsb_release", "-a"], 0x7f /* 8 vars */) = -1 ENOENT (No such file or directory)',
    'setuid(0) = -1 EPERM (Operation not permitted)', 'inotify_add_watch(3, "/tmp", IN_ALL_EVENTS) = -1 EPERM (Operation not permitted)',
    'openat(3, "x", O_RDONLY) = -1 ENOENT (No such file or directory)',
    'newfstatat(AT_FDCWD</tmp>, "/etc/shadow", 0x7f, 0) = 0',
])
def test_install_step_outside_the_envelope_is_unresolved_never_a_pass(line):
    """A pip that ignored the User-Agent replacement would exec uname / lsb_release and stat /etc/shadow: UNRESOLVED."""
    checked = contract_check.judge(ev(line, pid=10), contract(**{name: "*" for name in VOCABULARY}))
    assert (checked["result"], checked["rule"]) == ("UNRESOLVED", "INSTALL_OUTSIDE_ENVELOPE")


def test_recorded_install_step_is_inside_the_envelope():
    found = sandbox_events.subtract_baseline(recorded("events-benign"), baseline())
    install = [e for e in found if e["step"] == "install"]
    assert install and contract_check.judge(install, contract())["result"] == "OK"


# --- recorded runs end to end ----------------------------------------------------------------------------------------------

def test_recorded_benign_run_is_within_a_deny_all_contract():
    found = sandbox_events.subtract_baseline(recorded("events-benign"), baseline())
    checked = contract_check.judge(found, contract())
    assert (checked["result"], checked["rule"], checked["judged"]) == ("OK", "EVENTS_WITHIN_CONTRACT", 0)


def test_recorded_probe_run_is_a_violation_with_every_kind_listed():
    found = sandbox_events.subtract_baseline(recorded("events-probe"), baseline())
    checked = contract_check.judge(found, contract())
    assert checked["result"] == "VIOLATION"
    kinds = {v["capability"] for v in checked["violations"]} | set(checked["used"])
    assert {"NETWORK_CONNECT", "SECRET_READ", "SENSITIVE_FILE_READ", "FILE_WRITE", "PERSISTENCE_WRITE", "PROCESS_EXEC",
            "CREDENTIAL_CHANGE", "REFUSED_SYSCALL"} <= kinds


def test_harness_events_are_not_excluded_by_name():
    found = ev(READ.replace("/data/in.pdf", "/etc/hostname"), pid=9)
    assert found[0]["step"] == "harness" and contract_check.judge(found, contract())["result"] == "VIOLATION"


def test_a_fault_is_unresolved_never_a_pass():
    assert contract_check.judge([object()], contract())["rule"] == "INTERNAL_ERROR"
