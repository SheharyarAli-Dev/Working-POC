"""strace lines -> runtime events (`runtime_monitor.normalize`), and the correlation that is built on them.

The trace lines below were recorded on 2026-10-11 from `sandbox.run_counterfactual` running
`scenarios/cavr_controlled/invoice_pdf_lab.py` in the mode PINNED_INERT_LAB_STRACE (strace 6.19,
Python 3.12.15, counterfactual run). Only the temporary directory name is shortened.
"""
import pytest

from backend.cavr.policy import verify_runtime
from backend.cavr.runtime_monitor import normalize
from backend.threat_repo.source_sink_rules import correlate

MARKER = "CAVR_FAKE_SECRET_NOT_A_CREDENTIAL"
RECORDED = '''14804 openat(AT_FDCWD, "/tmp/asent-cavr-x/canary.txt", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 4
14804 newfstatat(AT_FDCWD, "canary.txt", {st_mode=S_IFREG|0644, st_size=33, ...}, AT_SYMLINK_NOFOLLOW) = 0
14804 openat(AT_FDCWD, "canary.txt", O_RDONLY|O_CLOEXEC) = 4
14804 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 4
14804 connect(4, {sa_family=AF_INET, sin_port=htons(18765), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 EINPROGRESS (Operation now in progress)
14805 accept4(3, {sa_family=AF_INET, sin_port=htons(49648), sin_addr=inet_addr("127.0.0.1")}, [16], SOCK_CLOEXEC) = 5
14804 getsockopt(4, SOL_SOCKET, SO_ERROR <unfinished ...>
14804 <... getsockopt resumed>, [0], [4]) = 0
'''
CONNECT = '7 connect(4, {sa_family=AF_INET, sin_port=htons(18765), sin_addr=inet_addr("127.0.0.1")}, 16) = '
DENIED = {"denied": ["SECRET_ACCESS", "NETWORK_CONNECT", "PROCESS_CREATE", "PERSISTENCE_WRITE", "EXECUTE_BINARY"]}


def kinds(trace):
    return [(event["type"], event["resource"]) for event in normalize(trace)]


def test_recorded_lab_trace_has_the_secret_read_and_then_the_connection():
    """CI defect: the connect of `socket.create_connection(..., timeout=1)` returns -1 EINPROGRESS and was dropped."""
    events = normalize(RECORDED)
    assert [(e["type"], e["resource"]) for e in events] == [
        ("FILE_WRITE", "/tmp/asent-cavr-x/canary.txt"), ("SECRET_ACCESS", "canary.txt"), ("NETWORK_CONNECT", "127.0.0.1:18765")]
    assert events[-1]["pid"] == "14804" and "EINPROGRESS" in events[-1]["raw"] and events[-1]["source"] == "strace"


def test_recorded_lab_trace_gives_the_confirmed_correlation_and_the_network_violation():
    events = normalize(RECORDED)
    confirmed = [hit for hit in correlate(None, events, [MARKER], DENIED) if hit["causal_confirmed"]]
    assert [(hit["source_event"]["type"], hit["sink_event"]["type"], hit["causal_witness"]) for hit in confirmed] == [
        ("SECRET_ACCESS", "NETWORK_CONNECT", "exact fake marker received by local harness")]
    assert {v["capability"] for v in verify_runtime(DENIED, events, [MARKER])} == {"SECRET_ACCESS", "NETWORK_CONNECT", "CANARY_FLOW"}


def test_the_connection_alone_is_not_a_confirmed_flow():
    events = normalize(RECORDED)
    assert [hit["causal_confirmed"] for hit in correlate(None, events, [], DENIED)] == [False]          # nothing received
    assert [hit["causal_confirmed"] for hit in correlate(None, events, ["other"], DENIED)] == [False]   # not the marker
    without_read = [e for e in events if e["type"] != "SECRET_ACCESS"]
    assert correlate(None, without_read, [MARKER], DENIED) == []                                         # no source event
    assert correlate(None, list(reversed(events)), [MARKER], DENIED) == []                               # connection before the read


@pytest.mark.parametrize("result, expected", [
    ("0", [("NETWORK_CONNECT", "127.0.0.1:18765")]),                                          # blocking socket
    ("-1 EINPROGRESS (Operation now in progress)", [("NETWORK_CONNECT", "127.0.0.1:18765")]),  # socket with a timeout
    ("-1 ECONNREFUSED (Connection refused)", []),
    ("-1 ENETUNREACH (Network is unreachable)", []),
    ("-1 EACCES (Permission denied)", []),
])
def test_connect_results(result, expected):
    assert kinds(CONNECT + result) == expected


def test_einprogress_is_an_exception_for_connect_only():
    assert kinds('7 openat(AT_FDCWD, "canary.txt", O_RDONLY) = -1 EINPROGRESS (Operation now in progress)') == []
    assert kinds('7 openat(AT_FDCWD, "canary.txt", O_RDONLY) = -1 ENOENT (No such file or directory)') == []
    assert kinds('7 execve("/bin/sh", ["sh"], 0x7ffd /* 3 vars */) = -1 ENOENT (No such file or directory)') == []
    # A local socket (name service lookup) is not a network connection, whatever it returns.
    assert kinds('7 connect(3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 EINPROGRESS (Operation now in progress)') == []
    assert kinds('7 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = -1 EINPROGRESS '
                 '(Operation now in progress)') == [("NETWORK_CONNECT", "unresolved socket")]
