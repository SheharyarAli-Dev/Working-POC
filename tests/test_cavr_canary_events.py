"""PR 11 of docs/cavr-m2-plan.md: canary checks in the event normaliser and the contract check.

The recorded traces (`tests/test_cavr_data/traces/spec-*.txt`, made by `record_events.py` from real `run_spec` runs,
with the run's canaries in the .json) show the real printing of write, writev, sendto, sendmsg and connect. Small
hand-made lines, in exactly that printing (measured 2026-11-23), cover the cases a recording cannot show.
"""
import base64
import json
from pathlib import Path

import pytest

from backend.cavr import contract_check, sandbox_events
from backend.cavr.sandbox_trace import check_trace
from tests.test_cavr_contract_check import PROCESSES, STEPS, contract

TRACES = Path(__file__).parent / "test_cavr_data" / "traces"
VALUE = "5d41402abc4b2a76b9719d911017c592"
CANARIES = [{"id": "file:aws-secret-key", "kind": "file", "where": "/tmp/home/.aws/credentials", "value": VALUE},
            {"id": "env:GITHUB_TOKEN", "kind": "env", "where": "GITHUB_TOKEN", "value": "ghp_00112233445566778899aabbccddeeff0011"}]
DENY = contract()
ALLOW_ALL = contract(**{name: "*" for name in ("FILE_READ", "SECRET_READ", "SENSITIVE_FILE_READ", "FILE_WRITE",
                                               "PERSISTENCE_WRITE", "PROCESS_EXEC", "NETWORK_CONNECT", "NATIVE_EXEC",
                                               "DYNAMIC_DOWNLOAD", "DYNAMIC_EXECUTION")})


def ev(*lines, pid=11, canaries=CANARIES):
    text = "".join(f"{pid} {line}\n" for line in lines)
    return sandbox_events.normalise(text, PROCESSES, {"install": [10], "imports": [11]}, STEPS, canaries=canaries)["events"]


def of(events, kind):
    return [event for event in events if event["type"] == kind]


SENDTO = ('sendto(3<socket:[2221122]>, "k={v}", 34, 0, {{sa_family=AF_INET, sin_port=htons(53), '
          'sin_addr=inet_addr("198.51.100.24")}}, 16) = -1 ENETUNREACH (Network is unreachable)')
WRITE = 'write(1<pipe:[2215843]>, "x{v}y\\n", 35) = 35'
WRITEV = ('writev(1<pipe:[2215843]>, [{{iov_base="a", iov_len=1}}, {{iov_base="{v}", iov_len=32}}, '
          '{{iov_base="\\n", iov_len=1}}], 3) = 34')
SENDMSG = ('sendmsg(3<socket:[2221122]>, {{msg_name={{sa_family=AF_INET, sin_port=htons(53), '
           'sin_addr=inet_addr("198.51.100.24")}}, msg_namelen=16, msg_iov=[{{iov_base="m={v}", iov_len=34}}], '
           'msg_iovlen=1, msg_controllen=0, msg_flags=0}}, 0) = -1 EPERM (Operation not permitted)')
UNIX = 'connect(4<socket:[2222092]>, {{sa_family=AF_UNIX, sun_path="/tmp/{v}.sock"}}, 39) = -1 ENOENT (No such file or directory)'
ABSTRACT = 'connect(4<socket:[2222092]>, {{sa_family=AF_UNIX, sun_path=@"{v}"}}, 29) = -1 ECONNREFUSED (Connection refused)'


# --- found -----------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("line", [SENDTO, WRITE, WRITEV, SENDMSG, UNIX, ABSTRACT])
def test_a_canary_in_a_write_send_or_connect_is_an_exfiltration_attempt(line):
    events = ev(line.format(v=VALUE))
    found = of(events, "CANARY_EXFIL_ATTEMPT")
    assert len(found) == 1 and found[0]["canaries"] == ["file:aws-secret-key"] and found[0]["step"] == "imports"
    assert found[0]["canary_forms"] == ["verbatim"]
    assert of(events, "CANARY_UNCHECKED") == []


def test_the_event_of_the_call_itself_stays():
    events = ev(SENDTO.format(v=VALUE))
    assert [e["type"] for e in events] == ["NETWORK_CONNECT", "CANARY_EXFIL_ATTEMPT"]
    assert events[1]["syscall"] == "sendto" and events[1]["errno"] == "ENETUNREACH"


def test_a_base64_or_hex_canary_is_found():
    b64 = base64.b64encode(b"token=" + VALUE.encode()).decode()
    found = of(ev(WRITE.format(v=b64), WRITE.format(v=VALUE.encode().hex())), "CANARY_EXFIL_ATTEMPT")
    assert [f["canary_forms"] for f in found] == [["base64"], ["hex"]]


def test_a_canary_split_over_two_iov_parts_is_found():
    line = ('writev(1<pipe:[1]>, [{iov_base="' + VALUE[:10] + '", iov_len=10}, {iov_base="' + VALUE[10:]
            + '", iov_len=22}], 2) = 32')
    assert of(ev(line), "CANARY_EXFIL_ATTEMPT")[0]["canaries"] == ["file:aws-secret-key"]


def test_an_env_canary_is_found_too():
    found = of(ev(WRITE.format(v=CANARIES[1]["value"])), "CANARY_EXFIL_ATTEMPT")
    assert found[0]["canaries"] == ["env:GITHUB_TOKEN"]


def test_escaped_bytes_are_decoded_before_matching():
    # \65 is "5": an escaped character of the canary is still the canary.
    escaped = VALUE.replace("5", "\\65", 1)
    assert of(ev(WRITE.format(v=escaped)), "CANARY_EXFIL_ATTEMPT")
    # Digits of an escape are not payload: the printed text `\05d414...` contains the canary's characters, but the
    # bytes are 0x05 "d414...", which do not.
    printed = "\\05" + VALUE[1:]
    assert VALUE in printed and not of(ev(WRITE.format(v=printed)), "CANARY_EXFIL_ATTEMPT")


@pytest.mark.parametrize("line", [WRITE.format(v="nothing here"), SENDTO.format(v="k=v"),
                                  'connect(3<socket:[1]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("198.51.100.24")}, 16) = -1 ENETUNREACH (Network is unreachable)'])
def test_no_canary_no_event(line):
    events = ev(line)
    assert not of(events, "CANARY_EXFIL_ATTEMPT") and not of(events, "CANARY_UNCHECKED")
    assert all(e["canary_checked"] for e in events)


def test_without_canaries_nothing_is_checked():
    events = ev(WRITE.format(v=VALUE), canaries=None)
    assert [e["type"] for e in events] == ["NO_EFFECT"] and not events[0].get("canary_checked")


# --- not checkable -----------------------------------------------------------------------------------------------------

def test_a_payload_strace_cut_is_unchecked():
    events = ev('write(1<pipe:[1]>, "BBBB"..., 70001) = 70001')
    found = of(events, "CANARY_UNCHECKED")
    assert len(found) == 1 and "cut" in found[0]["problem"] and found[0]["path"] is None


def test_a_cut_payload_with_a_canary_in_its_printed_part_is_still_an_exfiltration():
    events = ev(f'write(1<pipe:[1]>, "{VALUE}BBBB"..., 70001) = 70001')
    assert of(events, "CANARY_EXFIL_ATTEMPT") and of(events, "CANARY_UNCHECKED")


def test_an_array_strace_shortened_is_unchecked():
    line = 'writev(1<pipe:[1]>, [{iov_base="a", iov_len=1}, ...], 2000) = 2000'
    assert of(ev(line), "CANARY_UNCHECKED")


def test_a_buffer_printed_as_an_address_is_unchecked():
    assert of(ev("write(3</tmp/x>, 0x7ffc1234, 10) = -1 EFAULT (Bad address)"), "CANARY_UNCHECKED")


@pytest.mark.parametrize("line", ["writev(1<pipe:[1]>, 0x7ffd5a0c, 2) = -1 EFAULT (Bad address)",
                                  "sendmsg(3<socket:[1]>, {msg_name=NULL, msg_namelen=0, msg_iov=0x7ffd5a0c, msg_iovlen=1, "
                                  "msg_controllen=0, msg_flags=0}, 0) = -1 EFAULT (Bad address)"])
def test_an_iov_printed_as_an_address_is_unchecked(line):
    # Review of PRs 10-11 (MINOR 7)
    assert of(ev(line), "CANARY_UNCHECKED")


def test_a_write_to_a_file_keeps_the_files_path():
    found = of(ev('write(4</tmp/pip-target-x/lib/python/demo/big.py>, "aa"..., 70000) = 65536', pid=10),
               "CANARY_UNCHECKED")
    assert found[0]["path"] == "/tmp/pip-target-x/lib/python/demo/big.py" and found[0]["step"] == "install"


# --- write-family events without canaries (they appear only in spec runs) -------------------------------------------

def test_a_write_to_a_file_or_pipe_has_no_effect_and_to_a_socket_is_a_network_send():
    pipe, file, sock = ev('write(1<pipe:[1]>, "x", 1) = 1', 'pwrite64(4</tmp/a>, "x", 1, 0) = 1',
                          'write(3<socket:[9]>, "GET / HTTP/1.1\\r\\n", 16) = -1 EPIPE (Broken pipe)', canaries=None)
    assert (pipe["type"], file["type"], sock["type"]) == ("NO_EFFECT", "NO_EFFECT", "NETWORK_CONNECT")
    assert file["path"] == "/tmp/a"


# --- judged --------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("the_contract", [DENY, ALLOW_ALL])
def test_an_exfiltration_attempt_is_always_a_violation(the_contract):
    judged = contract_check.judge(ev(SENDTO.format(v=VALUE)), the_contract)
    assert judged["result"] == "VIOLATION"
    assert any(v["capability"] == "CANARY_EXFIL" for v in judged["violations"])


def test_an_exfiltration_attempt_in_the_install_step_is_a_violation_not_outside_the_envelope():
    judged = contract_check.judge(ev(WRITE.format(v=VALUE), pid=10), ALLOW_ALL)
    assert judged["result"] == "VIOLATION" and judged["violations"][0]["capability"] == "CANARY_EXFIL"


def test_an_exfiltration_attempt_that_failed_under_network_none_is_still_a_violation():
    events = ev(SENDTO.format(v=VALUE))
    assert of(events, "CANARY_EXFIL_ATTEMPT")[0]["ok"] is False
    assert contract_check.judge(events, ALLOW_ALL)["result"] == "VIOLATION"


def test_an_unchecked_payload_in_the_imports_step_is_unresolved():
    judged = contract_check.judge(ev('write(1<pipe:[1]>, "BBBB"..., 70001) = 70001'), ALLOW_ALL)
    assert judged["result"] == "UNRESOLVED" and judged["rule"] == "CANARY_CHECK_INCOMPLETE"


def test_a_cut_pip_write_to_the_install_target_is_inside_pips_envelope():
    lines = ['write(4</tmp/pip-target-x/lib/python/demo/big.py>, "aa"..., 70000) = 65536',
             'write(4</site/lib/demo/big.py>, "aa"..., 70000) = 65536']
    assert contract_check.judge(ev(*lines, pid=10), ALLOW_ALL)["result"] == "OK"


@pytest.mark.parametrize("line", ['write(1<pipe:[1]>, "aa"..., 70000) = 65536',
                                  'write(4</etc/x>, "aa"..., 70000) = 65536'])
def test_a_cut_pip_write_elsewhere_is_unresolved(line):
    judged = contract_check.judge(ev(line, pid=10), ALLOW_ALL)
    assert judged["result"] == "UNRESOLVED" and judged["rule"] == "CANARY_CHECK_INCOMPLETE"


def test_the_canary_types_are_judged_types():
    assert {"CANARY_EXFIL_ATTEMPT", "CANARY_UNCHECKED"} <= set(sandbox_events.JUDGED)
    assert contract_check.capability_of({"type": "CANARY_EXFIL_ATTEMPT"}) == ("never", ["CANARY_EXFIL"])


# --- recorded real runs ----------------------------------------------------------------------------------------------

def recorded(stem):
    meta = json.loads((TRACES / f"{stem}.json").read_text())
    trace = (TRACES / f"{stem}.txt").read_text()
    checked = check_trace(trace.encode(), meta["nonce"], [step["name"] for step in meta["steps"]])
    assert checked["complete"], checked["reason"]
    found = sandbox_events.normalise(trace, checked["processes"], checked["steps"], meta["steps"],
                                     canaries=meta["spec"]["canaries"])
    return found["events"], meta


def test_recorded_leaks_are_each_found_with_the_canary_that_leaked():
    events, meta = recorded("spec-canary")
    found = {(e["syscall"], tuple(e["canaries"]), tuple(e["canary_forms"])) for e in of(events, "CANARY_EXFIL_ATTEMPT")}
    assert found == {("sendto", ("file:aws-secret-key",), ("verbatim",)),
                     ("write", ("env:GITHUB_TOKEN",), ("base64",)),
                     ("writev", ("file:netrc-password",), ("verbatim",)),
                     ("connect", ("file:env-api-key",), ("verbatim",))}
    assert all(e["step"] == "imports" for e in of(events, "CANARY_EXFIL_ATTEMPT"))


def test_the_recorded_cut_write_is_unchecked_and_nothing_of_pip_is():
    events, _ = recorded("spec-canary")
    unchecked = of(events, "CANARY_UNCHECKED")
    assert [(e["step"], e["syscall"]) for e in unchecked] == [("imports", "write")]


def test_the_recorded_clean_run_has_no_canary_event_and_checked_every_write():
    events, meta = recorded("spec-clean")
    assert not of(events, "CANARY_EXFIL_ATTEMPT") and not of(events, "CANARY_UNCHECKED")
    writes = [e for e in events if e["syscall"] in ("write", "writev")]
    assert writes and all(e["canary_checked"] for e in writes)
    assert contract_check.judge(events, contract())["result"] == "OK"


def test_the_recorded_leak_run_is_a_violation_under_any_contract():
    events, _ = recorded("spec-canary")
    for the_contract in (DENY, ALLOW_ALL):
        judged = contract_check.judge(events, the_contract)
        assert judged["result"] == "VIOLATION"
        assert any(v["capability"] == "CANARY_EXFIL" for v in judged["violations"])
