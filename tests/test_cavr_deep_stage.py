"""PR 2 of docs/cavr-m2-plan.md: a deep-analysis stage behind the fast gate's escalation, fail closed.

`verify_request(..., deep=analyzer)` calls the deep analyzer only for a package whose fast verdict is an
escalated UNRESOLVED (a reachable sink the contract does not allow). Its answer can only replace that verdict.
There is no real deep analyzer yet (the sandbox is Phase 2), so these tests use `FakeDeep`, which records
every call and answers what the test tells it to. Everything else is the real pipeline on the recorded pypdf
6.21.4 wheel, registry JSON and OSV answer (`test_cavr_support.World`).
"""
import pytest

from backend.cavr import deep_stage
from backend.cavr.pipeline import ESCALATION, analyzer_version, verify_request
from test_cavr_support import PIN_VERSION, UNGUARDED, World, synthetic_advisory

BUDGET = {"runs": 8, "run_seconds": 20, "package_seconds": 120}  # Q8


class FakeDeep:
    """A deep analyzer double: answers `answer` (a dict, None, or an exception to raise) and records each call."""

    def __init__(self, answer=None, version="fake-deep/1", image_id="sha256:" + "a" * 64, budget=BUDGET, elapsed=1.0):
        self.answer, self.version, self.image_id, self.budget, self.elapsed = answer, version, image_id, budget, elapsed
        self.calls = []

    def analyse(self, package):
        self.calls.append(package)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def answer(status, rule="DEEP_TEST", reason="answer of the fake deep analyzer", **evidence):
    return {"status": status, "rule": rule, "reason": reason, "evidence": evidence or {"runs": 1}}


class Clock:
    """A clock for `deep_stage.run_deep` that advances by the fake analyzer's `elapsed` seconds per call."""

    def __init__(self, deep):
        self.deep, self.now, self.reads = deep, 1000.0, 0

    def __call__(self):
        self.reads += 1
        if self.reads % 2 == 0:            # the second read of a call is after `analyse` returned
            self.now += self.deep.elapsed
        return self.now


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


def escalate(world):
    """The demo adapter plus a PdfReader call outside the guard: the fast gate's escalated UNRESOLVED."""
    adapter = world.project / "app" / "pdf_adapter.py"
    adapter.write_text(adapter.read_text() + UNGUARDED)


def run(world, deep, monkeypatch=None, **overrides):
    if monkeypatch is not None:
        monkeypatch.setattr(deep_stage, "CLOCK", Clock(deep))
    return world.verify(deep=deep, **overrides)


def outcome(verdict):
    return verdict["status"], verdict["stage"], verdict["rule"]


def package_outcome(verdict):
    """A VERIFIED request always reads `verdict / ALL_CHECKS_PASSED`; the deep stage and rule are on the package."""
    (package,) = verdict["packages"]
    return package["status"], package["stage"], package["rule"]


# --- deep=None keeps today's behaviour -------------------------------------------------------------------------

def test_deep_none_keeps_the_analyzer_version_and_the_escalated_verdict(world):
    assert analyzer_version() == analyzer_version(None, None)
    escalate(world)
    verdict = world.verify()
    assert outcome(verdict) == ("UNRESOLVED", "reachability", "SINK_REACHABLE")
    assert verdict["escalation"] == ESCALATION and verdict["packages"][0]["evidence"].get("deep") is None
    assert ";deep:" not in verdict["analyzer_version"]


# --- what a deep answer can do ---------------------------------------------------------------------------------

def test_deep_verified_lifts_only_the_escalation(world, monkeypatch):
    escalate(world)
    deep = FakeDeep(answer("VERIFIED", "DEEP_CLEAN", "every run complete, no event outside the contract"))
    verdict = run(world, deep, monkeypatch)
    assert outcome(verdict) == ("VERIFIED", "verdict", "ALL_CHECKS_PASSED"), verdict["reason"]
    assert package_outcome(verdict) == ("VERIFIED", "deep", "DEEP_CLEAN")
    assert verdict["escalated"] is True and verdict["escalation"] == "escalated: deep analysis ran"
    package = verdict["packages"][0]
    assert package["escalated"] is True and package["evidence"]["deep"]["status"] == "VERIFIED"
    assert package["evidence"]["reachability"]["result"] != "OK"  # the fast evidence is kept next to the deep one
    (call,) = deep.calls
    assert (call["name"], call["version"]) == ("pypdf", PIN_VERSION) and call["escalation"] == ESCALATION
    assert call["reachability"]["sinks"] and [n["sha256"] for n in call["tree"]["nodes"]]


def test_deep_rejected_rejects_with_the_deep_evidence(world, monkeypatch):
    escalate(world)
    deep = FakeDeep(answer("REJECTED", "DEEP_VIOLATION", "NETWORK_CONNECT outside the contract", event="connect 198.51.100.24:443"))
    verdict = run(world, deep, monkeypatch)
    assert outcome(verdict) == ("REJECTED", "deep", "DEEP_VIOLATION")
    assert verdict["packages"][0]["evidence"]["deep"]["evidence"] == {"event": "connect 198.51.100.24:443"}


def test_deep_unresolved_stays_unresolved(world, monkeypatch):
    escalate(world)
    verdict = run(world, FakeDeep(answer("UNRESOLVED", "DEEP_TRACE_INCOMPLETE", "trace truncated")), monkeypatch)
    assert outcome(verdict) == ("UNRESOLVED", "deep", "DEEP_TRACE_INCOMPLETE")


# --- fail closed -----------------------------------------------------------------------------------------------

def test_deep_analyzer_that_raises_is_unresolved_internal_error(world, monkeypatch):
    escalate(world)
    verdict = run(world, FakeDeep(RuntimeError("container vanished")), monkeypatch)
    assert outcome(verdict) == ("UNRESOLVED", "deep", "INTERNAL_ERROR") and "container vanished" in verdict["reason"]


@pytest.mark.parametrize("bad,rule", [(None, "DEEP_NO_RESULT"), ("VERIFIED", "DEEP_RESULT_INVALID"),
                                      ({"status": "PASS", "rule": "X", "reason": "y"}, "DEEP_RESULT_INVALID"),
                                      ({"status": "VERIFIED"}, "DEEP_RESULT_INVALID"),
                                      ({"status": "VERIFIED", "rule": "", "reason": "y"}, "DEEP_RESULT_INVALID"),
                                      ({"status": "VERIFIED", "rule": "X", "reason": "y", "evidence": "not a dict"}, "DEEP_RESULT_INVALID")])
def test_no_or_malformed_deep_result_is_unresolved(world, monkeypatch, bad, rule):
    escalate(world)
    verdict = run(world, FakeDeep(bad), monkeypatch)
    assert outcome(verdict) == ("UNRESOLVED", "deep", rule)


class RaisingIdentity(FakeDeep):
    @property
    def image_id(self):
        raise RuntimeError("image lookup failed")

    @image_id.setter
    def image_id(self, value):
        pass


@pytest.mark.parametrize("deep", [RaisingIdentity(answer("VERIFIED")),
                                  FakeDeep(answer("VERIFIED"), budget={"package_seconds": 120, 1: "unsortable"})])
def test_an_identity_that_cannot_be_read_is_unresolved_never_an_exception(world, monkeypatch, deep):
    escalate(world)
    verdict = run(world, deep, monkeypatch)
    assert outcome(verdict) == ("UNRESOLVED", "deep", "DEEP_IDENTITY_UNKNOWN") and deep.calls == []
    assert verdict["analyzer_version"].endswith(";deep:unknown")


@pytest.mark.parametrize("field,value", [("version", ""), ("image_id", None), ("budget", {}),
                                         ("budget", {"runs": 8, "run_seconds": 20}), ("budget", {"package_seconds": -1})])
def test_deep_analyzer_without_a_full_identity_is_unresolved_and_never_called(world, monkeypatch, field, value):
    escalate(world)
    deep = FakeDeep(answer("VERIFIED"))
    setattr(deep, field, value)
    verdict = run(world, deep, monkeypatch)
    assert outcome(verdict) == ("UNRESOLVED", "deep", "DEEP_IDENTITY_UNKNOWN") and deep.calls == []


def test_going_over_the_time_budget_is_unresolved_even_when_the_answer_is_verified(world, monkeypatch):
    escalate(world)
    deep = FakeDeep(answer("VERIFIED", "DEEP_CLEAN"), elapsed=BUDGET["package_seconds"] + 0.5)
    verdict = run(world, deep, monkeypatch)
    assert outcome(verdict) == ("UNRESOLVED", "deep", "DEEP_BUDGET_EXCEEDED")
    assert "120" in verdict["reason"] and len(deep.calls) == 1


def test_a_violation_found_over_the_budget_is_still_rejected(world, monkeypatch):
    escalate(world)
    deep = FakeDeep(answer("REJECTED", "DEEP_VIOLATION"), elapsed=BUDGET["package_seconds"] + 0.5)
    assert outcome(run(world, deep, monkeypatch)) == ("REJECTED", "deep", "DEEP_VIOLATION")


def test_exactly_on_the_budget_is_within_it(world, monkeypatch):
    escalate(world)
    deep = FakeDeep(answer("VERIFIED", "DEEP_CLEAN"), elapsed=BUDGET["package_seconds"])
    assert package_outcome(run(world, deep, monkeypatch)) == ("VERIFIED", "deep", "DEEP_CLEAN")


# --- never called for a verdict that is not an escalated UNRESOLVED --------------------------------------------

def test_not_called_for_a_fast_verified_package(world, monkeypatch):
    deep = FakeDeep(answer("REJECTED"))
    verdict = run(world, deep, monkeypatch)
    assert outcome(verdict) == ("VERIFIED", "verdict", "ALL_CHECKS_PASSED") and deep.calls == []


def test_not_called_for_a_rejected_package(world, monkeypatch):
    world.advisories("pypdf", PIN_VERSION, [synthetic_advisory("SYNTH-DEEP-1", "pypdf", introduced="6.0", fixed="6.22.0")])
    escalate(world)
    deep = FakeDeep(answer("VERIFIED"))
    assert outcome(run(world, deep, monkeypatch))[0] == "REJECTED" and deep.calls == []


def test_not_called_for_a_blocked_request(world, monkeypatch):
    deep = FakeDeep(answer("VERIFIED"))
    verdict = run(world, deep, monkeypatch, request="pip install left-pad==1.0")
    assert verdict["status"] == "BLOCK" and deep.calls == []


def test_deep_verified_never_lifts_missing_advisories(world, monkeypatch, tmp_path):
    escalate(world)
    deep = FakeDeep(answer("VERIFIED"))
    verdict = run(world, deep, monkeypatch, advisory_cache_dir=tmp_path / "no-osv-answers")
    assert outcome(verdict) == ("UNRESOLVED", "advisories", "ADVISORIES_UNAVAILABLE") and deep.calls == []


def test_deep_verified_never_lifts_a_request_hash_mismatch(world, monkeypatch):
    """UNRESOLVED caused by a hash: the request pins a --hash the verified wheel does not have."""
    escalate(world)
    deep = FakeDeep(answer("VERIFIED"))
    world.write("reqs.txt", f"pypdf=={PIN_VERSION} --hash=sha256:{'0' * 64}\n")   # hashes are given in a requirements file
    verdict = run(world, deep, monkeypatch, request="pip install -r reqs.txt")
    assert outcome(verdict) == ("UNRESOLVED", "artifact", "REQUEST_HASH_MISMATCH") and deep.calls == []


def test_deep_verified_never_lifts_a_registry_hash_mismatch(world, monkeypatch):
    """REJECTED caused by a hash: the downloaded bytes differ from the registry digest."""
    escalate(world)
    wheel_url = next(url for url in world.index.routes if url.endswith(f"pypdf-{PIN_VERSION}-py3-none-any.whl"))
    body = bytearray(world.index.routes[wheel_url]); body[100] ^= 1
    world.index.routes[wheel_url] = bytes(body)
    deep = FakeDeep(answer("VERIFIED"))
    verdict = run(world, deep, monkeypatch)
    assert verdict["status"] == "REJECTED" and verdict["rule"] == "HASH_MISMATCH" and deep.calls == []


def test_not_called_for_an_unknown_contract(world, monkeypatch):
    world.policy["allowed_scopes"] = ["NOT_A_CAPABILITY:x"]
    escalate(world)
    deep = FakeDeep(answer("VERIFIED"))
    verdict = run(world, deep, monkeypatch)
    assert outcome(verdict) == ("UNRESOLVED", "contract", "CAPABILITY_POLICY_INVALID") and deep.calls == []


# --- cache -----------------------------------------------------------------------------------------------------

def test_a_cached_deep_verified_still_rechecks_osv(world, monkeypatch):
    escalate(world)
    deep = FakeDeep(answer("VERIFIED", "DEEP_CLEAN"))
    first = run(world, deep, monkeypatch)
    again = run(world, deep, monkeypatch)
    assert first["status"] == again["status"] == "VERIFIED" and again["cache_hit"] is True and len(deep.calls) == 1
    assert again["packages"][0]["evidence"]["deep"]["rule"] == "DEEP_CLEAN"
    world.advisories("pypdf", PIN_VERSION, [synthetic_advisory("SYNTH-DEEP-2", "pypdf", introduced="6.0", fixed="6.22.0")])
    later = run(world, deep, monkeypatch)
    assert outcome(later) == ("REJECTED", "advisories", "KNOWN_VULNERABILITY") and len(deep.calls) == 1


def test_changing_the_image_id_is_a_cache_miss(world, monkeypatch):
    escalate(world)
    first_deep = FakeDeep(answer("VERIFIED", "DEEP_CLEAN"))
    first = run(world, first_deep, monkeypatch)
    assert first["packages"][0]["cache"]["stored"] is True
    other = FakeDeep(answer("VERIFIED", "DEEP_CLEAN"), image_id="sha256:" + "b" * 64)
    second = run(world, other, monkeypatch)
    assert first["analyzer_version"] != second["analyzer_version"]
    assert second["cache_hit"] is False and second["packages"][0]["cache"]["lookup"] == "MISS" and len(other.calls) == 1


@pytest.mark.parametrize("change", [{"version": "fake-deep/2"}, {"budget": {**BUDGET, "runs": 4}}])
def test_changing_the_deep_version_or_budget_changes_the_key(world, monkeypatch, change):
    escalate(world)
    first = run(world, FakeDeep(answer("VERIFIED")), monkeypatch)
    assert first["packages"][0]["cache"]["stored"] is True
    changed = FakeDeep(answer("VERIFIED"))
    for name, value in change.items():
        setattr(changed, name, value)
    verdict = run(world, changed, monkeypatch)
    assert verdict["analyzer_version"] != first["analyzer_version"]
    assert verdict["cache_hit"] is False and len(changed.calls) == 1


def test_a_cached_deep_verified_is_never_served_without_that_deep_analyzer(world, monkeypatch):
    """After a deep VERIFIED is stored: deep=None and an identity-less analyzer both get the escalated UNRESOLVED."""
    escalate(world)
    stored = run(world, FakeDeep(answer("VERIFIED", "DEEP_CLEAN")), monkeypatch)
    assert stored["packages"][0]["cache"]["stored"] is True
    plain = world.verify()
    assert outcome(plain) == ("UNRESOLVED", "reachability", "SINK_REACHABLE") and plain["cache_hit"] is False
    nameless = FakeDeep(answer("VERIFIED"), version="")
    verdict = run(world, nameless, monkeypatch)
    assert outcome(verdict) == ("UNRESOLVED", "deep", "DEEP_IDENTITY_UNKNOWN") and verdict["cache_hit"] is False


def test_unresolved_deep_answers_are_not_cached(world, monkeypatch):
    escalate(world)
    deep = FakeDeep(answer("UNRESOLVED", "DEEP_TRACE_INCOMPLETE"))
    run(world, deep, monkeypatch)
    run(world, deep, monkeypatch)
    assert len(deep.calls) == 2 and world.cache_rows() == []
