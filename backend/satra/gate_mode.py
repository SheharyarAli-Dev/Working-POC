"""SATRA in a gate run: contract, trusted tests and counterfactual from the base `.asent/` config.

`analyze_configured(context, outdir, emit)` has the return shape of `analyzer.analyze`.
`analyzer.analyze` calls it for every gate run (`context.gate`); the built-in demo scenarios keep
the legacy InvoiceHub path. Nothing here reads the candidate's SRS.md or policy.json: the authority
is the frozen base config, so the change under review cannot switch SATRA off or rewrite its tests.

Steps (every pytest run is in a container with no network; without Docker/Podman: INCONCLUSIVE):

0. Gate image (`project_image.prepare`): the SATRA runner plus exactly the CAVR-approved wheels of the
   BASE commit's dependencies.lock.json, built before any test runs (a cached image is reused only
   when ASENT_SATRA_REUSE_IMAGES=1, for local development).
   No lockfile, an entry CAVR does not permit, a clash with the runner, a failed build: INCONCLUSIVE.
   There is no fallback to the shared asent-sandbox:local image. Test-run limits come from the base
   `.asent/satra/sandbox.json` (default 40 s / 512m, cap 180 s / 2g; outside that: INCONCLUSIVE).
1. Contract `rule_id` must be an enabled threat-repository SATRA rule, else INCONCLUSIVE.
   Then `harness_guard.suspicious(base, head)`: a head change to conftest.py, pytest/_pytest, site hooks,
   .pth files, pytest settings, or non-test code importing pytest / writing sys.modules → INCONCLUSIVE
   ("test-harness tampering suspected") before any image is built or test runs.
2. Trusted tests (base `.asent/satra/trusted_tests/`) on the base and on the head commit.
3. The project's own tests (`tests/`, when present) on the head commit.
4. Counterfactual: base copy with the contract's RETURN_TRUE target; the trusted tests must fail on
   it (killed), otherwise they cannot vouch for the contract: INCONCLUSIVE.
5. Oracle check, only when `project_security_tests` is configured: that file must pass the base twice
   and kill the mutant (`test_validator.judge`); otherwise it is listed as not checked.

    trusted base not passing / execution unavailable   INCONCLUSIVE
    trusted head failing                               REJECT  (APPLICATION_REGRESSION)
    project tests failing                              REJECT  (exit 1) / INCONCLUSIVE (other)
    mutant not killed                                  INCONCLUSIVE
    project security test weakened                     REJECT
    otherwise                                          ACCEPT
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from backend.orchestrator.hashing import copy_tree, digest
from backend.satra import harness_guard, project_image, pytest_runner
from backend.satra.counterfactuals import mutate_return_true
from backend.satra.diff_localizer import localize
from backend.satra.static_adapters import scan
from backend.satra.test_validator import is_pass, judge, killed, preflight
from backend.threat_repo.repository import active

NO_ENGINE = "External code requires Docker/Podman; a gate run never executes repository code on the host"
BOUNDED = "Bounded to the configured contract, its trusted tests and one RETURN_TRUE counterfactual; other vulnerability families are not covered"


def analyze_configured(context, outdir, emit):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    config = getattr(context, "config", None)
    cfg = config.module("SATRA") if config is not None and config.valid else None
    document = config.documents.get("satra_contract") if cfg is not None else None
    if cfg is None or not cfg.enabled or document is None:
        return "INCONCLUSIVE", {"mode": "configured", "reason": "no usable SATRA section and contract in the base .asent/ config"}, ["SATRA configuration unavailable"]

    details = localize(context.baseline, context.path)
    details["mode"] = "configured"
    contract = {**document, "authority": "base .asent/" + cfg.contract}
    contract["digest"] = digest(contract)
    details["contract"] = contract
    rule = contract["rule_id"]
    if rule not in {r["id"] for r in active(context.knowledge, "satra_rules")}:
        return "INCONCLUSIVE", {**details, "reason": "The contract rule is not an enabled threat-repository SATRA rule", "missing_rules": [rule]}, \
            ["Required independent knowledge cannot be waived by disabling it"]
    for region in details["regions"]:
        emit("satra.region_localized", region)
    emit("satra.contract_created", contract)
    details["static"] = scan(context.path, cfg.source_dirs or ["."])
    tampering = harness_guard.suspicious(context.baseline, context.path)
    if tampering:
        details["harness_tampering"] = tampering
        why = harness_guard.REASON + ": " + ", ".join(item["path"] for item in tampering)
        return "INCONCLUSIVE", {**details, "reason": why, "executions": {}}, \
            [harness_guard.REASON + "; a human must review the listed head changes before any SATRA result is trusted"]

    caps = pytest_runner.availability()
    engine = next((name for name in ("docker", "podman") if caps.get(name, {}).get("available")), None)
    if engine is None:
        return "INCONCLUSIVE", {**details, "reason": NO_ENGINE, "executions": {}}, [NO_ENGINE]

    limits, problem = project_image.sandbox_limits(config)
    details["sandbox_limits"] = limits
    if limits is None:
        return "INCONCLUSIVE", {**details, "reason": problem, "executions": {}}, [problem]
    image = project_image.prepare(context.baseline, config, engine)
    details["sandbox_image"] = {key: image.get(key) for key in (
        "status", "reason", "image", "key", "reused", "runner", "lockfile_sha256", "requirements_sha256",
        "packages", "provided_by_runner", "decisions", "build_log_tail")}
    emit("satra.sandbox_image", {key: details["sandbox_image"][key] for key in ("status", "reason", "image", "reused")})
    if image["status"] != "READY":
        why = "No approved gate image for this project: " + image["reason"]
        return "INCONCLUSIVE", {**details, "reason": why, "executions": {}}, [why]

    root = Path(config.path)
    trusted_dir = root / cfg.trusted_tests
    ini = root / cfg.pytest_ini if cfg.pytest_ini else None
    executions = {}

    def execute(label, path, trusted=False, targets=None):
        result = pytest_runner.run_pytest(path, outdir / label, "all", trusted, trusted_tests_dir=trusted_dir if trusted else None,
                                          external=True, targets=targets, pytest_ini=ini if trusted else None,
                                          image=image["image"], timeout=limits["timeout_seconds"], memory=limits["memory"])
        executions[label] = result
        emit("satra.test_result", {"label": label, **{k: v for k, v in result.items() if k not in ("stdout", "stderr", "tests")}})
        return result

    baseline = execute("trusted_baseline", context.baseline, trusted=True)
    candidate = execute("trusted_candidate", context.path, trusted=True)
    has_tests = any(name.startswith("tests/") for name in context.manifest)
    ordinary = execute("ordinary_candidate", context.path, targets=["tests"]) if has_tests else None
    uncertainty = [BOUNDED]
    target = contract["counterfactual"]["target"]
    with tempfile.TemporaryDirectory(prefix="asent-satra-gate-") as scratch:
        scratch = Path(scratch)
        mutant = copy_tree(context.baseline, scratch / "mutant")
        made = mutate_return_true(mutant, target)
        independent = execute("trusted_counterfactual", mutant, trusted=True) if made else {"available": False}
        feasible = bool(made) and is_pass(baseline) and killed(independent)
        validation = None
        if cfg.project_security_tests:
            test_file = cfg.project_security_tests
            source = context.read(test_file)
            valid, reason = preflight(source)
            if valid:
                testbase = copy_tree(context.baseline, scratch / "test_baseline")
                testmutant = copy_tree(mutant, scratch / "test_mutant")
                for folder in (testbase, testmutant):
                    (folder / test_file).parent.mkdir(parents=True, exist_ok=True)
                    (folder / test_file).write_text(source)
                tb = execute("test_on_secure_baseline", testbase, targets=[test_file])
                tm = execute("test_on_counterfactual", testmutant, targets=[test_file])
                repeat = execute("test_baseline_repeat", testbase, targets=[test_file])
                validation = judge(tb, tm, repeat, feasible)
                if validation["diagnosis"] == "ORACLE_WEAKENED" and made:
                    original = execute("baseline_oracle_mutant", mutant, targets=[test_file])
                    if not killed(original):
                        validation["diagnosis"] = "PRE_EXISTING_TEST_GAP"
            else:
                validation = {"accepted": False, "diagnosis": "ORACLE_WEAKENED", "reason": reason}
        else:
            uncertainty.append("Oracle integrity not checked: no project security test configured (satra.project_security_tests)")
    details["oracle"] = {**(validation or {"accepted": None, "diagnosis": "NOT_CONFIGURED", "reason": "no project security test configured"}),
                         "valid_counterfactual": feasible, "mutant_operator": "RETURN_TRUE " + target, "counterfactual_applied": bool(made)}
    emit("satra.counterfactual_result", details["oracle"])
    details["executions"] = executions
    details["findings"] = []
    details["adaptive"] = {"available": False, "reason": "adaptive test generation is not used in gate runs", "validations": []}

    if not is_pass(baseline):
        status, why = "INCONCLUSIVE", "Trusted tests do not pass on the base commit, or execution is unavailable"
    elif not candidate.get("available") or candidate.get("exit_code") not in (0, 1):
        status, why = "INCONCLUSIVE", "Candidate test execution is incomplete"
    elif not is_pass(candidate):
        status, why = "REJECT", "Candidate violates the trusted contract tests"
        details["findings"].append({"family": "application security", "diagnosis": "APPLICATION_REGRESSION",
                                    "tests": [t["name"] for t in candidate.get("tests", []) if t["status"] in ("FAIL", "ERROR")]})
    elif ordinary is not None and not is_pass(ordinary):
        status = "REJECT" if ordinary.get("exit_code") == 1 else "INCONCLUSIVE"
        why = "Ordinary project tests do not provide a clean regression result"
    elif not made:
        status, why = "INCONCLUSIVE", "The contract's counterfactual target was not found: " + target
    elif not feasible:
        status, why = "INCONCLUSIVE", "The trusted tests do not detect the counterfactual, so they cannot vouch for the contract"
    elif validation is not None and validation["diagnosis"] == "INCONCLUSIVE":
        status, why = "INCONCLUSIVE", validation["reason"]
    elif validation is not None and not validation["accepted"]:
        status, why = "REJECT", validation["reason"]
        details["findings"].append({"family": "security test integrity", **validation})
    else:
        status, why = "ACCEPT", "Trusted contract tests pass on head and detect a valid counterfactual"
    if ordinary is None:
        uncertainty.append("No project tests/ directory; only the trusted contract tests ran")
    details["reason"] = why
    return status, details, uncertainty
