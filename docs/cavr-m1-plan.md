# CAVR M1 plan: one real path for C1–C4

Status: approved by Maryam on 2026-10-10 with the changes marked **[approved change]** below.
Progress is tracked in the checklist at the end; update it as each commit lands.

## Working rules (apply to every step)

- Claude never runs `git commit` or `git push`. Each step stops with the diff in the working tree;
  Maryam reviews and commits it herself.
- One commit at a time. Do not start the next commit until asked.
- Edit only `backend/cavr/`, `tests/test_cavr_*`, `frontend/src/components/cavr/`,
  `docs/report-notes/`, plus the two approved exceptions: this file, and
  `test_controlled_dormant_execution` in `tests/test_modules.py`.
- Do not edit `backend/orchestrator/context_service.py` (Ali's area). Work around it inside `backend/cavr/`.
- No fixture-faked results. Hashes come from real files. Anything unknown is UNRESOLVED.
- Every feature has pytest tests, including failure and edge cases.
- Tests are offline by default. Live PyPI/OSV tests run only with `CAVR_LIVE=1`.
- `.venv/bin/python -m pytest -q` before each commit. Baseline on 2026-10-10 before any change:
  64 passed, 7 failed. The 7 failures are in `tests/test_api_replay.py` (1) and
  `tests/test_integration.py` (6), are orchestrator verdict mismatches (`REVIEW` vs `ACCEPT`/`BLOCK`),
  and are outside this branch's scope. A step is clean when it adds no new failures.

## Context

CAVR currently has two unrelated code paths that produce verdicts:

- `backend/cavr/analyzer.py` (orchestrator): mostly real computation, but only for packages already
  present as local files named in `dependencies.lock.json`. It never downloads anything, and its
  capability contract is a single hardcoded PDF rule.
- `backend/cavr/api.py` (dashboard tab): a 13-phase animation over `fixtures/scenarios.py`. The
  "artifact hash" is the SHA-256 of a source string, the transitive tree is `if name == ...`,
  the OSV check marks every version affected whenever a range contains `<=`, the requirement gate
  fails open, and re-verification/reconstruction return constants.

CLAUDE.md's M1 goals need one path that takes a real `pip install X==Y` or requirements.txt edit,
gates it, verifies the real PyPI file, and returns VERIFIED / REJECTED / UNRESOLVED with evidence.
The plan builds that path as new small modules in `backend/cavr/`, then points both entry points at it.

## Design

One function, `backend/cavr/pipeline.py::verify_request(request, project_dir, policy, store)`, runs
in this order. Every stage returns evidence; anything unknown becomes UNRESOLVED.

1. C1 capture -> structured request
2. C2 requirement gate -> BLOCK stops here, before any download
3. C3a download the real file, SHA-256 the bytes, compare with the registry digest
4. C3b transitive tree from each wheel's real `Requires-Dist`, then the subtree digest
5. C4 capability contract from the project's imports and call sites, then the contract digest
6. Cache lookup on the 8-field key (needs 3, 4, 5 first, because they are key fields)
7. OSV check, always run, even on a cache hit (advisories change while the artifact does not)
8. Light AST scan (cache miss only), compared against the contract and call-site reachability
9. Verdict; only VERIFIED and REJECTED are cached, UNRESOLVED never is

No stage installs or executes package code. Wheels only; an sdist-only release is UNRESOLVED.

### Sink reachability and escalation **[approved change]**

`pypdf==6.19.0` must still reach VERIFIED. A sensitive sink inside a wheel does not make the
verdict UNRESOLVED on its own. It does so only when the sink is reachable from the project's real
call sites.

- The existing pypdf guard, `backend/cavr/fast_gate.py::disabled_jbig2_sinks(artifact, context)`,
  stays and is the reachability proof for pypdf: it returns the `subprocess.run` lines in
  `pypdf/filters.py` that are unreachable because every `PdfReader` call site in the project sits
  inside `apply_configuration(jbig2dec_binary=None)`. Its result is kept in the evidence.
  It expects a `context` with `.manifest` and `.read(path)`; the pipeline passes a small adapter
  defined in `backend/cavr/` rather than changing `context_service.py`.
- A sink with no reachability proof and no call-site path to it from the contract (commit 9) is
  recorded as unreachable evidence, not as a failure.
- When a sink is reachable, the verdict is UNRESOLVED and the verdict carries a separate field
  `escalation: "deep analysis required (M2)"`, so the evidence states why it is UNRESOLVED.

### Fields in every verdict **[approved change]**

Every verdict, whatever its status and including BLOCK, records:

- `fast_gate_ms` – wall time of the fast gate for this request
- `cache_hit` – true or false
- `escalated` – true when `escalation` is set

These feed the supervisor's required report: cache hit rate and p50/p95 fast-gate latency.

## Reuse (import, do not edit)

- `backend/threat_repo/package_records.py::affected` – correct OSV event-range matching.
- `backend/integrations/osv_adapter.py::OSV` – live query plus dated, digest-checked cache
  (pass an explicit cache dir).
- `backend/cavr/trigger_discovery.py::scan` – rule-driven AST sink/trigger scan.
- `backend/cavr/manifest_parser.py::detect_manifest_changes` – requirements diff.
- `backend/cavr/fast_gate.py::disabled_jbig2_sinks` – pypdf reachability proof (see above).
- `backend/orchestrator/hashing.py::digest` – canonical JSON hashing.
- `backend/cavr/storage.py::CavrStorage` – add the verdict-cache table here.
- `artifacts/pypdf-6.19.0-py3-none-any.whl` + `advisories/registry-*.json` – a real wheel and a
  real recorded registry response for offline tests.

## Commits (each: code + `tests/test_cavr_*.py`, full pytest run, then stop for review)

0. `fix(cavr): refuse host execution of unpinned package source`
   `sandbox_runner.py` falls back to running the package on the host when Docker is missing or
   fails. Return a "no isolation" UNRESOLVED result instead, and carry it through
   `counterfactual.py` and `causal_graph.py` so it cannot turn into VERIFIED.
   Tests: no-Docker run executes nothing; failed container run does not fall back to the host.
   Deliberately out of scope: `backend/cavr/sandbox.py`, the hash-pinned inert lab path, keeps its host mode and is covered elsewhere.

0b. `test(cavr): accept either monitor mode in controlled dormant execution` **[approved change]**
   `tests/test_modules.py::test_controlled_dormant_execution` only. It currently requires
   `PINNED_INERT_LAB_PYTHON_AUDIT` / `PYTHON_AUDIT`, which fails on any machine with strace or
   Docker. Accept either monitor mode. Keep the `REJECTED` assertion and the
   normal-vs-counterfactual canary assertions unchanged.

1. `feat(cavr): C1 parse pip install commands into capture records` – new `capture.py`.
   Handles `pip install a==1 b==2`, `python -m pip`, `-r file` (read and expanded), `-c`.
   URLs, VCS, local paths, `-e`, custom index flags are recorded as unsupported.
   Tests: each form, nested `-r`, missing file, malformed line.

2. `feat(cavr): C1 capture requirements.txt edits` – snapshot/diff via `detect_manifest_changes`;
   remove the regex fallback that accepts unparseable lines as packages (report them instead).
   Tests: added, version changed, removed, unparseable, unpinned.

3. `feat(cavr): C2 fail-closed requirement gate` – rewrite `requirement_gate.py`.
   Missing or invalid policy -> UNRESOLVED; denylist -> BLOCK; not pinned with `==` -> BLOCK;
   not on allowlist (canonical name + specifier) -> BLOCK; lockfile present and name/version not
   in it -> BLOCK. `policy_version` = digest of the canonical policy JSON.
   Tests: each rule, name canonicalisation (`Foo_Bar` vs `foo-bar`), wrong version of an allowed name.

4. `feat(cavr): C3 fetch PyPI release metadata and verify artifact SHA-256` – new `pypi_client.py`.
   Reads `pypi.org/pypi/{name}/{version}/json`, picks the wheel, streams it into quarantine with a
   size cap, hashes the bytes on disk. Mismatch -> REJECTED; network error, yanked, no wheel ->
   UNRESOLVED. HTTP transport is injectable.
   Tests: real pypdf wheel + recorded registry JSON (match); one flipped byte (REJECTED); tmp-built
   wheels; timeout; opt-in live test behind `CAVR_LIVE=1`.

5. `feat(cavr): C3 read wheel metadata safely` – new `wheel_meta.py`: zip budget, path checks,
   `METADATA` name/version/`Requires-Dist`, `top_level.txt`/`RECORD` import names, native-file list.
   Tests: pypdf wheel, name mismatch, zip bomb budget, missing METADATA.

6. `feat(cavr): C3 transitive tree and subtree digest` – new `dep_tree.py`.
   Evaluate markers (extras off). **[approved change]** For M1, each child is pinned from the
   project lockfile; the module docstring notes `pip install --dry-run --report` as future work for
   resolver-accurate pins. Children that cannot be pinned exactly -> UNRESOLVED; every node goes
   through commit 4. Subtree digest = digest of the sorted reachable (name, version, sha256) set
   plus edges (safe with dependency cycles).
   Tests: tmp-built 3-level tree, cycle, marker-excluded dep, unpinned child, digest changes when a
   leaf's bytes change.

7. `feat(cavr): C3 OSV check with real version ranges` – new `advisories.py` wrapping `OSV` and
   `affected`. Affected -> REJECTED; unavailable, stale, or unsupported range type -> UNRESOLVED.
   Tests (offline, recorded responses): introduced/fixed, last_affected, multi-range,
   just-outside-range, GIT-only range, no data. Live variant behind `CAVR_LIVE=1`.

8. `feat(cavr): C3 light AST risk scan of wheel sources` – new `ast_scan.py` over every `.py` in
   the wheel using `scan`, plus `.pth`, native extensions and parse errors as explicit findings.
   Tests: clean module, env-gated socket, syntax error, `.so` present.

9. `feat(cavr): C4 capability contract from real imports and call sites` – rewrite
   `infer_capability_contract` + `context_extractor.py`. Map import names to distributions using
   the wheel's real `top_level.txt` (this replaces any need for the alias table in
   `context_service.py`, which stays untouched); record each call site (file:line, symbol); derive
   allowed capabilities from the threat-repo capability rules and the policy; package never
   imported -> contract "no call-site authority" -> UNRESOLVED. Output has a stable `digest`.
   Tests: aliased import, `from x import y as z`, unused package, digest stable across reordering,
   digest changes when a new call site appears.

10. `feat(cavr): 8-field verdict cache` – new `verdict_cache.py` + table in `storage.py`.
    Key = digest of (ecosystem, name, version, artifact sha256, subtree digest, contract digest,
    policy version, analyzer version). Rows carry an integrity digest.
    Tests: hit on identical inputs; a miss for each of the 8 fields changed one at a time;
    tampered row ignored; UNRESOLVED not stored.

11. `feat(cavr): single verify_request pipeline` – `pipeline.py` wiring 1–10 in the order above.
    **[approved change]** Sinks are judged by reachability (see "Sink reachability and
    escalation"): unreachable or guard-disabled sinks are evidence only; a reachable sink ->
    UNRESOLVED with `escalation: "deep analysis required (M2)"`. OSV is re-checked on every cache
    hit. Every verdict records `fast_gate_ms`, `cache_hit`, `escalated`.
    Tests: end-to-end `pypdf==6.19.0` VERIFIED with the guard evidence present; the same project
    with a `PdfReader` call outside the guard -> UNRESOLVED with `escalation` set and
    `escalated: true`; gate BLOCK with zero downloads; hash REJECTED; OSV REJECTED; UNRESOLVED on
    network loss; second run is a cache hit that still re-checks OSV; a cached VERIFIED turns
    REJECTED when the advisory data changes; the three metric fields are present on every status.

12. `feat(cavr): pip wrapper runs the pipeline before pip` – rewrite `pip_shim.py`.
    **[approved change]** By default the wrapper only decides: it prints the verdict and evidence
    and exits 0 on VERIFIED, non-zero otherwise, without installing anything. Only with an explicit
    `--install` flag, and only on VERIFIED, does it run real pip with `--require-hashes --no-deps`
    on a generated file listing the exact verified tree.
    Tests with pip stubbed: default never invokes pip; `--install` + VERIFIED invokes it once with
    the hash-pinned file; `--install` + REJECTED/UNRESOLVED/BLOCK never invokes it.

13. `refactor(cavr): dashboard API uses the pipeline` – `api.py` `/api/cavr/intercept` calls
    `verify_request`; `resolver.py`, `reverifier.py`, `reconstructor.py`, and `fixtures/scenarios.py`
    leave the verdict path. **[approved change]** The dashboard scenario chips become real requests,
    with no fixture source strings anywhere in the verdict path:
    - `pypdf==6.19.0` -> VERIFIED
    - `pypdf==5.1.0` -> REJECTED via OSV
    - a denylisted name -> BLOCK
    - a tampered wheel -> REJECTED on hash mismatch
    - network off -> UNRESOLVED
    Small `frontend/src/components/cavr/` updates for the new evidence shape, including
    `fast_gate_ms`, `cache_hit`, `escalated` and `escalation`.

14. `refactor(cavr): orchestrator analyzer delegates to the pipeline` – `analyze()` keeps its
    signature and return shape so `backend/orchestrator/` is untouched.

## Out-of-scope files

- `tests/test_modules.py` – approved for `test_controlled_dormant_execution` only (commit 0b).
  If commit 14 needs any other expectation in that file changed, stop and ask first.
- `backend/orchestrator/context_service.py` – not to be edited. Its hardcoded package-to-import
  alias table is worked around in commit 9.
- `backend/main.py`, `backend/orchestrator/`, `backend/integrations/`, `backend/satra/`,
  `backend/sable/` – ask before touching, per CLAUDE.md.

## Known issues deferred

Found in the commit 0 review (2026-10-10) and deliberately not fixed there:

- NOT_OBSERVED is shown as clean by consumers: `CounterfactualTab.tsx` chips it "CLEAN",
  `normalizer.py` maps it to `FILE_READ`/`INFO`, and `api.py` words NEEDS_REVIEW as hostile/blocked.
  The verdict itself is correct. -> step 13.
- Sandbox timeout is not enforced on a silent container (`readline()` blocks), and the kill stops
  the docker CLI rather than the container (no `--name` / `docker kill`). -> M2 sandbox.
- `harness.py` never imports a `.whl` yet reports `test_passed: True`; `image_digest` in
  `sandbox_runner.py` is a hardcoded constant, not checked against the image. -> step 13 / M2.
- Report forgery: the package shares stdout with the harness. Commit 0 treats more than one report
  marker as UNRESOLVED; a per-run random marker needs a `harness.py` change and an out-of-band
  report channel to be robust. A single forged report is accepted when the harness's own is
  suppressed (the package prints one report, then replaces `sys.stdout` or exits early with
  `os._exit(0)`). -> M2 sandbox.
- Invalid UTF-8 in container output: `readline()` raises `UnicodeDecodeError`, the `except` in
  `SandboxRunner.run` catches it, and the process is neither killed nor waited for. The result is
  still UNRESOLVED. -> M2 sandbox.
- `RequirementsTab.tsx` shows NFR-1 "Non-Root Isolation" as a hardcoded `status: "PASS"`, whatever
  the run did (NFR-2 is hardcoded the same way). -> step 13.

Found in the commit 0 review pass 4 (2026-10-10) and deliberately not fixed there:

- Two routes to VERIFIED without observation remain in the legacy dashboard path in
  `counterfactual.py`. (a) For the package name `dormant-exfil`, run 0 is a hardcoded NEUTRAL
  behaviour and `sandbox_runner.run` is never called; with no triggers the verdict is VERIFIED.
  (b) After an observed clean baseline, runs 1..n record "Branch evaluated safely" (NEUTRAL)
  without calling the sandbox, so a trigger-gated path is reported as explored. Both are removed
  in step 13. -> step 13.
- The docker command fix in `sandbox_runner.py` (image `ENTRYPOINT` runs the harness, only `/pkg`
  is passed) has not been executed. `docker/asent-sandbox/Dockerfile` does `COPY harness.py`, and
  `harness.py` exists only in `backend/cavr/`, so the image must be built with `backend/cavr` as
  the build context. Believed-correct command, from the repository root, **not yet run**:
  `docker build -f docker/asent-sandbox/Dockerfile -t asent-sandbox backend/cavr`.
  Real Docker verification waits until Docker is installed. -> M2.
- The proof drawer shows a stale command: `api.py` hardcodes
  `asent-sandbox python /opt/asent/harness.py /pkg/<name>.py` and a relative
  `seccomp=asent-seccomp.json`; neither matches what the runner now executes. -> step 13.
- Harness `events` are ignored: `baseline_behaviors` reads only the five metrics, so a report with
  zero metrics and non-empty `events` is a clean import. Metrics are authoritative for now;
  harness events are to be used from M2. -> M2.

## Verification

- `.venv/bin/python -m pytest -q` before every commit (offline).
- `CAVR_LIVE=1 .venv/bin/python -m pytest -q tests/test_cavr_live.py` for real PyPI + OSV.
- Manual: `python -m backend.cavr.pip_shim install pypdf==6.19.0` in a scratch venv
  (expect VERIFIED and nothing installed, then a cache hit on the second run); the same with
  `--install` (expect the install to run); a denylisted name (BLOCK, no download);
  `pypdf==5.1.0` (REJECTED with the OSV id).
- Report for the supervisor: cache hit rate and p50/p95 of `fast_gate_ms` over the stored verdicts.

## Progress

- [x] 0 refuse host execution of unpinned package source (committed 2026-10-10, `3be14db`)
- [ ] 0b accept either monitor mode in `test_controlled_dormant_execution`
- [ ] 1 C1 pip command capture
- [ ] 2 C1 requirements.txt edit capture
- [ ] 3 C2 fail-closed requirement gate
- [ ] 4 C3 PyPI fetch + SHA-256
- [ ] 5 C3 wheel metadata
- [ ] 6 C3 transitive tree + subtree digest
- [ ] 7 C3 OSV ranges
- [ ] 8 C3 AST scan
- [ ] 9 C4 capability contract
- [ ] 10 verdict cache
- [ ] 11 pipeline
- [ ] 12 pip wrapper
- [ ] 13 dashboard API
- [ ] 14 orchestrator analyzer
