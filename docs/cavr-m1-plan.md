# CAVR M1 plan: one real path for C1–C4

Status: approved by Maryam on 2026-10-10 with the changes marked **[approved change]** below.
Progress is tracked in the checklist at the end; update it as each commit lands.

## Working rules (apply to every step)

- **[changed 2026-10-10, decided by Maryam]** Steps 0 and 0b were done one at a time: Claude stopped
  with the diff in the working tree and Maryam reviewed and committed it herself. From step 1 on, steps
  run in batches through `.claude/commands/cavr-batch.md` (`/cavr-batch <steps>`):
  - Claude does the named steps in order without asking between them, and commits each step itself
    with the plan's message for that step, staging that step's files by name (never `reports/` or
    `.claude/settings.local.json`).
  - Claude never runs `git push`.
  - One `cavr-reviewer` pass runs at the end of each batch, over the diff from the commit before the
    batch to `HEAD`. BLOCKERs are fixed in one extra commit; MINOR items go to "Known issues deferred".
  - Claude stops and asks only if a test cannot be made to pass without weakening it, the plan needs a
    real change, or a file outside the allowed scope must be edited.
  - Where this plan and the `/cavr-batch` command differ, the command wins.
- Do not start steps outside the batch that was asked for.
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

## Commits (each: code + `tests/test_cavr_*.py`, full pytest run, then commit; review at the end of each batch)

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

Found in commit 0b (2026-10-10, `521c414`) and deliberately not fixed there:

- `backend/cavr/runtime_monitor.py::normalize` skips every strace line containing ` = -1 `. A
  non-blocking connect is printed by strace as `connect(...) = -1 EINPROGRESS`, so in strace mode the
  lab package's connect gives no `NETWORK_CONNECT` event and no correlation has `causal_confirmed`
  true. Seen with a real strace 6.19 on the lab package; the verdict was still `REJECTED` and the canary
  was still received. Consequence: `tests/test_modules.py::test_controlled_dormant_execution` still
  fails on a machine with strace, at its `causal_confirmed` assertion; commit 0b fixed only the mode
  assertions. Because every failed syscall is skipped, a blocked connect or a failed open of a secret
  file in a `--network none` container would also leave no event (read from the code, not run; docker
  and podman modes were not executed). No code change now. -> M2 sandbox.
  **Fixed for `connect(...) = -1 EINPROGRESS` on 2026-10-11** (the test failed in CI at exactly this assertion;
  `docs/report-notes/cavr-report-notes.md`, "Defects found by CI"). Every other failed syscall is still skipped. -> M2 sandbox.

Found in the batch 1-3 review (2026-10-10, MINOR items) and deliberately not fixed there:

- Gate, local versions: `a==1.0+local` is expected to satisfy the allowlist entry `a==1.0` (PEP 440;
  read from the rules, not run). Block local versions or pin the behaviour with a test. -> step 4.
  **Handled in step 4:** the gate still permits it and `pypi_client.fetch_artifact` returns UNRESOLVED
  for any local version before any network call
  (`test_local_version_is_unresolved_even_though_the_gate_permits_it`).
- Gate decisions carry the version as written (`"1"` for `a==1`), not normalised. It feeds the cache
  key. -> step 10. **Handled in step 10:** `verdict_cache.cache_key` uses the canonical version
  (`test_spellings_of_the_same_release_give_the_same_key`).
- `check_requirement_gate` builds `f"{name}=={version}"`, so a version string containing a marker
  (`2.31.0; python_version > "1"`) is PERMITTED while `api.py` keeps the raw string. -> step 13.
- `requirement_gate.py` module docstring says PERMITTED is returned "from exactly one place";
  `evaluate_capture` has two more. Reword. -> next change to the file.
- `load_json_file` does not catch `RecursionError` from a deeply nested JSON file. -> step 11.
- A lockfile path that is given but missing skips the lockfile rule, so deleting the lockfile turns the
  rule off. Documented and tested; to be decided in step 11.
- `api.py` shows an UNRESOLVED gate result as `policy_state = "REJECTED"`. Fail-closed but mislabelled.
  No automated test covers the `api.py` gate change. -> step 13.
- `capture.py`: no depth or total-file limit on nested `-r`; a long chain can raise `RecursionError`
  and diamond includes are re-read. Add a cap that records an error. -> step 12.
- `capture.py`: `-r` accepts any absolute path and unparseable lines are copied into `errors[].raw`, so
  `-r <a secrets file>` would put its lines into evidence. Truncate `raw` or restrict includes to the
  project directory. -> step 12.
- `capture.py`: a FIFO or device named by `-r` blocks on open. Check `is_file()` first. -> step 12.
- `parse_pip_command(None)` raises `TypeError` instead of returning an error record. -> step 12.
- `capture_requirements_edit` raises `ValueError`/`KeyError` on bad snapshots; the caller must catch
  it. -> step 11.
- `manifest_parser.py` docstring says the diff "is `detect_manifest_changes`"; the code calls `_diff`
  (which `detect_manifest_changes` also calls). Reword. -> next change to the file.
- Removed option lines in a requirements edit (for example `--require-hashes` deleted) are not in
  `changes`. -> step 11.
- Nice-to-have capture tests: `pip install a==1 && pip install b==1`, `PIP_INDEX_URL=x pip install a==1`,
  the `--` separator, `-r https://...`, `-qr reqs.txt`. By reading, all fail closed. -> step 12.

Found in the batch 4-8 review (2026-10-10, MINOR items, all derived by reading) and deliberately not fixed there:

- `pypi_client.select_wheel`: two wheel entries with the same filename make `sorted` compare the entry
  dicts and raise `TypeError` (a crash, not a result). Sort on (rank, filename) or return
  `REGISTRY_INVALID`. -> step 11.
- `pypi_client.fetch_artifact`: a filename with a NUL byte passes `parse_wheel_filename` and `mkstemp`
  raises an uncaught `ValueError`. -> step 11.
- `pypi_client._chunks`: the 120 s deadline is checked only when a chunk arrives; a slow drip below the
  15 s read timeout can run past it. The Step 4 notes state the deadline without this limit. -> step 11.
- `pypi_client.NAME` (and `wheel_meta.NAME`) use `match` with `$`, which accepts a trailing newline.
  Use `fullmatch`. -> step 11.
- `HttpxTransport.stream` (redirect, non-200) has no offline test; `httpx.MockTransport` would cover it.
  -> step 11.
- After a `HASH_MISMATCH`, an older good `<filename>` from an earlier run stays in quarantine beside
  `<filename>.rejected`. -> step 11.
- `wheel_meta._headers`: parser defects are ignored (a non-header line inside the header block ends it
  silently). Treat non-empty `defects` as `METADATA_INVALID`. -> step 9.
  **Handled in step 9** (`test_a_line_that_is_not_a_header_inside_the_header_block_is_unresolved`).
- `wheel_meta.read_wheel` without an expected name and version skips the request identity check; the
  pipeline must always pass both. -> step 11.
- `wheel_meta.check_entries`: the duplicate-name check lowercases but does not Unicode-normalise
  (NFC vs NFD). -> step 11.
- `dep_tree`: a node key is (name, version text), so `1.0` and `1.0.0` coming from different sources
  could become two nodes. -> step 10 (together with the version normalisation item above).
  **Handled in step 10** (`test_the_same_release_written_two_ways_is_one_node`).
- `ast_scan`: nested archives (`.zip`, `.egg`, `.whl`), `*.data/scripts/*` without a `.py` suffix and
  `.pyw` files are neither scanned nor reported, and the result is still `SCAN_COMPLETE`. Add a
  "not scanned" finding. -> step 11.
- `ast_scan._alias_pass`: `from os import *` followed by `system(...)` is not found. -> step 11.
- Test names that claim more than the test checks:
  `test_subtree_digest_is_stable_and_does_not_depend_on_requires_dist_order` (no digest compared for the
  swapped order), `test_every_recorded_advisory_matches_5_1_0_and_most_do_not_match_6_19_0` ("most",
  asserts all), `test_scanning_does_not_execute_the_package` (cannot fail). -> next change to each file.
- `tests/test_cavr_data/osv-pypdf-5.1.0.json` was not opened by the reviewer; "real, only trimmed" rests on
  the recording step and on the live test (`CAVR_LIVE=1`), not on the review.
- The reviewer did not run the full suite; the 7 baseline failures were confirmed by the batch runs only.

Handled in step 11 (2026-10-10), each with a test: `load_json_file` RecursionError; `capture_requirements_edit`
errors caught by the pipeline (`CAPTURE_FAILED`); `select_wheel` duplicate filename and NUL filename; `NAME`
fullmatch; `HttpxTransport` offline tests; stale good file beside `.rejected`; `read_wheel` always gets name and
version (through `dep_tree`); NFC duplicate names; `ast_scan` not-scanned finding and star imports; the
`requirement_gate.py` docstring; the `test_scanning_does_not_execute_the_package` test can now fail.
Decided in step 11: a missing lockfile stays "no lockfile" and is stated in the verdict (`lockfile.present`).
Still open after step 11: `_chunks` slow-drip deadline -> M2; removed option lines of an edit -> step 12;
`test_cavr_advisories.py` test name and `manifest_parser.py` docstring -> next change to each file.
Found in step 11: the pypdf proof did not cover pages decoded after the `with apply_configuration(...)` block
ends. **Handled in the batch 9-11 review fix:** the reader must stay inside the guard block
(`test_pages_read_after_the_guard_block_are_unresolved_and_escalated`). What remains: an object taken from the
reader (a page, a stream) and used after the block is not followed. -> Maryam / M2.

Found in the batch 9-11 review (2026-10-10, MINOR items, all derived by reading) and deliberately not fixed there:

- `reachability.py`: other ways to import at run time do not make every sink reachable (`importlib.__import__`,
  `importlib.util` / `machinery`, `runpy`, `pkgutil`, writes to `sys.path` / `__path__` / `sys.modules`). -> M2.
- `pipeline.py`: a second requirement for the same release in one request is skipped, so its extras and `--hash`
  are never checked. Merge them or return UNRESOLVED. -> step 12.
- `pipeline._log`: `requested` is built outside the `try`, so a caller-made record with a non-list `command` raises;
  the full command (which may hold index-URL credentials) is stored in `verdict_log`. Redact it. -> step 12.
- `pipeline._verify_package`: a consistent cache row whose JSON lacks `scan` / `reachability` gives `INTERNAL_ERROR`
  on every run. Treat it as a miss. -> step 12.
- `skipped_directories` is not in the verdict: any directory holding `pyvenv.cfg`, any dot-directory and
  `node_modules` are invisible to the contract and the proof; `.pyw`, notebooks and scripts without a suffix are not
  read. Put the list in the evidence and the limitations. -> step 13.
- `context_extractor._Uses`: aliases are per file and the last binding wins in `ast.walk` order, so a nested import
  can re-attribute every call in the file. -> M2 (scopes).
- `context_extractor`: a reference in an annotation or under `TYPE_CHECKING` counts as call-site authority. -> M2.
- `tests/test_cavr_contract.py`: `test_digest_changes_when_a_new_call_site_appears` and
  `test_digest_changes_when_a_call_site_moves_or_is_removed` would still pass if call sites were dropped from the
  digest, because `sources_digest` changes anyway. -> next change to the file.
- Nice-to-have test: two requirements for one release in one request (see the second item). -> step 12.
- Style: assigned lambdas and long lines in `pipeline.py` and `context_extractor.py`;
  `capability_contract._entry_modules` is a nested one-liner that is hard to explain line by line. -> next change
  to each file.
- Outside this diff: the seed sink list is small (`subprocess.call` / `check_output`, `os.popen`, `os.exec*` and
  `sock.connect` on an instance are not sinks), so "0 denied sinks" is weak evidence. `backend/threat_repo/seed/`
  is not in this branch's scope; state it as a limitation in the report. -> Maryam.
- The fix commit for this review has not been reviewed again.

Handled in step 12 (2026-10-10), each with a test: `capture.py` cap on `-r` files (100 per command), `-r` only
inside the project directory and never a URL, FIFO / device refused before `open`, `parse_pip_command(None)`, the five
nice-to-have command forms; removed option lines of an edit (`removed_options`); `pipeline.py` duplicate release in one
request (`DUPLICATE_REQUIREMENT`), `_log` inside the `try` and redacted, incomplete cache row treated as a miss
(`ROW_INCOMPLETE`); the `manifest_parser.py` docstring.
Still open after step 12: a requirements file inside the project is read whatever it is (`-r .env`); a root
requirement's marker is ignored; other pip commands are not passed through; `--cavr-python` for another Python version
relies on pip's hash check failing. -> M2 / Maryam.

Open after step 13 (2026-10-10), needs Maryam's decision: `frontend/src/components/CavrModule.tsx` is outside the
allowed scope and was not edited. It still holds the five old chips (labels and package names), the eight-step timeline
with fixed timings, a proof drawer that prints "VERIFIED MATCH" for every run, and the sandbox console panel. The backend
serves the five real scenarios at `GET /api/cavr/scenarios` and runs them with `POST /api/cavr/run?scenario=<id>`.
Handled in step 13: NOT_OBSERVED chip in `CounterfactualTab.tsx`; NFR-1 / NFR-2 hardcoded PASS; both routes to VERIFIED
without observation (the dashboard no longer calls `counterfactual.py`); stale docker command (the proof says "not run");
UNRESOLVED gate shown as REJECTED; marker in the version field; `skipped_directories` in the verdict.
Still open after step 13: `normalizer.py` maps NOT_OBSERVED to `FILE_READ`/`INFO` and `harness.py` / `image_digest`
(legacy sandbox path, no longer called by the dashboard) -> M2; `/api/cavr/cache`, `/simple/` and the dialog texts
(removed or replaced in the batch review fix); `storage.SEED_PACKAGES` hashes not checked against PyPI; legacy modules
(`resolver.py`, `reverifier.py`, `reconstructor.py`, `fixtures/scenarios.py`, `triggers.py`, `repair_engine.py`) are
unused by the dashboard and still in the repository; the frontend was not checked in a browser.

Step 14 stopped before any code change (2026-10-10), needs Maryam's decision: the safe scenario is VERIFIED today only
because `analyze()` accepts PyPI's advisory list (`advisories/registry-*.json`, mode `PYPI ADVISORY METADATA (dated)`);
the pipeline returns UNRESOLVED `ADVISORIES_UNAVAILABLE` for the same data. Delegating therefore changes
`test_cavr_safe_cache_and_advisory` in `tests/test_modules.py`, which the plan says to ask about first. Options A-D are in
`docs/report-notes/cavr-report-notes.md`, section "Step 14". Separately: that registry record is accepted for 30 days,
so from 2026-10-25 the same test fails with the current code.
**Decided 2026-10-14 by Maryam and done:** delegate; update the old-path tests in `tests/test_modules.py` and
`tests/test_integration.py`; live PyPI/OSV in production, recorded data in tests (`tests/conftest.py`); policy from
`policy.json` `dependencies.allowed`; the RESTRICTED branch in `final_gate.py` is reported, not edited. The registry-record
expiry no longer applies to the orchestrator path (it does not read `advisories/registry-*.json`).

Handled in the batch 12-13 review fix (2026-10-10): demo-condition runs are no longer logged or cached; `/simple/*`,
`POST /api/cavr/cache` and `/api/cavr/dialog/*` removed; `GET /api/cavr/cache` lists the real verdict cache;
`demo_condition` in every event; note facts corrected. `README.md` line 168 still mentions `/simple/` (not in scope).

Found in the batch 12-13 review (2026-10-10, 1 BLOCKER outside the scope and the MINOR items, all derived by reading)
and deliberately not fixed there:

- **BLOCKER, needs Maryam:** `frontend/src/components/CavrModule.tsx` prints "VERIFIED MATCH" for every run (`:1163`),
  "Counterfactual Container Runs (1)" for an empty list (`:1168`), "Matches" on a timer for the Re-verify button
  (`:126-131`), fixed stage timings (`:379-447`), the sandbox and honeytoken panel after every verdict (`:774-923`), and
  still sends the old chips (`:146-164`).
- `api.py` `run_verification` / `launch_cavr_pipeline`: the task reference is not kept and there is no `try/finally`; a
  fault after the pipeline leaves the run unfinished and the stream sends heartbeats for ever. Always mark the run
  finished; add a test. -> next change to the file.
- `api.py` `approve_alternative`: accepts unknown run ids, appends after the final event, and no alternative exists on
  this path. Return 404 or remove; untested. -> with the `CavrModule.tsx` decision.
- `api.py` / `assurance.py`: "Terminal Hash", `evidence_chain_root` and `total_blocks` are taken before the final record,
  so they differ from `/verify`'s `terminal_digest`. Label it. -> next change.
- `api.pip_request`: the single token can itself be an option (`package="-rrequirements.txt"` reads the sample
  project's own file). Fail-closed; reword the docstring and add a test case. -> next change.
- `api.verdict_events`: the gate event is published as "Requirement gate" even when the capture failed before the gate.
- `pipeline.metrics`: p50 / p95 include BLOCK and capture-failure rows, which download nothing. Report per status, or
  only runs that reached the artifact stage. -> Maryam (it is the report number).
- `pip_shim.py`: the output does not say which policy file was used; `python -m pip` runs with the caller's directory on
  `sys.path` (a `pip.py` in the project would run; use `-P` or a temporary `cwd`); a non-dict verdict or a `ValueError`
  from the runner gives a traceback (nothing is installed). -> next change to the file.
- `capture.redact`: `--proxy user:pass@host:8080` without a scheme is not redacted, and a password containing `@` leaks
  its tail. `capture._read_file`: `path != root` lets `-r .` through to the "not a regular file" error; simplify.
- `pypi_client` with the shared quarantine: a `tampered_wheel` demo run deletes the good wheel that a concurrent real run
  is about to scan (that run becomes UNRESOLVED `ARTIFACT_CHANGED`). Give demo runs their own directory.
- `RequirementsTab.tsx`: PASS / FAIL means "stage produced output" or "request passed" (FR-2 shows FAIL when the gate
  correctly blocks); the scope box still describes sandbox isolation and an offline OSV mirror.
  `CapabilityContractTab.tsx`: `startsWith` can match a longer capability name. `OverviewTab.tsx`: the badge counts all
  findings, the list shows three. `MetricsTab.tsx`: "per verified request" should be "per request".
- `requirement_gate.check_requirement_gate`: the docstring still calls it the dashboard entry point.
- Tests: none for `approve_alternative`, for `pip_shim._default_store()` returning None, or for an unknown status exit
  code; `test_printable_certificate_shows_the_real_values_and_escapes_them` checks escaping of `reason` only;
  `test_only_the_two_named_conditions_change_the_transport` checks `demo_condition` only.
- Hard to explain line by line: `pip_shim.install_plan` (`setdefault(...) != ...`), the eviction slice in
  `api.launch_cavr_pipeline`, the unreachable `yield` in `OfflineTransport.stream`, the 90-line `verdict_events`, many
  lines over 120 characters.
- The reviewer did not run the live tests and did not open the dashboard in a browser. The fix commit has not been
  reviewed again.

Demo polish (2026-10-11), six issues listed by Maryam after the demo script, one commit each (`384ec4f` .. `cdbfa27`)
and one review fix commit. Not plan steps; they close the open part of step 13. Handled, each with a test: the chips
are six real requests read from `GET /api/cavr/scenarios` (chip 4 is `left-pad==1.0`, `NOT_ON_ALLOWLIST`); the page
prints only API values and a dash for what was not computed ("VERIFIED MATCH", the fixed timeline, the sandbox panel
and the Re-verify timer are gone); `hash_comparison.matches` is `None` when nothing was hashed; `fast_gate_ms` per
status and per cache lookup, no overall percentile; demo runs have their own quarantine directory; long advisory
lists as a count and three ids. From the earlier lists this also handles: the `CavrModule.tsx` BLOCKER of the batch
12-13 review, "p50 / p95 include BLOCK rows", "a tampered_wheel demo run deletes the good wheel", the `OverviewTab`
badge / list mismatch, and the `RequirementsTab` PASS / FAIL meaning and scope box.

Found in the demo-polish review (2026-10-11, MINOR items, derived by reading) and deliberately not fixed there:

- `api.verdict_events`: `advisory_summary` names the requested package but counts every node of the tree; wrong when a
  dependency is the affected one. Not reachable with the shipped policy (pypdf has one node). -> next change to the file.
- `ExpandableStep.tsx`: a green tick means "ran", so the artifact stage of a tampered run and the gate stage of a BLOCK
  get a tick. Use a neutral marker, or colour by the stage's first value. -> Maryam (it is the look of the page).
- `OverviewTab.tsx`: "Cache hit: no" for a BLOCK or an internal error; the cache was never reached. Print the cache
  stage's `lookup` value or a dash.
- `CavrModule.tsx` cache dialog: every row gets the CSS class `trusted`, also a cached REJECTED analysis.
- `pipeline.cache_lookup_of`: a request with one HIT package and one that never reached the lookup, or a HIT followed by
  `REQUEST_HASH_MISMATCH`, is logged `MISS`; `CACHE_UNAVAILABLE` counts as a lookup. Say so in the docstring or add a
  value. -> next change to the file.
- `storage.init_db`: two processes starting on an old database can both run `ALTER TABLE`; catch "duplicate column".
- `Timeline.tsx`: `STAGE_NAMES` repeats `api.STAGE_TITLES` and stages are matched by index; no test compares the two.
- Tests: the fixed-string check is a blocklist of 17 literals; the render tests run no click, fetch, effect or
  `EventSource` and no intermediate state (a verdict without a proof); the harness does not render `Timeline` itself and
  its `assurance` view is unused; `test_the_running_app_loads_none_of_the_fixture_or_simulation_modules` sees
  import-time loading only; in `test_a_tampered_run_never_deletes_or_alters_the_genuine_wheel_in_quarantine` the last
  "still a cache hit" assertion cannot detect a deletion (the bytes / mtime / inode assertions can).
- `RepairTab.tsx`, `CounterfactualTab.tsx`, `CausalGraphTab.tsx`: the branches for data that the API never sends hold
  hardcoded "OSV Clean" ticks and default costs. Unreachable today; delete or fix before M2.
- `CavrModule.tsx` header and `RequirementsTab.tsx` scope box: static text still names counterfactual activation, sandbox
  and typosquat defences that the fast gate does not do. Labels, not results. -> Maryam.
- Hard to explain line by line: `pipeline._nearest_rank` (`-(-percent * n // 100)`), the three-way `setdefault` loop in
  `pipeline.metrics`, the 25-line `values` literal in `api.stage_summary`.
- `tests/test_cavr_data/render_cavr.mjs` requires `esbuild`, which is installed only as a dependency of vite.
- The fix commit for this review has not been reviewed again. The page has not been opened in a browser.
- Outside the review: `project_policy.json` approves `pdf-clean-extractor==1.0.0`, a name with no release on PyPI
  (anyone could register it). -> Maryam.

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
- [x] 0b accept either monitor mode in `test_controlled_dormant_execution` (committed 2026-10-10, `521c414`)
- [x] 1 C1 pip command capture (committed 2026-10-10, `73f7892`; batch review fixes in the next commit)
- [x] 2 C1 requirements.txt edit capture (committed 2026-10-10, `4c053b6`; batch review fixes in the next commit)
- [x] 3 C2 fail-closed requirement gate (committed 2026-10-10, `c018f30`; batch review fixes in the next commit)
- [x] 4 C3 PyPI fetch + SHA-256 (committed 2026-10-10, `00b9332`; batch review fix in the next commit)
- [x] 5 C3 wheel metadata (committed 2026-10-10, `3ba4970`; batch review fix in the next commit)
- [x] 6 C3 transitive tree + subtree digest (committed 2026-10-10, `3cb1a35`; batch review fix in the next commit)
- [x] 7 C3 OSV ranges (committed 2026-10-10, `b7c98cf`; batch review fix in the next commit)
- [x] 8 C3 AST scan (committed 2026-10-10, `c72b56a`; batch review fix in the next commit)
- [x] 9 C4 capability contract (committed 2026-10-10, `a188cb6`; batch review fix in the next commit)
- [x] 10 verdict cache (committed 2026-10-10, `d8e6367`)
- [x] 11 pipeline (committed 2026-10-10, `c5c0ef4`; batch review fixes in the next commit)
- [x] 12 pip wrapper (committed 2026-10-10, `1e17034`)
- [x] 13 dashboard API (backend and `frontend/src/components/cavr/` committed 2026-10-10, `ca5a0e2`, batch review fix in the
      next commit; the chips, timeline and proof drawer in `frontend/src/components/CavrModule.tsx` done on 2026-10-11
      at Maryam's request, `384ec4f` and `f705496`, see "Demo polish"; not yet opened in a browser)
- [x] 14 orchestrator analyzer (committed 2026-10-14, `cc81d9d` move to `m2_deep_analyzer.py`, `fe59fc0` delegation;
      decisions in the Step 14 note of 2026-10-14; not reviewed by cavr-reviewer)
