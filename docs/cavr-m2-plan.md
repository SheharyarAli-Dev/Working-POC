# CAVR M2 plan: finish CAVR

Status: **decisions recorded** (Maryam, 2026-11-22; see "Decisions"). Phase 1 (PR 1, PR 2) is being implemented on
branch `cavr-m2-phase1-wiring`. Owner: Maryam Fatima. Progress is tracked per phase at the end;
update it as each PR lands.

## Sources read

- Design: `~/cavr-docs/CAVR_Revised_Research_Design_and_Architecture_FINAL.docx` (v2.0, 26 Sep 2026), converted to
  text. Section numbers below (§5.1 P1–P13, §6.1–6.11, §10, §16) are that document's.
- `docs/cavr-m1-plan.md` (including "Known issues deferred"), `docs/cavr-demo.md`, `docs/asent-gate.md`,
  `docs/report-notes/cavr-report-notes.md` (M1 steps 0–14, demo polish, gate steps 1–11), `docs/report-notes/cavr-study-qa.md`.
- Code: all of `backend/cavr/`, `backend/orchestrator/`, `backend/gate/`; `frontend/src/components/cavr/RequirementsTab.tsx`.
- Tests: every `tests/test_cavr_*.py`, `tests/test_gate_cavr_verdicts.py`, the CAVR tests in `tests/test_modules.py`.
- Environment facts checked on 2026-11-22: Docker 29.9.3 is installed and running (the M1 notes say "Docker not
  installed"; that is no longer true on this machine). Images present: `asent-sandbox:local` (built from
  `docker/sandbox.Dockerfile`, used by SATRA), `asent-satra-runner:local`. The image `sandbox_runner.py` names,
  `asent-sandbox` from `docker/asent-sandbox/Dockerfile`, has never been built. `z3` and `networkx` 3.7 import in `.venv`.
- Test baseline on 2026-11-22: `tests/test_cavr_*.py` + `tests/test_gate_cavr_verdicts.py`: 1303 passed, 8 skipped
  (live, `CAVR_LIVE` unset), 270 s. The full `.venv/bin/python -m pytest -q` did not finish within 15 minutes on this
  machine (stopped, no result), so there is no full-suite baseline yet; it must be measured before PR 1.

## Decisions (Maryam, 2026-11-22)

| Q | Decision | Where it changes the plan |
|---|---|---|
| Q1 | **Option A.** Demo runs delegate to `verify_request`; without an OSV answer a package is UNRESOLVED. The `tests/test_modules.py` expectations change accordingly. | PR 1 |
| Q2 | The VERIFIED demo pin becomes **`pypdf==6.21.4`**; `pypdf==6.19.0` and `pypdf==5.1.0` stay as REJECTED demo cases. Checked 2026-11-22: 6.21.4 has a wheel (`pypdf-6.21.4-py3-none-any.whl`, uploaded 2026-10-28), is not yanked, and has 0 advisories on PyPI's JSON and on OSV. The real wheel, registry JSON and OSV answer are recorded for offline tests; if any of them changes before PR 1, stop and ask. | PR 1 |
| Q3 | Out of M2, listed under "Future work": npm, eBPF, Tree-sitter, Sigstore, level-4 package replacement, RESTRICTED enforcement. | Checklist row 34, PR 14, PR 15, "Future work" |
| Q4 | Edits outside the CAVR scope are approved (`docker/`, `.github/workflows/`, `tests/test_modules.py`, `frontend/src/components/CavrModule.tsx`, demo project data). Every commit touching a shared file carries **`[owner review: <file or area>]`** at the end of its subject line. | Working rules; PRs 1, 3, 12, 19 |
| Q5 | Tracer: strace as container root with only four capabilities and `no-new-privileges`: `SYS_PTRACE` (trace), `SETUID` + `SETGID` (`strace -u cavr` drops to UID/GID 10001), `DAC_READ_SEARCH` (read `/proc/<pid>/fd` of a UID 10001 process, mode 0500, so that `strace -y` prints each fd's path; added 2026-11-23, PR 7, Maryam). Package code runs as UID 10001 and holds no capability (the drop clears every set); the image has no setuid / setgid file and no file capability (Docker test). NFR-1 is reworded to **"package code never runs as root"**. | NFR-1, sandbox rule 3, PR 5, PR 7 |
| Q6 | Separate image `asent-cavr-sandbox:local`, base pinned by digest. | PR 3 |
| Q7 | Time triggers through **libfaketime** in the image. | PR 3, PR 11 |
| Q8 | Budget accepted: 8 runs, 20 s per run, 120 s per package; deep runs only on escalation. Deep **VERIFIED only if** every run completed within budget, every trace is complete, and no event falls outside the contract in any run context. Any violation -> **REJECTED**; anything incomplete -> **UNRESOLVED**. | PR 2, PR 9, PR 12 |
| Q9 | Repair only **proposes a patch** (requirements, lockfile, policy) for human approval; it is never applied by CAVR or the gate. The proposal itself is re-verified. | PR 15, PR 16, PR 17 |
| Q10 | CAVR re-verifies with its own checks. Project tests reuse SATRA's image builder through its public API (`backend/satra/project_image.py::prepare`, to be confirmed as public with SATRA's owner) without editing SATRA; if that is not possible, the missing project-test run is recorded as a limitation. | PR 16 |
| Q11 | FR-11..FR-15 and NFR-3..NFR-6 adopted. | Requirement IDs, PR 19 |
| Q12 | Each legacy module is deleted once its tested replacement has landed and nothing uses it. | Working rules, PR 20 |

Q8 frontier rule (confirmed by Maryam, 2026-11-22): "every run completed within budget" also covers the frontier.
If the budget ends while a high-risk trigger is still unexplored, or a trigger cannot be synthesized, the analysis is
incomplete -> UNRESOLVED, with those triggers listed. Accepted consequence: until PR 12 adds the frontier loop, PR 9
returns UNRESOLVED for an escalated package that has such a trigger. Packages that are not escalated never reach the
deep stage, so their fast-gate verdicts do not change.

## Requirement IDs

The dashboard matrix (`frontend/src/components/cavr/RequirementsTab.tsx`) already uses **FR-1 … FR-10, NFR-1, NFR-2**,
and the report notes cite them. They are kept unchanged. FR-11..FR-15 and NFR-3..NFR-6 are new (adopted, Q11).

| ID | Name | Design ref |
|---|---|---|
| FR-1 | Intercept before execution | P1, §6.1, Objective 1 |
| FR-2 | Requirement gate enforcement | P2, §6.1 |
| FR-3 | Capability contract inference | P3–P4, §6.2, Objective 2 |
| FR-4 | Adaptive counterfactual activation | P7, §6.4, Objective 4 |
| FR-5 | Causal capability graph | P9, §6.6, Objective 5 |
| FR-6 | Fail-closed security policy | §6.7, Objective 6 |
| FR-7 | Minimal safe repair | P10, §6.9, Objective 7 |
| FR-8 | Re-verification | P11, §6.10, Objective 7 |
| FR-9 | Clean reconstruction | P12, §6.11, Objective 8 |
| FR-10 | Tamper-evident evidence / assurance | P13, §6.11, Objective 8 |
| FR-11 | Exact artifact, tree and known-risk resolution | P5 |
| FR-12 | Security-relevant trigger discovery and priority | P6, §6.3, Objective 3 |
| FR-13 | OS observation and event normalisation | P8, §6.5, Objective 5 |
| FR-14 | RESTRICTED verdict and its enforcement | §6.7 |
| FR-15 | CAVR verdict in every orchestrator / gate run | §1.3, §5 |
| NFR-1 | Package code never runs as root; no-network, read-only, limited sandbox; transactional isolation | §6.8, §15.2, §16.2 |
| NFR-2 | Deterministic, no paid LLM / API | §9.1, §15.1 |
| NFR-3 | Privacy: only package name and version leave the machine | §16.3 |
| NFR-4 | Efficiency: cache hit rate, p50/p95 per stage, runs per package | §10.1, §17 |
| NFR-5 | Canary-only secrets: no real credential or host environment in any run | §6.5, §16.2 |
| NFR-6 | Bounded claim: every verdict states what was and was not verified | §6.11, §16.2 |

## Requirements checklist

Status rule: **done** = implemented, tested (including failure cases) and on the path the gate uses.
**partial** = something real exists but is untested, demo-only, not used by `verify_request` / the gate, or missing a
design part. **not started** = nothing, or only a stub that returns constants (a stub is not counted as a prototype).

### Fast gate (M1) components

| # | Component (ID) | Status | Proved by (code; tests) | Missing |
|---|---|---|---|---|
| 1 | Capture: pip commands and requirements edits (FR-1) | partial | `capture.parse_pip_command`, `manifest_parser.capture_requirements_edit`, `pip_shim.main`; `test_cavr_capture.py` (53), `test_cavr_manifest.py` (37), `test_cavr_pip_shim.py` (35) | No agent pre-tool hook or local daemon (Unix socket / localhost API, §6.1); nothing puts the wrapper on `PATH`; other pip subcommands not passed through; a file inside the project is read whatever it is (`-r .env`); npm not handled |
| 2 | Requirement gate (FR-2) | done | `requirement_gate.evaluate_capture`; `test_cavr_requirement_gate.py` (57), `test_cavr_gate_adapter.py::test_denied_package_is_rejected_without_a_download`, `test_gate_cavr_verdicts.py::test_block_is_block_exit_1_without_a_download` | For repair (PR 15): the policy approves exact pins only, so a repaired version is BLOCKed until a person approves the proposed policy patch (Q9) |
| 3 | Project context (FR-3, P3) | partial | `context_extractor.extract_project_context`, `usage_of`; `test_cavr_contract.py` (48), `test_cavr_vendored_use.py` (14) | Git diff, changed files and task text are not inputs (§6.1); aliases are per file, last binding wins (no scopes); annotations and `TYPE_CHECKING` count as call-site authority; no Tree-sitter (npm) |
| 4 | Capability contract (FR-3, P4) | partial | `capability_contract.infer_capability_contract`; `test_cavr_contract.py` | Capabilities come from policy `allowed_scopes` + threat-repo rules, not inferred from the used API slice (§6.2 `PdfReader(path)` -> `FILE_READ(path)`); no required / optional / unexplained classes or confidence; the orchestrator report reads `contract.required` / `confidence`, which the new contract does not have; the old `infer()` is still used by the demo analyzer |
| 5 | Artifact: real wheel SHA-256 vs registry digest (FR-11) | done | `pypi_client.fetch_artifact`, `wheel_meta.read_wheel`; `test_cavr_pypi_client.py` (42), `test_cavr_wheel_meta.py` (41), `test_cavr_live.py` (live) | sdist-only releases are UNRESOLVED (by design); `_chunks` slow-drip deadline (M1 deferred) |
| 6 | Transitive tree + subtree digest (FR-11) | partial | `dep_tree.build_tree`, `subtree_digest`; `test_cavr_dep_tree.py` (38) | Children are pinned only from the project lockfile; no resolver (`pip install --dry-run --report`), which repair needs |
| 7 | OSV with real version ranges (FR-11) | done | `advisories.check_advisories`; `test_cavr_advisories.py` (40), live tests | Recorded data ages; live OSV lists 18 advisories for the demo pin `pypdf==6.19.0` (gate step 9 note); the VERIFIED demo pin moves to `pypdf==6.21.4` (Q2, PR 1) |
| 8 | Light AST risk scan | done | `ast_scan.scan_wheel`; `test_cavr_ast_scan.py` (34) | Seed sink list is small (`backend/threat_repo/seed/`, outside scope); no decoding of obfuscated payloads (that is the deep path's job) |
| 9 | Sink reachability | partial | `reachability.judge_sinks`; `test_cavr_reachability.py` (26) | One proof only (the pypdf guard); `runpy`, `pkgutil`, `sys.path` edits not followed; objects used after the guard block not followed. M2 answers these through the deep path, not more proofs |
| 10 | 8-field verdict cache | done | `verdict_cache.lookup` / `store`; `test_cavr_verdict_cache.py` (27) | Deep results need the sandbox image ID and budget in the key (through `analyzer_version`, PR 2) |
| 11 | Fast-gate verdict (FR-6) | done | `pipeline.verify_request`; `test_cavr_pipeline.py` (55) | An escalated UNRESOLVED (`deep analysis required (M2)`) has nowhere to go; RESTRICTED is never produced |
| 12 | Gate wiring via `verify_request` (FR-15) | partial | `analyzer.analyze` -> `gate_adapter.analyze_pipeline` when `context.gate`; `test_cavr_gate_adapter.py` (18), `test_gate_cavr_verdicts.py` (5), `test_gate_end_to_end.py` | Demo / scenario runs still use the lockfile analyzer with its own advisory rule (M1 step 14; Q1 option A, PR 1); no deep stage; the orchestrator assurance report's CAVR fields (`discovered_triggers`, `runtime`, `causal_evidence`, `required`, `confidence`) are empty for gate runs |

### Deep analysis, repair and assurance (M2) components

| # | Component (ID) | Status | Proved by (code; tests) | Missing |
|---|---|---|---|---|
| 13 | Trigger discovery and priority (FR-12, P6) | partial | `trigger_discovery.scan` (demo analyzer; `ast_scan` uses it for sinks only), `triggers.discover_triggers` (legacy, `counterfactual.py` only); `test_modules.py::test_controlled_dormant_execution`, `test_cavr_targeted.py` | Only literal env-var and file-existence predicates; no hostname / user / platform / time / sleep / CI / container / cloud-metadata predicates; priority is `risk_weight × sinks`, the §6.3 formula exists only in legacy `triggers.py`; not used by `verify_request` |
| 14 | Behaviour sandbox (NFR-1, P7, §6.8) | partial | `sandbox_runner.SandboxRunner` (flags), `harness.py`; `sandbox.run_counterfactual` + `lab_harness.py` (demo lab); `test_cavr_sandbox_runner.py` (33, Docker mocked), `test_modules.py::test_controlled_dormant_execution` | Not called by `verify_request` or the gate; its image has never been built or run; `image_digest` is a hardcoded constant; `harness.py` never installs a wheel and reports `test_passed: True`; timeout not enforced on a silent container and the kill stops the docker CLI, not the container; the package can forge the stdout report; invalid UTF-8 leaves the process un-waited; the seccomp profile (default `SCMP_ACT_ERRNO`, 57 allowed syscalls) has never been tried with Python; `sandbox.py` keeps a host mode for hash-pinned sources and adds `SYS_PTRACE`; tag clash: `asent-sandbox:local` is SATRA's image |
| 15 | Counterfactual activation (FR-4, P7, §6.4) | partial | `counterfactual.py` (legacy loop, dashboard tests only), `sandbox.run_counterfactual` (two fixed runs, one env canary); same tests as row 14 | No frontier loop over real triggers; no file / hostname / time synthesis; no budget, no new-predicate feedback, no early stop; residual triggers do not reach the verdict; name-specific branches (`dormant-exfil`) |
| 16 | OS observation and normalisation (FR-13, P8) | partial | `runtime_monitor.normalize` (strace); `normalizer.py` (legacy); `test_cavr_runtime_monitor.py` (5) | **Every failed syscall is dropped** except `connect … EINPROGRESS`: under `--network none` every connect fails (`ENETUNREACH`), so network attempts are invisible, and a denied open of a secret file is too; endpoint hardcoded `127.0.0.1:18765`; SECRET_ACCESS only for `canary.txt`; harness processes excluded by the substring `python`; harness `events` ignored (5 metrics only); no eBPF |
| 17 | Causal capability graph (FR-5, P9, §6.6) | partial | `causal_graph.build` (demo analyzer), `build_causal_graph` (legacy: hardcoded `invoice-utils` -> `sub-telemetry-hook`), `threat_repo.source_sink_rules.correlate`; `test_cavr_sandbox_runner.py`, `test_modules.py` | No graph from the real tree + real events; no event -> package attribution; no canary data flow (`derived_from`); no cross-package path query |
| 18 | Runtime policy + RESTRICTED (FR-6, FR-14, §6.7) | partial | `policy.verify_runtime` (rule `PDF_MINIMUM_CAPABILITY`); `final_gate.decide` accepts RESTRICTED only with `restriction_enforced`; `test_cavr_runtime_monitor.py` | Not driven by the contract's scopes; RESTRICTED is never produced and nothing enforces it |
| 19 | Transactional isolation (NFR-1, §6.8) | partial | Fast gate executes nothing; `pip_shim` decides only, `--install` installs only the verified tree with `--require-hashes --no-deps`; gate never installs; `test_cavr_pip_shim.py` | No disposable environment for deep runs (= row 14); no check that analysis containers are gone afterwards |
| 20 | Minimal safe repair (FR-7, P10, §6.9) | partial (level 1 done) | `repair_proposal.propose_repair` (2026-11-23): newer releases of the same package from the registry, minus pre-release, yanked, wheel-less and OSV-affected (package-wide answer, 24 h), same major first, at most 5 candidates in 60 s; removal when never imported and nothing depends on it; a proposed patch (requirements diff, lockfile entry, approved pins) for a person (Q9); `test_cavr_repair.py` (26), `test_cavr_repair_surfaces.py` (10). `repair.rank_repairs` + orchestrator `_repair` remain for the LOCAL-lab demo until PR 12 | Cost terms (w1–w4) not computed: the order is smallest upgrade, same major first; no constraints from other packages' Requires-Dist (no resolver); no downgrades; level 2 (transitive path) absent; level 4 (replacement) is future work (Q3) |
| 21 | Re-verification (FR-8, P11, §6.10) | partial (fast gate) | Each candidate: full `verify_request` on a temporary copy of the project with the patched requirements, lockfile and policy, fresh quarantine, no store; the copy must read like the project; only VERIFIED, not escalated is proposed (`repair_proposal._check_pin`). `reverifier.py` deleted | Fresh sandbox per candidate; project tests (Q10); deep analysis of an escalated candidate |
| 22 | Clean reconstruction (FR-9, P12, §6.11) | not started | `reconstructor.reconstruct_environment` returns a constant; its "baseline digest" is the hash of a time string (fixture-faked) | Build from the trusted baseline + verified hash-pinned tree in a fresh environment; check installed RECORD hashes; real baseline digest. Building block: `pip_shim.install_plan` |
| 23 | Evidence chain and certificate (FR-10, P13) | partial | `assurance.EvidenceChain`, `verify_chain`, `certificate_for_verdict` (dashboard); orchestrator chain + `asent.assurance.v1` (orchestrator-owned); `test_cavr_api.py` | `compute_record_hash` does not hash `ts` or `substep` (changes to them are not detected); "Terminal Hash" is taken before the final record; certificate has no baseline digest, deep-run, repair or reconstruction fields; no SARIF |
| 24 | Dashboard requirements matrix | partial | `RequirementsTab.tsx` (FR-1..10, NFR-1..2, prints backend values only); `test_cavr_frontend.py` (21) | Scope box expands CAVR as "Continuous Artifact Verification and Runtime" (design: Counterfactual Activation, Verified Repair & Recovery) and lists defences the fast gate does not do; module column names legacy modules; FR-4/5/7/8/9 and NFR-1 always show a dash; no rows for FR-11..15, NFR-3..6 |

### Non-functional requirements

| # | ID | Status | Proved by | Missing |
|---|---|---|---|---|
| 25 | NFR-1 package code never runs as root; isolation | partial | rows 14 and 19 | everything in row 14 |
| 26 | NFR-2 deterministic, no paid API | done by construction, untested | no LLM / paid client is imported by `backend/cavr/` (read, 2026-11-22) | a test that fails if one is imported |
| 27 | FR-6 fail closed | done for the fast gate | `test_cavr_pipeline.py`, `test_status_mapping`, `test_network_off_is_unresolved` | the deep path must keep it (every M2 PR has fail-closed tests) |
| 28 | NFR-3 privacy | partial | by reading: PyPI and OSV requests carry only name and version | a test with a recording transport; evidence never leaves the machine |
| 29 | NFR-4 efficiency | partial | `pipeline.metrics` (p50/p95 `fast_gate_ms` per status and cache lookup, hit rates); `test_cavr_pipeline.py` | `deep_analysis_ms`, runs per package, deep cache hit rate |
| 30 | NFR-5 canary-only secrets | partial | `harness.HONEYTOKEN_*`, `lab_harness.FAKE` (fixed strings) | random per-run canaries; a test that no host environment value enters a run |
| 31 | NFR-6 bounded claim | partial | `gate_adapter.BOUNDED`, orchestrator `bounded_claim` | per-verdict list of exercised and unexercised conditions (PR 12, PR 18) |
| 32 | Linux, local, no paid infrastructure | done | design §15; nothing paid is used | — |
| 33 | Evaluation corpus, baselines, ablations (§10) | not started | — | PR 21 |
| 34 | npm, eBPF, Tree-sitter, Sigstore, level-4 replacement, RESTRICTED enforcement | not started | — | future work, out of M2 (Q3; see "Future work") |

## Order of work (fast first)

Decided by Maryam, 2026-11-22. The quick parts come first; the PR numbers below are kept as names, not as the order.

1. **Phase 1 wiring** (PR 1, PR 2).
2. **Repair as a proposed pin / removal patch** (PR 15, and the fast-gate part of PR 16): the proposal (requirements,
   lockfile, policy patch) is re-verified with CAVR's existing checks (`verify_request` in a temporary copy of the
   project), no sandbox. A candidate whose fast verdict is an escalated UNRESOLVED stays UNRESOLVED until step 3.
3. **Phase 2 sandbox** (PR 3 – PR 9).
4. **Phase 3 counterfactual activation and causal graph** (PR 10 – PR 13).
5. **Dashboard and evaluation** (PR 19, and a 10–15 package evaluation from PR 21).

Everything else goes to "Future work": PR 14 (RESTRICTED), the sandbox and project-test parts of PR 16, PR 17 (clean
reconstruction), PR 18 (certificate), PR 20 (NFR guards and legacy removal check), and PR 21's baselines and ablations
beyond the 10–15 package evaluation. Legacy modules are still deleted by the PR that replaces them (Q12).

## Order of work

One part per PR, each a branch off `master`, small commits inside it (`feat(cavr): …`, `fix(cavr): …`,
`test(cavr): …`). For every PR: tests are written first and fail; `.venv/bin/python -m pytest -q` before each commit;
one `cavr-reviewer` pass; report notes under "Step N". A legacy module is deleted, with its tests, once its tested
replacement has landed and nothing uses it any more (Q12); usually that is the replacing PR. A commit that touches a
file outside `backend/cavr/`, `tests/test_cavr_*`, `frontend/src/components/cavr/`, `docs/report-notes/` and this plan
ends its subject line with `[owner review: <file or area>]` (Q4), for example
`build(cavr): CAVR sandbox image [owner review: docker/]`.

The 21 PRs are grouped into five phases. A phase is done when all its PRs are merged; its exit check is listed with it.

**Docker tests.** Marked through a helper in `tests/test_cavr_support.py` (`requires_docker`): they run only with
`CAVR_DOCKER=1` and a working engine, otherwise they are skipped and say why. Unit tests never start a container
(fake `Popen` / fake runner). Traces used by offline tests are real recordings from a Docker run, stored in
`tests/test_cavr_data/traces/` with the command, image ID and date that produced them.

### Sandbox security rules (apply to PRs 3–17; each rule has a test)

1. **No network.** `--network none` on every run; no DNS. PyPI / OSV are asked on the host before the run, never
   inside it. Test: a package that connects records a failed `NETWORK_CONNECT` and the container has only `lo`.
2. **Read-only.** `--read-only` root; wheels at `/pkg:ro`, project at `/project:ro`; writable only `tmpfs` with
   `noexec,nosuid,nodev` and a size cap; the trace directory is not writable or readable by the package's user.
3. **Least privilege; package code never runs as root (NFR-1).** Package code runs as UID 10001. Only the trusted
   tracer (strace) runs as container root, with `--cap-drop ALL --cap-add SYS_PTRACE --cap-add SETUID --cap-add SETGID
   --cap-add DAC_READ_SEARCH` and nothing else (Q5); `--security-opt no-new-privileges`; the repository seccomp profile (its SHA-256 goes into
   `analyzer_version`); no Docker socket, no host home, no SSH agent, no host environment variables. Test: every
   process of the package in the trace has UID 10001.
4. **Limits.** `--pids-limit 64`, `--memory 256m --memory-swap 256m`, `--cpus`, `--ulimit nofile,fsize`;
   wall-clock deadline enforced from the host with `docker kill <name>` then `docker rm -f <name>`; output byte cap.
5. **Pinned image.** The image is checked by its ID (`docker image inspect`) before every run; mismatch or
   missing -> UNRESOLVED. The base image is pinned by digest.
6. **Exact bytes.** Each wheel is re-hashed right before it is mounted; installed offline with
   `--no-index --no-deps --only-binary :all: --require-hashes`; no sdist, no `setup.py`, ever.
7. **Canaries only.** The run environment is built from scratch from the synthesis spec; canaries are random per
   run and registered; no real credential exists anywhere in the container.
8. **Fail closed (Q8).** Deep VERIFIED only if every run completed within budget, every trace is complete, and no
   event falls outside the contract in any run context. Any violation -> REJECTED. Anything incomplete -> UNRESOLVED:
   no engine, image problem, timeout, killed, non-zero harness exit, truncated or malformed trace, an event type the
   normaliser does not know, budget exhausted with high-risk triggers unexplored. Never a host fallback.
9. **Disposable.** Every run is a new container named `cavr-<run>-<n>` with `--rm`; tests check that `docker ps -a`
   shows none afterwards. Nothing from a run is ever copied into the project.

## Phase 1 — Wiring (PR 1, PR 2)

Exit check: every CAVR verdict in the orchestrator, gate and dashboard comes from `verify_request`, and the deep stage
exists behind the escalation (still answering UNRESOLVED without a sandbox).

### PR 1 — `refactor(cavr): orchestrator CAVR analysis goes through verify_request` (finishes M1 step 14)

- Part: `analyzer.analyze` sends every PyPI node of the demo / scenario runs through `verify_request`, as gate runs
  already do; the analyzer's own advisory rule (`OSV().query` on PyPI's advisory list) is removed (Q1 option A: no OSV
  answer -> UNRESOLVED). LOCAL lab nodes keep the lab path, labelled as the demo lab, until PR 12 replaces it.
  `gate_adapter` rows get the fields the orchestrator's assurance report reads (`sha256`, `contract.allowed/denied`,
  `escalation`). The old `capability_contract.infer` stays: the LOCAL lab path and the orchestrator's `_repair` still
  read its contract, so it is deleted in PR 12 with the lab path (Q12; decided 2026-11-22). No orchestrator file is edited.
- Demo pins (Q2), in their own commit: the VERIFIED demo case becomes `pypdf==6.21.4` (demo project requirements,
  lockfile, `.asent/cavr/policy.json`, dashboard scenario chip); `pypdf==6.19.0` and `pypdf==5.1.0` stay as REJECTED
  cases. The real 6.21.4 wheel, its registry JSON and its OSV answer are recorded once (date and SHA-256 noted) for the
  offline tests; nothing is hand-written. Shared files: `[owner review: demo_project, tests/test_modules.py]`.
- Tests first: `test_demo_pypi_node_is_judged_by_the_pipeline`, `test_demo_run_never_asks_osv_outside_the_pipeline`,
  `test_demo_run_without_an_osv_answer_is_unresolved`, `test_demo_pin_6_21_4_is_verified_on_the_recorded_answers`,
  `test_demo_pin_6_19_0_is_rejected_by_recorded_advisories`,
  `test_assurance_report_lists_each_cavr_package_sha256_and_contract`, `test_pipeline_fault_in_a_demo_run_is_unresolved`;
  `tests/test_modules.py::test_cavr_safe_cache_and_advisory` changed to the new pin and option A.
- Docker: no. Network: once, to record the 6.21.4 data.
- Acceptance: no CAVR status for a PyPI node is produced anywhere but `verify_request`; full suite has no new failures
  apart from the approved expectation changes; the assurance report of a gate run lists every package's sha256.

### PR 2 — `feat(cavr): deep-analysis stage behind the escalation, fail closed`

- Part: `verify_request(..., deep=None)`. Called only for a package whose fast verdict is UNRESOLVED with
  `escalation` (later also for packages with a high-risk trigger, PR 12). It may return VERIFIED / REJECTED / UNRESOLVED
  and can only replace that escalated UNRESOLVED; a REJECTED, BLOCK, unknown-advisory or unknown-contract verdict never
  calls it. `deep=None` keeps today's behaviour. The deep analyzer's version, image ID and budget go into
  `analyzer_version`, so the key stays the 8 fields. `gate_adapter.SETTINGS["deep"]` passes it through.
- Tests first (fake deep analyzer): VERIFIED lifts only the escalation; REJECTED rejects with the deep evidence; raising
  -> UNRESOLVED `INTERNAL_ERROR`; unknown status -> UNRESOLVED; not called for each of the four non-escalated cases;
  a cached deep VERIFIED still re-checks OSV; changing the image ID is a cache miss.
- Docker: no.
- Acceptance: `deep=None` output is byte-identical to today's on `test_cavr_pipeline.py`; every new path is fail-closed.

## Phase 2 — Behaviour sandbox (PR 3 – PR 9)

Exit check: an escalated package gets one observed run in `asent-cavr-sandbox:local` through `asent gate`; every
sandbox security rule above has a passing Docker test; violation -> REJECTED, incomplete -> UNRESOLVED.

### PR 3 — `build(cavr): CAVR sandbox image and image identity check`

- Part: one image for CAVR only, `asent-cavr-sandbox:local` (Q6; no clash with SATRA's `asent-sandbox:local`), from
  `python:3.12-slim@sha256:…`, with strace and libfaketime (Q7); new `backend/cavr/sandbox_image.py::image_identity()`
  reads the real image ID; the hardcoded `image_digest` goes. The seccomp profile is proven to let Python start.
  CI builds the image and runs the Docker tests. Shared files: `[owner review: docker/, .github/workflows/]`.
- Tests first: unit `test_image_id_mismatch_is_unresolved`, `test_missing_image_is_unresolved`; Docker
  `test_python_starts_under_the_seccomp_profile`, `test_running_container_has_every_lockdown_flag` (reads
  `docker inspect` HostConfig: ReadonlyRootfs, NetworkMode none, CapDrop ALL, SecurityOpt, PidsLimit, Memory, User),
  `test_container_has_only_loopback`.
- Acceptance: evidence carries the real image ID; a profile that blocks Python startup makes the Docker test fail.

### PR 4 — `fix(cavr): sandbox deadline, kill, output and resource limits on the real container`

- Part: `--name cavr-<run>-<n>`; host-side deadline independent of output (reader thread + queue); `docker kill` and
  `docker rm -f` by name; bytes with a cap, decoded with `errors="replace"`; `--memory-swap`, `--ulimit`.
  Closes the three M1 deferred runner items.
- Tests first: unit (fake `Popen`) silent container killed at the deadline, invalid UTF-8, output over the cap ->
  UNRESOLVED, kill targets the container name; Docker `test_sleeping_container_is_killed_and_removed`,
  `test_fork_bomb_stops_at_the_pids_limit`, `test_memory_hog_is_killed_and_unresolved`.
- Acceptance: no run outlives its deadline by more than 5 s; `docker ps -a` is empty after every test.

### PR 5 — `feat(cavr): behaviour evidence from a trace the package cannot write`

- Part: the verdict reads only the syscall trace; the package's stdout is shown as untrusted output, never parsed as
  a report (removes the stdout markers and `baseline_behaviors`' five metrics). Tracer (Q5): strace as container root
  with only `SYS_PTRACE`, `SETUID`, `SETGID` and `no-new-privileges`, `strace -f -u 10001`, trace in a root-only tmpfs;
  package code as UID 10001. Trace SHA-256 in the evidence.
- Tests first (Docker): a package printing a fake report is ignored; a package writing to the trace directory gets
  `EACCES`, recorded; a trace without the harness's exit line -> UNRESOLVED; every package process in the trace has
  UID 10001 (`test_package_code_never_runs_as_root`); unit: report markers in stdout change nothing.
- Acceptance: the M1 "report forgery" item is closed with a test.

### PR 6 — `feat(cavr): install the verified wheels and import the project's entry modules in the sandbox`

- Part: a new trusted harness (mounted read-only) installs exactly the verified tree offline (rule 6) into a tmpfs
  target and imports the contract's entry modules. Old `harness.py` is deleted.
- Tests first: unit — the generated hash file holds exactly the tree's sha256 values; a wheel whose quarantine bytes
  changed is refused before mounting. Docker (wheels built in `tmp_path`): benign wheel -> clean trace, exit 0; import
  that connects to `198.51.100.24:443` -> failed connect recorded; import that reads `~/.aws/credentials` -> secret
  access recorded; a `.pth` file runs at start-up and is recorded.
- Acceptance: the M1 "`harness.py` reports `test_passed: True` without importing" item is closed.

### PR 7 — `fix(cavr): every attempted sensitive syscall becomes an event`

- Part (review of PRs 3-6, MAJOR 1): strace gets `-yy` and a larger `-s`, and an event whose path or address is
  truncated (`"..."...`) or relative to a dirfd that cannot be resolved is unknown -> UNRESOLVED.
- Part: `runtime_monitor.normalize` keeps failed attempts with their errno; real endpoints from `sockaddr`
  (IPv4, IPv6, Unix); SECRET_ACCESS from the run's canary path set; harness processes excluded by PID from the trace,
  not by the substring `python`; unknown sensitive lines are counted and make the run UNRESOLVED. `normalizer.py` deleted.
- Tests first (recorded real traces): `connect … = -1 ENETUNREACH` is a NETWORK_CONNECT attempt; `openat` canary
  `= -1 EACCES` is a SECRET_ACCESS attempt; IPv6; `sendto`; `execve("/bin/sh")`; `clone` with and without `CLONE_THREAD`.
- Docker: only to record the traces once.

### PR 8 — `feat(cavr): observed events judged against the capability contract`

- Part: replaces `policy.verify_runtime` (hardcoded `PDF_MINIMUM_CAPABILITY`) with a check of each event against the
  contract's allowed scopes; an attempt counts like a success; an event type with no rule -> UNRESOLVED.
- Tests first: each capability allowed / denied / scoped; denied connect attempt is a violation; scoped network grant
  with matching and non-matching endpoint; harness PIDs excluded.
- Docker: no.

### PR 9 — `feat(cavr): escalated packages get one observed sandbox run`

- Part: PRs 3–8 plugged into the PR 2 interface for a baseline environment run, only for escalated packages (Q8).
  Verdict rule (Q8): VERIFIED only if the run completed within budget (20 s per run, 120 s per package), its trace is
  complete, and no event falls outside the contract; any violation -> REJECTED; anything incomplete -> UNRESOLVED with
  the reason. `gate_adapter` passes the deep analyzer when the engine and image check pass; otherwise UNRESOLVED
  "no isolation", as today. Deep time in `deep_analysis_ms` (NFR-4). Until PR 12 there is no frontier, so under the
  confirmed Q8 frontier rule an escalated package with a high-risk trigger in front of a reachable sink is incomplete
  -> UNRESOLVED (accepted). Packages that are not escalated are unaffected: they never reach the deep stage and keep
  their fast-gate verdict.
- Tests first: unit (fake runner) one test per clause of the rule (over budget, incomplete trace, out-of-contract
  event, all three satisfied); `test_escalated_package_with_an_unexplored_trigger_is_unresolved_until_the_frontier_exists`;
  `test_non_escalated_packages_never_reach_the_deep_stage` (deep analyzer spy not called, verdict identical to
  `deep=None`); Docker end-to-end: a wheel whose import exfiltrates a canary -> REJECTED through
  `asent gate`; a benign wheel with a reachable sink and a clean complete run -> VERIFIED.
- Acceptance: the M1 `escalation: "deep analysis required (M2)"` string is replaced by the deep verdict or a precise
  residual reason.

## Phase 3 — Counterfactual activation and causal graph (PR 10 – PR 14)

Exit check: env-, file-, time- and hostname-gated samples are clean in the baseline run and REJECTED in their
counterfactual run; the §6.6 three-package canary path is found; unexplored triggers make the verdict UNRESOLVED.

### PR 10 — `feat(cavr): trigger frontier with the design's predicate families and priority` (FR-12)

- Part: `trigger_discovery` gains hostname / user, platform, time / date comparisons, sleep, CI / container checks,
  cloud metadata address, file existence through `Path` objects; each trigger is linked to reachable sinks with the
  import closure from `reachability`; priority = sink_risk × reachability_confidence × novelty / estimated_run_cost
  (§6.3), each factor in the evidence. Legacy `triggers.py` deleted.
- Tests first: one positive and one negative sample per family; the §6.3 high / low examples rank as in the design;
  helper-call predicates stay `unsupported`; priority is deterministic.
- Docker: no.

### PR 11 — `feat(cavr): safe environment synthesis with per-run canaries`

- Part: for each trigger, an environment spec: env variable with a random canary, fake file under a tmpfs HOME,
  `--hostname`, time shift through libfaketime (`LD_PRELOAD` + `FAKETIME`, Q7; covers native code too). Canary
  registry per run.
- Tests first: each family's spec; `test_no_host_environment_value_reaches_a_run` (sets a fake host secret, asserts
  absent); canaries differ between runs; an unsupported trigger produces no spec and stays residual.
- Docker: one test that the spec is what the container sees.

### PR 12 — `feat(cavr): budgeted counterfactual activation loop` (FR-4)

- Part: §6.4 loop: highest-priority unexplored trigger -> synthesized environment -> fresh container -> merge events;
  newly seen predicates join the frontier; early stop on a decisive violation (-> REJECTED); budget 8 runs, 20 s per
  run, 120 s per package (Q8), overridable only by the base policy. The Q8 rule applies across all runs: VERIFIED only
  if every run completed within budget, every trace is complete and no event in any context is outside the contract;
  unexplored or unsynthesizable high-risk triggers are listed and make the verdict UNRESOLVED. Replaces
  `counterfactual.py`, the `sandbox.py` lab path, the old `capability_contract.infer`, and (with the legacy
  `SandboxRunner` and `docker/asent-sandbox/Dockerfile`, `[owner review: docker/]`) the old `harness.py`; the demo LOCAL lab node moves onto this path
  (`test_controlled_dormant_execution` re-pointed, `[owner review: tests/test_modules.py]`).
- Tests first: unit (fake runner) order follows priority, budget stops the loop, early stop, residuals in the verdict,
  a baseline that is not observed stops the loop as UNRESOLVED; Docker: an env-gated sample is clean in the baseline run
  and REJECTED in the counterfactual run; a file-gated and a time-gated sample likewise.
- Acceptance: activation rate and new sensitive paths per run are in the evidence (design §10.1).

### PR 13 — `feat(cavr): causal capability graph from real evidence` (FR-5)

- Part: graph from the tree (`depends_on`), scan and frontier (`conditioned_by`), trace (`spawns`, `reads`, `connects`),
  and canary flow (`derived_from`: a canary in a connect payload, argv or written file). Event -> package attribution
  by the file each traced `openat`/`execve` names, matched against each wheel's RECORD. Path query: secret source -> external sink across
  packages. Legacy `build_causal_graph` and its hardcoded nodes deleted.
- Tests first: the §6.6 example (A reads, B passes, C sends) found as one path across three packages; the same events
  in one package; a path with no canary is not a flow; graph JSON is deterministic.
- Docker: one end-to-end transitive sample.

### PR 14 — `feat(cavr): RESTRICTED verdict` (FR-14)

- Part: RESTRICTED when every violation is a capability the policy marks `restrictable`; the verdict carries the
  generated restriction (seccomp / network rules); `restriction_enforced` stays false, so the final gate gives REVIEW.
  Enforcing the restriction is future work (Q3).
- Tests first: restrictable-only -> RESTRICTED; any other violation -> REJECTED; final gate REVIEW.

## Phase 4 — Repair, re-verification, reconstruction and assurance (PR 15 – PR 18)

Exit check: a REJECTED demo pin (`pypdf==6.19.0`) yields a re-verified repair proposal (requirements, lockfile,
policy patch) for human approval; the proposal was never applied by CAVR; its certificate verifies.

### PR 15 — `feat(cavr): minimal safe repair candidates from real releases` (FR-7)

- Part: for a REJECTED package (advisory or behaviour): releases from the registry JSON, minus yanked, sdist-only and
  OSV-affected; constraints from every tree node's Requires-Dist; Z3 minimises
  w1·direct deps changed + w2·version distance + w3·call sites changed + w4·new risk (§6.9); levels 1–3; level 4 is
  future work (Q3). The result is a **proposal only** (Q9): a patch to requirements, lockfile and the policy's approved
  pins, for a person to approve in its own pull request; CAVR and the gate never apply it. `repair_engine.py` deleted;
  `repair.rank_repairs` reused or replaced.
- Tests first (recorded registry JSON): nearest safe patch chosen; affected and yanked versions excluded; unsatisfiable
  constraints -> UNRESOLVED "no safe candidate"; weights change the choice as expected; the project directory and
  policy file are unchanged after a repair run (`test_repair_never_applies_its_proposal`).
- Docker: no.

### PR 16 — `feat(cavr): re-verify each repair candidate in a fresh transaction` (FR-8)

- Part: the whole proposal (requirements, lockfile, policy patch; Q9) applied to a temporary copy of the project;
  full `verify_request` with a fresh quarantine directory and fresh sandbox, so the proposed policy goes through the
  requirement gate like any other; contract recomputed; deep analysis as in phases 2–3. Project tests (Q10): through
  SATRA's image builder public API (`backend/satra/project_image.py::prepare`, confirmed public with SATRA's owner
  first), SATRA not edited; if that is not possible, the verdict states "project tests not run" as a limitation and the
  proposal is never marked functionally verified. First candidate that passes everything becomes the proposal; failures
  recorded. `reverifier.py` deleted.
- Tests first: a candidate that fails OSV, one that fails behaviour, one that fails project tests are each rejected
  with the reason; the next is tried; nothing touches the original project directory; without the SATRA builder the
  limitation is in the verdict.
- Docker: yes for the behaviour and test parts.

### PR 17 — `feat(cavr): clean reconstruction from the trusted baseline` (FR-9)

- Part: from the base commit export and the re-verified proposal, a fresh environment gets exactly the verified tree
  (rule 6); every installed file's RECORD hash is checked; baseline digest = git tree ID + image ID + Python version.
  Output is the proposal patch plus this reconstruction record, as evidence for the human approval (Q9); nothing is
  applied to the trusted project. `reconstructor.py` deleted.
- Tests first: installed set equals verified set; one altered file -> UNRESOLVED; the patch applies cleanly to the
  base; the trusted project directory is unchanged byte for byte.
- Docker: yes.

### PR 18 — `feat(cavr): assurance certificate from real fields` (FR-10)

- Part: record hash covers every field (`ts`, `substep`); terminal hash after the final record; certificate lists
  baseline digest, artifact digests, contract obligations, exercised and unexercised conditions, deep runs (image ID,
  flags), repair and reconstruction results, residual uncertainty; JSON and SARIF.
- Tests first: changing any one field breaks `verify_chain`; certificate fields equal the verdict's values; a check
  that did not run is absent, never "passed".

## Phase 5 — Dashboard and evaluation (PR 19 – PR 21)

Exit check: every matrix row shows a real stage value or a dash; NFR guard tests pass; no legacy module remains;
the evaluation script writes the metrics table for the report from real runs.

### PR 19 — `feat(cavr): requirements matrix shows the real stage of each requirement`

- Part: rows FR-1..15, NFR-1..6 (Q11) with real module names, NFR-1 worded "package code never runs as root"; scope text
  from the design (Counterfactual Activation, Verified Repair & Recovery) with the "Future work" items marked as not
  done; remove the unreachable branches with hardcoded "OSV Clean" ticks. `CavrModule.tsx` as needed
  (`[owner review: frontend/src/components/CavrModule.tsx]`).
- Tests first: `test_cavr_frontend.py` render tests per row with and without the stage's data.

### PR 20 — `test(cavr): NFR guards and legacy removal check`

- Tests: no paid / LLM client imported anywhere in `backend/cavr/` (NFR-2); a recording transport sees only name and
  version (NFR-3); no remaining import of `resolver`, `reverifier`, `reconstructor`, `fixtures/scenarios`, `triggers`,
  `repair_engine`, `normalizer`, `inspector`.

### PR 21 — `feat(cavr): evaluation corpus, baselines and ablations` (design §10)

- Part: inert, synthetic samples only (benign-but-sensitive, env / file / time / hostname-gated, transitive,
  obfuscated, native wrapper, repairable, unresolved); baselines (existence, OSV only, static only, one normal run);
  ablations (no contract, no counterfactual, no graph, naive repair); a script that writes the metrics table for the
  report. No live malware (§16.2).
- Docker: yes.

## Future work (out of M2, Q3)

Stated as limitations in the report and on the dashboard, not implemented in M2:

- npm / JavaScript ecosystem (capture, registry, tree, contract, sandbox).
- eBPF / bpftrace observation; M2 uses strace only.
- Tree-sitter parsing (needed for npm; Python uses `ast`).
- Sigstore / provenance evidence.
- Level-4 repair: replacing a package by a different one through an API-slice adapter.
- RESTRICTED enforcement: the verdict and the generated restriction exist (PR 14); nothing enforces it, so the final
  gate gives REVIEW.

## Still open

- **SATRA image builder API** (Q10): confirm with SATRA's owner that `backend/satra/project_image.py::prepare` is a
  public API CAVR may call. Before PR 16.
- **Full-suite baseline**: measured before PR 1 (Maryam, 2026-11-22): 2282 passed, 8 skipped, 1 xfailed.
- **Demo pin data** (Q2): if `pypdf==6.21.4` gains an advisory or its wheel changes before PR 1 is recorded, stop and ask.

## Progress

### Phase 1 — Wiring
- [x] PR 1 orchestrator through `verify_request` + demo pin `pypdf==6.21.4` (branch `cavr-m2-phase1-wiring`, 2026-11-22; report notes Step M2-1)
- [x] PR 2 deep-analysis stage interface (branch `cavr-m2-phase1-wiring`, 2026-11-22; report notes Step M2-2)

### Phase 2 — Behaviour sandbox
- [x] PR 3 CAVR sandbox image `asent-cavr-sandbox:local` + identity check (branch `cavr-m2-sandbox`, 2026-11-23; report notes Step M2-7): own seccomp copy, the shared profile cannot start a container
- [x] PR 4 runner deadline / kill / limits (branch `cavr-m2-sandbox`, 2026-11-23; report notes Step M2-8): `sandbox_exec.run_container`
- [x] PR 5 trusted trace channel (package code never runs as root) (branch `cavr-m2-sandbox`, 2026-11-23; report notes Step M2-9): strace's stderr is the trace, `sandbox_trace.check_trace`
- [x] PR 6 wheel install + import harness (branch `cavr-m2-sandbox`, 2026-11-23; report notes Step M2-10): `sandbox_observe.observe`; exec tmpfs only for the install target; `harness.py` kept until PR 12 (`docker/asent-sandbox/Dockerfile` still copies it; review 2026-11-23); refused syscalls and ptrace checked (Step M2-11)
- [x] PR 7 normalisation v2 (branch `cavr-m2-deep`, 2026-11-23; report notes Step M2-12): `sandbox_events.py`; strace `-y -s 4096` with `DAC_READ_SEARCH`; pip's User-Agent replaced; `normalizer.py` deleted, `runtime_monitor.py` kept (LOCAL lab, PR 12)
- [x] PR 8 runtime contract check (branch `cavr-m2-deep`, 2026-11-23; report notes Step M2-13): `contract_check.py`; label scopes -> UNRESOLVED (D5); `policy.verify_runtime` kept for the LOCAL lab (PR 12)
- [ ] PR 9 one observed run for escalated packages

### Phase 3 — Counterfactual activation and causal graph
- [ ] PR 10 trigger frontier
- [ ] PR 11 environment synthesis (libfaketime, per-run canaries)
- [ ] PR 12 counterfactual loop
- [ ] PR 13 causal graph
- [ ] PR 14 RESTRICTED verdict

### Phase 4 — Repair, re-verification, reconstruction and assurance
- [x] PR 15 repair proposal (fast-first item 2, branch `cavr-m2-repair`, 2026-11-23): `repair_proposal.py`; `repair_engine.py` deleted; `repair.rank_repairs` and the orchestrator `_repair` kept until PR 12 (owner, 2026-11-23: the `cross_module` LOCAL-lab demo still uses them)
- [ ] PR 16 re-verification of the proposal — fast-gate part done with PR 15 (`verify_request` on a copy of the project, `reverifier.py` deleted); sandbox and project tests (Q10) open
- [ ] PR 17 clean reconstruction
- [ ] PR 18 assurance certificate

### Phase 5 — Dashboard and evaluation
- [ ] PR 19 requirements matrix
- [ ] PR 20 NFR guards + legacy removal check
- [ ] PR 21 evaluation corpus
