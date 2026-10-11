# CAVR study Q&A

## Batch A — steps 1-3: C1 capture and C2 requirement gate (2026-10-10)

### Q1. How does a `pip install X==Y` command become a capture record?

`parse_pip_command` in `backend/cavr/capture.py` writes down what was asked for; nothing is
downloaded or run.

1. It splits the command into words and checks it really is pip (`pip`, `pip3`, `python -m pip`).
2. It finds the subcommand. Only `install` is captured.
3. It sorts every other word: a named package goes into `requirements` (name, version, `pinned`);
   a URL, `git+...`, local path, `-e` or custom index goes into `unsupported`; a malformed spec or a
   missing `-r` file goes into `errors`. `-r` files are opened and sorted the same way; `-c` lines go
   into `constraints`.
4. `complete` is true only when `unsupported` and `errors` are both empty.

Example: `pip install requests==2.31.0 ./local` gives one requirement (`requests`, `2.31.0`, pinned),
one `unsupported` entry ("local path requirement"), and `complete: False`.

### Q2. How does a requirements.txt edit become a capture record?

`backend/cavr/manifest_parser.py` compares the file before and after the edit.

1. `snapshot_requirements` records the file's text and the SHA-256 of its bytes, once before and once
   after.
2. `capture_requirements_edit` compares the two. A line is identified by package name plus marker.
3. Each difference is labelled ADDED, VERSION_CHANGED, MODIFIED (same version, different extras or
   `--hash`) or REMOVED.
4. `requirements` holds only the added and changed lines, because those are what must be verified.
   Unreadable lines go into `errors`; `complete` is set as in Q1.

Example: `a==1` becomes `a==1` + `b==2`. The record has one change (ADDED `b`), `requirements` is
`b==2`, and `complete` is true.

### Q3. How does the requirement gate decide PERMITTED / BLOCK / UNRESOLVED?

`evaluate_requirement` in `backend/cavr/requirement_gate.py` checks rules in order; the first that
applies decides:

1. No policy, or a broken policy -> UNRESOLVED.
2. The request is not a named package -> UNRESOLVED.
3. Name on the denylist -> BLOCK.
4. Not pinned to one exact version with `==` -> BLOCK.
5. Name and version not on the allowlist -> BLOCK.
6. A lockfile exists but is broken -> UNRESOLVED; it exists without this name and version -> BLOCK.
7. Nothing above applied -> PERMITTED.

BLOCK means the policy was read and says no; UNRESOLVED means the gate could not tell. For a whole
record, `evaluate_capture` gives BLOCK if any requirement is blocked, else UNRESOLVED if the record is
incomplete, else PERMITTED. Examples with the shipped `project_policy.json`: `requests==2.31.0` is
PERMITTED; `requests-security==2.31.0` is BLOCK (denylist); `requests==2.31.0` plus a `git+` URL is
UNRESOLVED.

### Q4. What were the two fail-open paths fixed in `31dd229`?

"Fail-open" means something that should have been stopped came out as PERMITTED.

1. **Malformed record** (`evaluate_capture` in `requirement_gate.py`). If `requirements` was not a
   list, the gate treated it as empty, found nothing to judge, and permitted it. It also believed
   `complete: True` even when the record listed unsupported entries.
   Example: `{"requirements": ("zzz==1",), "complete": True}` was PERMITTED; it is now UNRESOLVED.
   The gate now works out completeness itself from `unsupported` and `errors`.
2. **Hidden duplicate line** (`read_manifest` in `manifest_parser.py`). The comparison keeps one line
   per name plus marker, so a second line for the same package overwrote the first.
   Example: adding `a==2.0; python_version >= "3"` above the existing `a==1.0; python_version >= "3"`
   showed no change and `complete: True`. Two differing lines for the same package are now an error,
   so the result is UNRESOLVED.

## Batch B — steps 4-8: C3 fast gate on real PyPI artifacts (2026-10-10)

Each stage answers OK, REJECTED or UNRESOLVED. VERIFIED is the final verdict of the whole pipeline
(plan step 11, not built yet): it needs every stage to answer OK.

### Q1. How does CAVR download a package from PyPI and prove the file is genuine?

`fetch_artifact` in `backend/cavr/pypi_client.py`.

1. It asks PyPI for the release description: `https://pypi.org/pypi/{name}/{version}/json`. That lists
   every file of the release with its SHA-256.
2. `select_wheel` picks the wheel that fits this Python. The file URL must be on
   `https://files.pythonhosted.org`.
3. It downloads the wheel into a quarantine folder, with a size cap and a time limit.
4. `_sha256_of_file` reads the saved file back and computes its SHA-256.
5. That hash is compared with the one PyPI listed. One changed byte gives a different hash.

- OK: the real `pypdf-6.19.0` wheel hashes to `7e5d6e73…e48d14`, the same as PyPI's value.
- REJECTED (`HASH_MISMATCH`): the same wheel with one bit flipped; it is kept as `….whl.rejected`.
- UNRESOLVED: a timeout, a yanked release, or a release with only a `.tar.gz` (`NO_WHEEL`).

### Q2. How does CAVR build the dependency tree?

`build_tree` in `backend/cavr/dep_tree.py`, using `read_wheel` in `backend/cavr/wheel_meta.py`.

1. Start with the requested package. Download and hash it (Q1).
2. `read_wheel` opens the wheel as a zip (nothing is extracted) and reads its `METADATA` file. The
   `Requires-Dist` lines there are the package's own list of dependencies.
3. A line with a condition that is false on this machine (for example `sys_platform == "win32"` on
   Linux) is skipped and recorded under `excluded`.
4. Each remaining dependency is pinned to the one version in the project lockfile, then steps 1-4
   repeat for it. A package is loaded once, so a cycle ends.
5. `subtree_digest` makes one SHA-256 over all (name, version, file hash) entries plus the edges.

- OK: `app 1.0 -> mid 1.5 -> leaf 2.0`, all three in the lockfile and all three hashes match.
- REJECTED: the same tree with the `leaf` wheel tampered; one bad node rejects the whole tree.
- UNRESOLVED (`CHILD_NOT_PINNED`): `app` needs `leaf>=1` and the lockfile has no `leaf`.

### Q3. How does the OSV check decide a version is affected?

`check_advisories` and `match_advisory` in `backend/cavr/advisories.py`.

1. It asks OSV (live, or a saved answer at most 30 days old) for advisories about this name and version.
2. Each advisory has ranges written as events: `introduced` starts the affected range, `fixed` ends
   it (the fixed version itself is safe), `last_affected` ends it (that version is still affected).
3. `match_advisory` walks the events with `package_records.affected` and says AFFECTED, NOT_AFFECTED
   or UNKNOWN.
4. Any AFFECTED advisory rejects the package. If nothing is affected but something is UNKNOWN, or
   there is no usable answer, the result is UNRESOLVED.

Example range: introduced `0`, fixed `6.19.0`. Then `6.18.1` is affected and `6.19.0` is not.

- OK (`NO_KNOWN_VULNERABILITY`): pypdf 6.19.0; OSV returned no advisory (recorded 2026-10-10).
- REJECTED (`KNOWN_VULNERABILITY`): pypdf 5.1.0; 97 advisories, for example `GHSA-php9-fj8v-98fj`.
- UNRESOLVED: offline with no saved answer, a saved answer 31 days old, or an advisory with only a
  GIT commit range (`RANGE_UNSUPPORTED`).

### Q4. What does the AST scan look for?

`scan_wheel` in `backend/cavr/ast_scan.py`. It reads the code as text and never runs it.

1. Every `.py` file in the wheel is parsed into a syntax tree with Python's `ast` module.
2. Sinks: calls that can do something sensitive, from the threat-repository rules, such as
   `subprocess.run`, `os.system`, `socket.create_connection`, `eval`. Also when hidden behind an
   import alias (`from subprocess import run`).
3. Triggers: an `if` that depends on an environment variable or a file existing and has a sink
   inside, for example `if os.getenv("DEPLOY_ENV") == "prod": socket.create_connection(...)`.
4. Things it cannot read: files with syntax errors, native code (`.so`, `.pyd`), `.pyc` files, and
   `.pth` files with `import` lines (Python runs those at every start).

The result says whether all the code was read, not whether it is safe. The sinks are evidence that
step 11 will judge against the project's own call sites.

- OK (`SCAN_COMPLETE`): pypdf 6.19.0; 59 files read, 2 sinks listed (`pypdf/filters.py` lines 774, 804).
- REJECTED (`UNSAFE_PATH`): a wheel with an entry named `../evil.py`.
- UNRESOLVED: a file with a syntax error, or a wheel containing a `.so` (`COMPILED_CODE_NOT_SCANNED`).

## Batch C — steps 9-11: C4 contract, verdict cache, one pipeline (2026-10-10)

Answers describe the code after the batch review fix (`002a69c`).

### Q1. How is the capability contract built from the project's real imports and call sites?

`extract_project_context` (`context_extractor.py`), then `infer_capability_contract`
(`capability_contract.py`). Files are only parsed with `ast`; nothing is run.

1. Read every `.py` file of the project. A file that cannot be read or parsed -> UNRESOLVED.
2. Per file, note what each import binds: after `from pypdf import PdfReader as R`, `R` means
   `pypdf.PdfReader`. Every call through such a name is a call site: file, line, real name.
3. Ask the wheel which import names it provides (`top_level.txt`, else RECORD). The package name is
   never used as a guess: `invoice-tools` may install `invtools`.
4. Keep the imports and call sites for those names. None, or imported but never used -> UNRESOLVED
   `NO_CALL_SITE_AUTHORITY`.
5. Allowed = what the policy's `allowed_scopes` grants, minus what the threat-repo rule for the
   project's task denies. Everything else is denied. `digest` covers all of it plus the source hashes.

Example: InvoiceHub + pypdf 6.19.0 -> call sites `app/pdf_adapter.py:7 pypdf.apply_configuration`,
`:8 pypdf.PdfReader`; allowed `FILE_READ`, `FILE_WRITE`; denied `PROCESS_EXEC`, `NETWORK_CONNECT`.

### Q2. What are the 8 cache-key fields, and why each one?

`cache_key` in `verdict_cache.py`: the SHA-256 of these eight values. One missing -> no key, no lookup.

| Field | Why it is in the key |
|---|---|
| `ecosystem` | The same name can exist outside PyPI; only PyPI is verified. |
| `name` | Which package (`Foo_Bar` = `foo-bar`). |
| `version` | Which release (`1.0` = `1.0.0`). |
| `artifact_sha256` | The exact bytes downloaded; a tampered or re-uploaded file is a new key. |
| `subtree_digest` | Every dependency under it and its hash. |
| `contract_digest` | How this project uses it and what is allowed; includes the source hashes. |
| `policy_version` | Digest of the policy; a policy edit must not reuse old verdicts. |
| `analyzer_version` | Pipeline + scanner version + sink-rule digest; new rules must re-judge. |

Example: change `jbig2dec_binary=None` in the project -> `contract_digest` changes -> cache miss.

### Q3. How does `verify_request` run C1 -> C4 end to end?

`verify_request(request, project_dir, policy, store)` in `backend/cavr/pipeline.py`:

1. C1 capture: `pip install pypdf==6.19.0` becomes a record (`parse_pip_command`).
2. C2 gate: policy, allowlist, lockfile (`evaluate_capture`). BLOCK stops here, before any download.
3. C3: download each wheel, SHA-256 it, compare with PyPI, follow `Requires-Dist` (`build_tree`).
4. C4 contract (Q1), then the cache lookup with the 8-field key (Q2).
5. OSV for every package of the tree, on every run, also on a cache hit (`check_advisories`).
6. Cache miss only: AST scan, then `judge_sinks` marks each sink allowed (`*` grant), switched off
   by the project's guard, unreachable from what the project imports, or reachable.
7. Verdict: REJECTED for a wrong hash or an affected version; UNRESOLVED when anything is unknown or
   a denied sink is reachable (`escalation: "deep analysis required (M2)"`); otherwise VERIFIED.

Every verdict has `fast_gate_ms`, `cache_hit`, `escalated`. Examples: Q4.

### Q4. One example of each verdict, and of a cache hit

Tests in `tests/test_cavr_pipeline.py`, with the real pypdf wheel and the InvoiceHub code.

- **VERIFIED** (`test_pypdf_6_19_0_is_verified_with_the_guard_evidence`): hash `7e5d6e73…e48d14`
  equals PyPI's, OSV lists nothing, and `PdfReader` is only used inside
  `with apply_configuration(jbig2dec_binary=None)`, so the two `subprocess.run` calls in
  `pypdf/filters.py` (774, 804) are `GUARD_DISABLED` evidence.
- **REJECTED** (`test_one_flipped_byte_is_rejected`): one bit of the served wheel flipped ->
  `HASH_MISMATCH`; the file is kept as `.rejected` and no scan runs.
- **UNRESOLVED** (`test_the_same_project_with_a_reader_outside_the_guard_is_unresolved_and_escalated`):
  one `PdfReader(path)` outside the guard -> both sinks `REACHABLE`, `SINK_REACHABLE`, `escalated: true`.
- **Cache hit** (`test_second_run_is_a_cache_hit_that_still_checks_osv`): the VERIFIED request twice;
  second run `cache_hit: true`, the scan ran once, OSV was asked twice, the wheel was hashed twice.

## Batch D — steps 12-14: pip wrapper, dashboard API, orchestrator (2026-10-11)

Steps 12 and 13 are committed (`1e17034`, `ca5a0e2`, review fix `fe9fd4f`). Step 14 is not implemented.

### Q1. How does the pip wrapper stop a real `pip install` before it runs?

It never starts pip until the pipeline has said VERIFIED. You run the wrapper instead of pip:
`python -m backend.cavr.pip_shim install pypdf==6.19.0`. In `backend/cavr/pip_shim.py`, `main`:

1. `split_arguments` takes out the wrapper's own options (`--install`, `--cavr-project`, ...).
2. `verify_request(["pip", ...], project, policy, store)` checks the request (gate, hash, tree, OSV, contract, scan).
3. It prints the verdict and evidence. Exit code 0 VERIFIED, 1 REJECTED, 2 UNRESOLVED, 3 BLOCK.
4. Without `--install` it stops here. With `--install`, and only on VERIFIED, `install_plan` writes
   one line per verified file, `pypdf==6.19.0 --hash=sha256:7e5d6e73…8d14`, and `_install` runs
   `python -m pip install --require-hashes --no-deps ... -r <that file>`.

What you typed is never given to pip, so `--index-url` or `-e` cannot reach it. pip downloads again,
but `--require-hashes` refuses any file whose SHA-256 is not the verified one.
Example: `install reqeusts==2.31.0 --install` -> BLOCK, exit 3, nothing downloaded, pip not called
(`test_install_on_block_never_invokes_pip_and_downloads_nothing`).
Limit: nothing puts the wrapper on `PATH` as `pip`. A plain `pip install` typed in a shell is not intercepted.

### Q2. How does the dashboard now get real verdicts instead of fixture data?

`backend/cavr/api.py` no longer computes anything. `POST /api/cavr/intercept` builds the request
`pip install <package>==<version>` (`pip_request`) and `run_verification` calls the same
`verify_request` as the wrapper, for the project `backend/cavr/sample_project` and the policy
`project_policy.json`. `verdict_events` then turns the verdict into one event per stage that ran
(gate, artifact / tree / OSV, cache, contract / scan), copying the values. Before, the "hash" was the
SHA-256 of a source string in `fixtures/scenarios.py`; that module is not imported any more.

The five scenarios in `SCENARIOS` are real requests. Two only change the network: `TamperingTransport`
flips one bit of the downloaded wheel, `OfflineTransport` fails every request. The pipeline runs
unchanged, so a scenario can only make a verdict worse; such runs are not logged or cached.
Example: `pypdf==5.1.0` passes the gate (`pypdf>=5,<7`), the real wheel's hash matches, and OSV
rejects it with 97 advisories, one of them `GHSA-7hfw-26vp-jp8m`
(`test_pypdf_5_1_0_is_rejected_by_osv_with_the_recorded_advisory_ids`).
Limit: the chips on the page are in `frontend/src/components/CavrModule.tsx` (not edited), so the
page still sends the five old package names; the new scenarios run through `POST /api/cavr/run?scenario=<id>`.

### Q3. How does the orchestrator use the new pipeline?

It does not yet. Step 14 was stopped before any code change, so `backend/cavr/analyzer.py::analyze`
is the old code: it reads the wheel named in `dependencies.lock.json` from disk, checks its hash
against the recorded registry response, and does its own contract, scan, OSV and cache. It does not
call `verify_request`.

Why it stopped: for the safe scenario the only advisory data `analyze()` has is PyPI's advisory list
(`advisories/registry-f9283cc3….json`). `analyze()` accepts that; the pipeline does not, because that
list has no version ranges to check. Measured on 2026-10-10:
`OSV().query("pypdf", "6.19.0")` -> available, mode `PYPI ADVISORY METADATA (dated)`;
`check_advisories("pypdf", "6.19.0", ROOT / "advisories")` -> UNRESOLVED `ADVISORIES_UNAVAILABLE`.
So delegating would turn the safe scenario from VERIFIED into UNRESOLVED and fail
`tests/test_modules.py::test_cavr_safe_cache_and_advisory`, which the plan says to ask about first.
The four options (A-D) are in `cavr-report-notes.md`, section "Step 14"; the decision is open.

## Batch E — demo polish: chips, timeline, metrics, advisory lists, tampered wheel (2026-10-11)

Six commits, `384ec4f` to `cdbfa27`, and one review fix commit after them. Recorded outputs of the six cases are in `docs/cavr-demo.md`.

### Q1. How do the six chips on the page reach the real pipeline?

The page no longer knows any package name. `CavrModule.tsx` asks `GET /api/cavr/scenarios` and draws one chip per
entry (`cavr/ScenarioChips.tsx`). A click calls `runScenario`, which sends `POST /api/cavr/run?scenario=<id>`.
In `backend/cavr/api.py`, `run_scenario_endpoint` looks the id up in `SCENARIOS`, builds
`pip install <package>==<version>` and starts `run_verification`, which calls the same `verify_request` as the pip wrapper.
The page then reads the events of the run and `GET /api/cavr/proof/<run id>`.

Example: chip "4. left-pad 1.0 (not allowed)" -> `pip install left-pad==1.0` -> BLOCK `NOT_ON_ALLOWLIST` in 2.17 ms,
nothing downloaded (`test_left_pad_is_blocked_as_not_on_the_allowlist_before_any_download`).
Chip 2 is the same request as chip 1. It is a cache hit only because chip 1 stored an analysis; clicked first it is a miss.
`expected_status` in `SCENARIOS` is text for the chip and is never used to decide anything.

### Q2. How does the page show "—" for something that was not computed?

The backend says what was computed. `api.stage_summary(verdict)` returns six stages (capture, gate, artifact, cache,
analysis, verdict). Each has a list of `{label, value}` copied from the verdict, and `ran`, which is true when at least
one value is not `None`. It is served as `stages` in the proof. The same rule holds in the tabs: "no sink call found"
is printed only when a sink judgement exists, and an advisory count only when OSV answered (`api._affected_count`).
The page prints every value through `shown()` in `cavr/types.ts`: `None` becomes `NOT_COMPUTED`, the dash.
`cavr/ExpandableStep.tsx` draws one stage; a stage with `ran: false` says "did not run".

Example: for the BLOCK of `left-pad`, stages artifact, cache and analysis have `ran: false` and only dashes; the proof
drawer shows a dash for both hashes and for the hash result. Before, it printed "VERIFIED MATCH" for every run.
There is no time per stage because the pipeline measures only `fast_gate_ms` for the whole request.

### Q3. Why is `fast_gate_ms` reported per verdict, and what is `NOT_REACHED`?

One median over all logged verdicts was 2.72 ms on the first demo run, because half the rows were BLOCKs that take
about 2 ms and download nothing. `pipeline.metrics(store)` now groups the times of `verdict_log` three ways:
by status (VERIFIED / REJECTED / BLOCK / UNRESOLVED), by cache lookup, and by the pair. Each group has `count`,
`p50`, `p95` (nearest rank, `_nearest_rank`). A group with no rows has `None`, shown as a dash, not 0.

The cache lookup of a request is written to the log by `pipeline.cache_lookup_of`: `HIT` (every package's analysis
came from the cache), `MISS` (a package reached the lookup and was not served from it), `NOT_REACHED` (a BLOCK or a
failed download: nothing was looked up). So there are two hit rates: hits / all verdicts, and hits / (hits + misses).
A `MISS` does not mean the scan ran: `pypdf==5.1.0` is a MISS that OSV rejects before the scan.

Example from the recorded run: VERIFIED p50 3912.65 ms over 3 requests; BLOCK 2.17 ms over 1; 2 hits of 4 lookups.

### Q4. How is a list of 97 advisories shown?

As the count and the first three ids, with the whole list one click or one option away.
`advisories.summarise_ids(ids)` makes `A, B, C and 94 more`; `FIRST_IDS = 3`. It is used in the reason of
`check_advisories`, in the wrapper line (`pip_shim._render_package`) and in `resolution.advisory_summary` of the API.
The evidence is never shortened: `affected` in the verdict still holds all 97 with aliases and fixed versions.

Where the whole list is: on the page, the "OSV advisories" card in the Overview tab (`cavr/AdvisoryList.tsx`) has a
closed section "Show all 97 advisories" and a link to the proof JSON; in the terminal, `--cavr-json`.
Example: `advisories: pypdf 5.1.0 KNOWN_VULNERABILITY: 97 advisories: GHSA-23w6-3w8w-8484, GHSA-248m-82v9-q6g6,
GHSA-2q4j-m29v-hq73 and 94 more (every id: --cavr-json)`.

### Q5. Why can the tampered-wheel case no longer delete the genuine pypdf wheel?

Because it no longer works in the same directory. After a hash mismatch `pypi_client.fetch_artifact` keeps the bad
file as `<name>.rejected` and removes an older file of the same name from that directory (it is not what the registry
serves now). The demo run used the real quarantine, so that older file was the genuine wheel of case 1.
Now `api.demo_quarantine_dir(condition)` gives a demo run its own directory, `<quarantine>-demo/tampered_wheel/`,
and `verify_dashboard_request` passes it to the pipeline. The tampered file is the demo's own download.

Example (recorded): the genuine wheel has SHA-256 `7e5d6e73…8d14` before and after case 5, with the same modification
time and inode; the rejected file `a52a19f9…e7b9` is in `quarantine-demo/tampered_wheel/`.
Test: `test_a_tampered_run_in_the_middle_of_a_real_run_does_not_change_the_real_verdict` (before the fix the real run
ended UNRESOLVED `ARTIFACT_CHANGED`).

## Batch F — the repair integration test (2026-10-11)

### Q1. Why did `test_cavr_repair_invalidates_satra_then_reverifies` fail with BLOCK instead of ACCEPT?

Because CAVR could not see that the project uses pypdf once the PDF code moved into a vendored file, so the repair was
never applied. The scenario `cross_module` replaces `app/pdf_adapter.py` with one line,
`from vendor.invoice_pdf_lab import extract_invoice_text`. The call `PdfReader(...)` is then in `vendor/`, not in `app/`.
The older contract (`capability_contract.infer`) takes its call sites from the orchestrator's
`ContextService.dependency_context`, which reads only `app/*.py`. It found no pypdf call, so the contract was
`insufficient` and every package got "Capability contract lacks task/call-site authority" (UNRESOLVED).
The first analysis was still REJECTED (the sandbox saw the lab file send the canary). The repair then swapped in
`vendor/invoice_pdf_safe.py` and re-checked it: CAVR said UNRESOLVED again, for the same reason. The service applies a
repair only when the re-check is VERIFIED, so the run stayed at BLOCK and no `repair.applied` event was written.

The fix is `capability_contract.use_through_local_artifacts`: it follows the chain in the real files and needs all four
links: the lock holds pypdf and a LOCAL `.py` file with the locked SHA-256; a file in `app/` imports it; the application
calls the imported name; that file calls pypdf. Example: `app/pdf_adapter.py:1` imports, `app/main.py:87` calls,
`vendor/invoice_pdf_safe.py` calls `PdfReader`. One link missing -> `[]` -> still UNRESOLVED.
