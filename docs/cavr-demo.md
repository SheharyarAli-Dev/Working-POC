# CAVR mid demo script

Seven cases, each through the one real verification path (`backend/cavr/pipeline.py::verify_request`):
real PyPI downloads, real SHA-256, real OSV. Nothing in this script uses fixture data.

Every block marked **Recorded output** is the real output of the command above it, run on
2026-10-11 (local time) at commit `79f8c49`, Python 3.14.4, WSL2, with internet access.
Lines that will differ on your run are listed under each case. One recorded line is shortened
and marked as such.

| # | Case | Entry point | Expected |
|---|---|---|---|
| 1 | `pypdf==6.19.0` | pip wrapper | VERIFIED, exit 0 |
| 2 | the same again | pip wrapper | VERIFIED, `cache_hit: True` |
| 3 | `pypdf==5.1.0` | pip wrapper | REJECTED `KNOWN_VULNERABILITY` with OSV ids, exit 1 |
| 4 | `left-pad==1.0` (not on the allowlist) | pip wrapper | BLOCK `NOT_ON_ALLOWLIST`, exit 3, nothing downloaded |
| 5 | tampered wheel | dashboard API | REJECTED `HASH_MISMATCH` |
| 6 | network unavailable | pip wrapper (6a) and dashboard API (6b) | UNRESOLVED `REGISTRY_UNAVAILABLE`, exit 2 |
| 7 | the dashboard view | browser | see case 7; **the page cannot start cases 1, 3, 5 and 6 itself** |

Read "Things that did not behave as expected" at the end before you present.

---

## 0. Before the demo

Needs: the repository's `.venv`, Node.js (for the dashboard build), internet access.
Use two terminals, both in the repository root.

### Terminal A: set-up (once)

```bash
cd /home/dell/Working-POC

# A separate data directory for the demo: its own verdict cache, verdict log and quarantine.
export ASENT_DATA=$PWD/runtime-demo
rm -rf runtime-demo            # start empty, so case 1 is a cache miss

# The wrapper, pointed at the same project and policy the dashboard uses.
cavr() {
  .venv/bin/python -m backend.cavr.pip_shim \
    --cavr-project backend/cavr/sample_project \
    --cavr-policy backend/cavr/project_policy.json "$@"
}

# The dashboard bundle must contain the current tabs (frontend/dist is a local build, not in git).
npm --prefix frontend run build
```

- Project being protected: `backend/cavr/sample_project` (an invoice reader that uses pypdf inside
  `apply_configuration(jbig2dec_binary=None)`).
- Policy: `backend/cavr/project_policy.json` (approves `pypdf>=5,<7`; denylist includes `requests-security`).
- The wrapper only decides. It installs nothing unless `--install` is added (not used in this script).

### Terminal B: start the app (needed for cases 5, 6b and 7)

```bash
cd /home/dell/Working-POC
ASENT_DATA=$PWD/runtime-demo .venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Leave it running. `ASENT_DATA` must be the same directory as in terminal A, so the dashboard
reads the verdict cache and verdict log that the wrapper writes.

---

## Case 1 — `pypdf==6.19.0` -> VERIFIED

```bash
cavr install pypdf==6.19.0; echo "exit code: $?"
```

**What it shows:** C1 capture, C2 gate, C3 real download + SHA-256 against the registry + tree + OSV,
C4 contract from the project's call sites, AST scan, sink reachability, verdict.

**Expected:** `CAVR verdict: VERIFIED`, `cache_hit: False`, `HASH_MATCH` with the same SHA-256 on
both lines, two sinks `GUARD_DISABLED`, `cache: MISS, stored`, exit code 0.

**Recorded output:**

```text
CAVR verdict: VERIFIED
  stage: verdict   rule: ALL_CHECKS_PASSED
  reason: 1 requested packages verified: pypdf==6.19.0
  request: pip install pypdf==6.19.0
  fast_gate_ms: 3354.26   cache_hit: False   escalated: False
  gate: PERMITTED (ALLOWED)   policy version: e4b357a45bb7400290f240991bbe174606fafa750e9fd08dba7fb18c0984fc46
package pypdf==6.19.0: VERIFIED (verdict / ALL_CHECKS_PASSED)
  reason: hash, tree, advisories and contract checked; 2 sink calls found; none is both denied by the contract and reachable from the project
  artifact: pypdf-6.19.0-py3-none-any.whl HASH_MATCH
    sha256 7e5d6e730e7dae87d560a2cee218b852f6498c8be61966f3cd02ead971e48d14
    registry 7e5d6e730e7dae87d560a2cee218b852f6498c8be61966f3cd02ead971e48d14
  tree: TREE_BUILT, 1 file(s), subtree digest 00e26bfd4d0fac2afad4f9e7816f9615e090a2d65e3ffdeacadc8d477762238d
    pypdf==6.19.0 sha256 7e5d6e730e7dae87d560a2cee218b852f6498c8be61966f3cd02ead971e48d14
  contract: CONTRACT_INFERRED, 4 call site(s), digest 6dac79316ba769a26d0c3bb448c55b3b37fcadee2c26b6acc8ccf50d9e1e07ce
  advisories: pypdf 6.19.0 NO_KNOWN_VULNERABILITY
  scan: pypdf SCAN_COMPLETE (59 Python files)
  sink: pypdf/filters.py:774 subprocess.run GUARD_DISABLED
  sink: pypdf/filters.py:804 subprocess.run GUARD_DISABLED
  cache: MISS, stored
install: not requested; nothing was installed (run again with --install after a VERIFIED verdict)
exit code: 0
```

**Will differ:** `fast_gate_ms`. The policy version changes if `project_policy.json` is edited, the
contract digest if the sample project's source changes.
**Could differ one day:** if OSV publishes an advisory for 6.19.0, the correct answer becomes
REJECTED `KNOWN_VULNERABILITY`.

**Points to say:** the SHA-256 is computed from the downloaded bytes and equals PyPI's; pypdf does
call `subprocess.run` twice, and both calls are switched off by the project's own guard, which is
why they are evidence and not a failure.

---

## Case 2 — the same again -> cache hit, with timing

```bash
cavr install pypdf==6.19.0; echo "exit code: $?"
```

**Expected:** VERIFIED again, `cache_hit: True`, last package line `cache: HIT`, everything else
identical to case 1.

**Recorded output:**

```text
CAVR verdict: VERIFIED
  stage: verdict   rule: ALL_CHECKS_PASSED
  reason: 1 requested packages verified: pypdf==6.19.0
  request: pip install pypdf==6.19.0
  fast_gate_ms: 2037.57   cache_hit: True   escalated: False
  gate: PERMITTED (ALLOWED)   policy version: e4b357a45bb7400290f240991bbe174606fafa750e9fd08dba7fb18c0984fc46
package pypdf==6.19.0: VERIFIED (verdict / ALL_CHECKS_PASSED)
  reason: hash, tree, advisories and contract checked; 2 sink calls found; none is both denied by the contract and reachable from the project
  artifact: pypdf-6.19.0-py3-none-any.whl HASH_MATCH
    sha256 7e5d6e730e7dae87d560a2cee218b852f6498c8be61966f3cd02ead971e48d14
    registry 7e5d6e730e7dae87d560a2cee218b852f6498c8be61966f3cd02ead971e48d14
  tree: TREE_BUILT, 1 file(s), subtree digest 00e26bfd4d0fac2afad4f9e7816f9615e090a2d65e3ffdeacadc8d477762238d
    pypdf==6.19.0 sha256 7e5d6e730e7dae87d560a2cee218b852f6498c8be61966f3cd02ead971e48d14
  contract: CONTRACT_INFERRED, 4 call site(s), digest 6dac79316ba769a26d0c3bb448c55b3b37fcadee2c26b6acc8ccf50d9e1e07ce
  advisories: pypdf 6.19.0 NO_KNOWN_VULNERABILITY
  scan: pypdf SCAN_COMPLETE (59 Python files)
  sink: pypdf/filters.py:774 subprocess.run GUARD_DISABLED
  sink: pypdf/filters.py:804 subprocess.run GUARD_DISABLED
  cache: HIT
install: not requested; nothing was installed (run again with --install after a VERIFIED verdict)
exit code: 0
```

**Timing on the recorded run:** 3354.26 ms (miss) against 2037.57 ms (hit).

**Be exact about what the hit saves.** A cache hit skips the AST scan and the sink judgement only.
The wheel is downloaded and hashed again, the tree and the contract are rebuilt (they are fields
of the cache key), and OSV is asked again (advisories change while the file does not). Most of
both times is network, so the difference varies from run to run; do not promise a fixed speed-up.

---

## Case 3 — `pypdf==5.1.0` -> REJECTED with the OSV ids

```bash
cavr install pypdf==5.1.0; echo "exit code: $?"
```

**Expected:** gate `PERMITTED` (the policy allows `pypdf>=5,<7`), artifact `HASH_MATCH` (it is the
genuine 5.1.0 wheel), then `CAVR verdict: REJECTED`, stage `advisories`, rule `KNOWN_VULNERABILITY`,
advisory ids in the reason, exit code 1.

**Recorded output** (the `advisories:` line lists all 97 ids on one line; it is shortened here):

```text
CAVR verdict: REJECTED
  stage: advisories   rule: KNOWN_VULNERABILITY
  reason: pypdf==5.1.0: pypdf 5.1.0 is affected by 97 known advisories: GHSA-23w6-3w8w-8484, GHSA-248m-82v9-q6g6, GHSA-2q4j-m29v-hq73, GHSA-2rw7-x74f-jg35, GHSA-3crg-w4f6-42mx ...
  request: pip install pypdf==5.1.0
  fast_gate_ms: 8889.56   cache_hit: False   escalated: False
  gate: PERMITTED (ALLOWED)   policy version: e4b357a45bb7400290f240991bbe174606fafa750e9fd08dba7fb18c0984fc46
package pypdf==5.1.0: REJECTED (advisories / KNOWN_VULNERABILITY)
  reason: pypdf 5.1.0 is affected by 97 known advisories: GHSA-23w6-3w8w-8484, GHSA-248m-82v9-q6g6, GHSA-2q4j-m29v-hq73, GHSA-2rw7-x74f-jg35, GHSA-3crg-w4f6-42mx ...
  artifact: pypdf-5.1.0-py3-none-any.whl HASH_MATCH
    sha256 3bd4f503f4ebc58bae40d81e81a9176c400cbbac2ba2d877367595fb524dfdfc
    registry 3bd4f503f4ebc58bae40d81e81a9176c400cbbac2ba2d877367595fb524dfdfc
  tree: TREE_BUILT, 1 file(s), subtree digest 724a6fc8a993064e5b2900af588536d1710f877557e42f48b369ea8b010884ef
    pypdf==5.1.0 sha256 3bd4f503f4ebc58bae40d81e81a9176c400cbbac2ba2d877367595fb524dfdfc
  contract: CONTRACT_INFERRED, 4 call site(s), digest 6dac79316ba769a26d0c3bb448c55b3b37fcadee2c26b6acc8ccf50d9e1e07ce
  advisories: pypdf 5.1.0 KNOWN_VULNERABILITY (GHSA-23w6-3w8w-8484, GHSA-248m-82v9-q6g6, ... [SHORTENED IN THIS FILE: 97 ids in the real output, among them GHSA-7hfw-26vp-jp8m] ..., PYSEC-2026-4160)
  cache: MISS
install: not requested; nothing was installed (run again with --install after a VERIFIED verdict)
exit code: 1
```

**Will differ:** `fast_gate_ms`; the number of advisories (97 on the recorded run) grows when OSV
publishes more.

**Points to say:** the allowlist let it through and the file is genuine; it is the advisory check,
with OSV's version ranges evaluated for 5.1.0, that rejects it. A REJECTED-by-advisory verdict is
not cached (`cache: MISS`, nothing stored).

---

## Case 4 — a package not on the allowlist -> BLOCK before any download

```bash
cavr install left-pad==1.0; echo "exit code: $?"
ls runtime-demo/cavr/quarantine        # proof that nothing was downloaded for it
```

**Expected:** `CAVR verdict: BLOCK`, stage `gate`, rule `NOT_ON_ALLOWLIST`, no `package` section
(no artifact, no tree), exit code 3, and no `left-pad` file in the quarantine directory.

**Recorded output:**

```text
CAVR verdict: BLOCK
  stage: gate   rule: NOT_ON_ALLOWLIST
  reason: left-pad is not on the project allowlist
  request: pip install left-pad==1.0
  fast_gate_ms: 1.42   cache_hit: False   escalated: False
  gate: BLOCK (NOT_ON_ALLOWLIST)   policy version: e4b357a45bb7400290f240991bbe174606fafa750e9fd08dba7fb18c0984fc46
install: not requested; nothing was installed (run again with --install after a VERIFIED verdict)
exit code: 3
pypdf-5.1.0-py3-none-any.whl
pypdf-6.19.0-py3-none-any.whl
```

The two files listed are the wheels of cases 1 and 3. 1.42 ms is the whole run: no network was used.

**Variants, same exit code 3** (not recorded for this file): `cavr install requests-security==2.31.0`
gives rule `DENYLIST`; `cavr install pypdf` (no version) gives rule `NOT_PINNED`.

---

## Case 5 — tampered wheel -> REJECTED on hash mismatch

This case runs through the dashboard API, because something has to sit between PyPI and CAVR to
change the file. The API's demo condition `tampered_wheel` wraps the real download and flips one
bit of the wheel on the way in; the pipeline then runs unchanged. Terminal B must be running.

Define two helpers in terminal A (once):

```bash
run_scenario() {
  curl -s -X POST "http://127.0.0.1:8000/api/cavr/run?scenario=$1" \
    | .venv/bin/python -c 'import json,sys; print(json.load(sys.stdin)["run_id"])'
}
show() {
  curl -s -N "http://127.0.0.1:8000/api/cavr/stream/$1" > /dev/null    # returns when the run has finished
  curl -s "http://127.0.0.1:8000/api/cavr/proof/$1" | .venv/bin/python -c '
import json, sys
p = json.load(sys.stdin); v = p["cavr_verdict"]
print("request:", p["request"])
print("verdict:", v["status"], "| stage:", v["stage"], "| rule:", v["rule"])
print("reason:", v["reason"])
print("demo condition:", p["demo_condition"])
print("hash expected (registry):", p["hash_comparison"]["declared_or_expected"])
print("hash of what arrived:    ", p["hash_comparison"]["actual_sha256"])
print("hash matches:", p["hash_comparison"]["matches"])
print("fast_gate_ms:", v["fast_gate_ms"], "| cache_hit:", v["cache_hit"], "| escalated:", v["escalated"], "| logged:", v["logged"])'
}
```

Then:

```bash
RUN=$(run_scenario tampered_wheel); echo "run id: $RUN"; show $RUN
sha256sum runtime-demo/cavr/quarantine/*.rejected     # the file that arrived, kept as evidence
```

**Expected:** `verdict: REJECTED | stage: artifact | rule: HASH_MISMATCH`; the registry hash is the
`7e5d6e73…` of case 1 and the arrived hash is different; `hash matches: False`; `logged: False`;
`sha256sum` of the `.rejected` file equals "hash of what arrived".

**Recorded output:**

```text
run id: cavr-1791664471231-e13240
request: pip install pypdf==6.19.0
verdict: REJECTED | stage: artifact | rule: HASH_MISMATCH
reason: pypdf==6.19.0: pypdf-6.19.0-py3-none-any.whl: SHA-256 of the downloaded file is a52a19f9f614cd13e3f7544c78e5a44fc0996507c8b1b620abd45da5d73ee7b9, the registry says 7e5d6e730e7dae87d560a2cee218b852f6498c8be61966f3cd02ead971e48d14
demo condition: {'id': 'tampered_wheel', 'description': 'one bit of every downloaded wheel is flipped between PyPI and CAVR'}
hash expected (registry): 7e5d6e730e7dae87d560a2cee218b852f6498c8be61966f3cd02ead971e48d14
hash of what arrived:     a52a19f9f614cd13e3f7544c78e5a44fc0996507c8b1b620abd45da5d73ee7b9
hash matches: False
fast_gate_ms: 1549.8 | cache_hit: False | escalated: False | logged: False
```

`sha256sum` on the recorded run:

```text
a52a19f9f614cd13e3f7544c78e5a44fc0996507c8b1b620abd45da5d73ee7b9  runtime-demo/cavr/quarantine/pypdf-6.19.0-py3-none-any.whl.rejected
```

**Will differ:** the run id and `fast_gate_ms`. The arrived hash is the same every time (the same
bit of the same file is flipped).

**Points to say:** this is a demo condition and the output says so. The condition only replaces
the transport, so it can cause a mismatch but can never produce a VERIFIED. Such runs are not
written to the verdict log (`logged: False`), so they are not in the report numbers.

---

## Case 6 — network unavailable -> UNRESOLVED

### 6a. Through the wrapper, with a real connection failure

The three variables send every HTTPS request to a local port where nothing listens, so the
connection is really refused. No demo switch is involved.

```bash
HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 ALL_PROXY=http://127.0.0.1:9 \
  cavr install pypdf==6.19.0; echo "exit code: $?"
```

**Expected:** `CAVR verdict: UNRESOLVED`, stage `artifact`, rule `REGISTRY_UNAVAILABLE`,
`cache_hit: False`, exit code 2. Not VERIFIED, although the same request was VERIFIED and cached
two cases ago.

**Recorded output:**

```text
CAVR verdict: UNRESOLVED
  stage: artifact   rule: REGISTRY_UNAVAILABLE
  reason: pypdf==6.19.0: cannot read the registry: ConnectError: [Errno 111] Connection refused
  request: pip install pypdf==6.19.0
  fast_gate_ms: 70.02   cache_hit: False   escalated: False
  gate: PERMITTED (ALLOWED)   policy version: e4b357a45bb7400290f240991bbe174606fafa750e9fd08dba7fb18c0984fc46
package pypdf==6.19.0: UNRESOLVED (artifact / REGISTRY_UNAVAILABLE)
  reason: cannot read the registry: ConnectError: [Errno 111] Connection refused
  artifact: None REGISTRY_UNAVAILABLE
    sha256 None
    registry None
  tree: REGISTRY_UNAVAILABLE, 0 file(s), subtree digest None
  advisories: pypdf 6.19.0 NO_KNOWN_VULNERABILITY
  cache: None
install: not requested; nothing was installed (run again with --install after a VERIFIED verdict)
exit code: 2
```

The `advisories` line is the dated OSV answer saved by cases 1 and 2 (OSV could not be reached
either). It does not rescue the verdict: without the file there is nothing to verify.

**Points to say:** the cache cannot turn "I could not download it" into VERIFIED, because the
SHA-256 of the downloaded file is one of the eight key fields. Unknown stays UNRESOLVED.

### 6b. Through the dashboard API

```bash
RUN=$(run_scenario network_off); echo "run id: $RUN"; show $RUN
```

**Expected:** `verdict: UNRESOLVED | stage: artifact | rule: REGISTRY_UNAVAILABLE`, both hashes
`None`, `logged: False`.

**Recorded output:**

```text
run id: cavr-1791664472814-24ceea
request: pip install pypdf==6.19.0
verdict: UNRESOLVED | stage: artifact | rule: REGISTRY_UNAVAILABLE
reason: pypdf==6.19.0: cannot read the registry: ConnectError: the network is off (dashboard demo condition)
demo condition: {'id': 'network_off', 'description': 'every request to PyPI fails and OSV is not asked live'}
hash expected (registry): None
hash of what arrived:     None
hash matches: False
fast_gate_ms: 3.96 | cache_hit: False | escalated: False | logged: False
```

`hash matches: False` here is misleading: no hash was computed, so it should read `None`
(see "Things that did not behave as expected", item 2).

---

## Case 7 — the dashboard view

Terminal B must be running and the bundle built (step 0). Open **http://127.0.0.1:8000** and go to
the CAVR module. Reload the page after cases 1-6 so it reads the current cache.

**Not checked in a browser.** What is written below was checked through the endpoints the page
calls (`/api/cavr/cache`, `/api/cavr/metrics`, `/api/cavr/intercept`, the stream and the proof) and
the page itself answered `200` with the newly built bundle. Do one dry run in the browser before
the demo.

### What the page can show today

1. **Cache box -> "Click to view".** The real verdict cache. After cases 1-6 it has one row
   (the box shows "1 pinned"). Recorded answer of `/api/cavr/cache`:

   ```text
   pypdf 6.19.0 VERIFIED 7e5d6e730e7dae87d560a2cee218b852f6498c8be61966f3cd02ead971e48d14 CAVR verdict cache 2026-10-10T20:33:48.163567+00:00
   ```

   One row only: 5.1.0 was rejected by an advisory (never cached), the BLOCK analysed nothing, and
   demo runs get no store.

2. **Evidence tab "Metrics".** The verdict log, which includes the wrapper runs of cases 1-4 and 6a
   because both use the same `ASENT_DATA`. Recorded answer of `/api/cavr/metrics` after cases 1-6
   and five chip clicks (newest first; columns: id, status, stage, rule, `fast_gate_ms`, cache hit, request):

   ```text
   {'verdicts': 10, 'cache_hits': 1, 'cache_hit_rate': 0.1, 'fast_gate_ms_p50': 2.72, 'fast_gate_ms_p95': 8889.56, 'by_status': {'BLOCK': 5, 'REJECTED': 1, 'UNRESOLVED': 2, 'VERIFIED': 2}}
   10 BLOCK gate DENYLIST 1.69 - | pip install requests-security==2.31.0
   9 BLOCK gate NOT_ON_ALLOWLIST 2.72 - | pip install invoice-utils==2.0.1
   8 BLOCK gate NOT_ON_ALLOWLIST 1.28 - | pip install dormant-exfil==1.2.0
   7 BLOCK gate DENYLIST 2.04 - | pip install reportlab-legacy==3.5.21
   6 UNRESOLVED artifact RELEASE_NOT_FOUND 1297.84 - | pip install pdf-clean-extractor==1.0.0
   5 UNRESOLVED artifact REGISTRY_UNAVAILABLE 70.02 - | pip install pypdf==6.19.0
   4 BLOCK gate NOT_ON_ALLOWLIST 1.42 - | pip install left-pad==1.0
   3 REJECTED advisories KNOWN_VULNERABILITY 8889.56 - | pip install pypdf==5.1.0
   2 VERIFIED verdict ALL_CHECKS_PASSED 2037.57 cache_hit | pip install pypdf==6.19.0
   1 VERIFIED verdict ALL_CHECKS_PASSED 3354.26 - | pip install pypdf==6.19.0
   ```

   Rows 1-5 are cases 1, 2, 3, 4 and 6a. Cases 5 and 6b are not there, as intended.
   Rows 6-10 are the five chips (next point).

3. **The five scenario chips.** They still send the old package names, and now get real verdicts.
   Recorded by sending each chip's request to `/api/cavr/intercept`:

   | Chip on the page | Request sent | Real verdict |
   |---|---|---|
   | 1. Approved Benign | `pip install pdf-clean-extractor==1.0.0` | UNRESOLVED `RELEASE_NOT_FOUND` (PyPI has no such release) |
   | 2. Known Vulnerable (OSV) | `pip install reportlab-legacy==3.5.21` | BLOCK `DENYLIST` |
   | 3. Trigger-Dependent (Dormant) | `pip install dormant-exfil==1.2.0` | BLOCK `NOT_ON_ALLOWLIST` |
   | 4. Transitive Risk | `pip install invoice-utils==2.0.1` | BLOCK `NOT_ON_ALLOWLIST` |
   | 5. Typosquat / Slopsquat | `pip install requests-security==2.31.0` | BLOCK `DENYLIST` |

   Chip 5 is the one worth clicking: a real gate BLOCK. After it, the Overview tab should show the
   gate finding, the Requirements tab FR-2, and the Metrics tab one more BLOCK row.

### What the page cannot show today

- It has no way to start cases 1, 2, 3, 5 or 6: the chips are hardcoded in
  `frontend/src/components/CavrModule.tsx`, which is outside this branch's scope and unchanged.
  The five planned scenarios exist on the backend (`GET /api/cavr/scenarios`,
  `POST /api/cavr/run?scenario=verified|known_vulnerable|denylisted|tampered_wheel|network_off`)
  but no button calls them. Show those cases in the terminal, and their rows in the Metrics tab.
- Parts of that same file print fixed text around real results. Avoid them or explain them:
  **Proof Details** prints "VERIFIED MATCH" for every run and "Counterfactual Container Runs (1)";
  the timeline shows fixed timings such as "680ms"; the sandbox console panel appears after every
  verdict; chip labels 1-4 do not describe what is now sent.

---

## Numbers for the supervisor's report

With terminal B running:

```bash
curl -s http://127.0.0.1:8000/api/cavr/metrics | .venv/bin/python -m json.tool
```

On the recorded run (cases 1-4, 6a and the five chip requests) the endpoint returned: 10 verdicts,
1 cache hit, hit rate 0.1, p50 2.72 ms, p95 8889.56 ms. Read item 3 below before quoting p50.

---

## Things that did not behave as expected

Cases 1-6 all gave the expected verdict, stage, rule and exit code. These are the things to know:

1. **Case 7 is only partly possible.** The page cannot launch cases 1, 2, 3, 5 and 6, and
   `CavrModule.tsx` prints fixed text (see above). Needs your decision on editing that file.
2. **`hash matches: False` in case 6b** when no hash was ever computed. `api.run_verification` sets
   `matches` to "rule is HASH_MATCH", which is `False` for `REGISTRY_UNAVAILABLE`; it should be
   `None` unless both hashes exist. Display only; the verdict is right. Not fixed.
3. **p50 of `fast_gate_ms` was 2.72 ms** because half of the logged rows are BLOCKs, which take
   1-3 ms and download nothing. As a latency figure for "verifying a package" it is misleading;
   quote the per-case times instead, or the percentile over rows that reached the artifact stage
   (not implemented).
4. **The cache hit saved about 1.3 s on this run (3354 -> 2037 ms), and that is not a stable number.**
   Both runs download the wheel and ask OSV; only the scan is skipped. On another run the two
   times could be closer.
5. **Case 3 prints all 97 advisory ids on one line** (about 2,000 characters). It is correct but
   hard to read on a projector. The `reason` line above it shows the first five.
6. **After case 5 the good `pypdf-6.19.0` wheel is gone from the quarantine directory**; only
   `pypdf-6.19.0-py3-none-any.whl.rejected` remains. The demo run shares the directory with real
   runs and a hash mismatch removes the older good copy. No verdict is affected (every run
   downloads again), but do not run case 5 at the same time as another case.
7. **Case 6a output shows `artifact: None`, `sha256 None`, `cache: None`.** Correct (nothing was
   downloaded, the cache was never reached) but it reads oddly.
8. **`frontend/dist` was stale** (built on 9 Oct, before the tab changes). It is not in git, so the
   build in step 0 is required on every machine, or the page shows the old tabs against the new API.
9. **Not run for this file:** `--install` (covered by the live test
   `test_live_pip_wrapper_installs_only_with_the_flag_and_only_the_verified_wheel`, which passed on
   2026-10-10), the two variants of case 4, and anything in a browser.

---

## After the demo

```bash
# Terminal B: Ctrl+C
rm -rf runtime-demo        # the demo's cache, log and quarantined wheels
```

Nothing was installed by any command in this script.
