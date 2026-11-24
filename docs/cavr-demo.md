# CAVR mid demo script

Six cases, each one chip on the CAVR page and each through the one real verification path
(`backend/cavr/pipeline.py::verify_request`): real PyPI downloads, real SHA-256, real OSV.
Nothing in this script uses fixture data.

Every block marked **Recorded output** is the real output of the command above it, run on
2026-10-11 (local time) at commit `42e2524`, Python 3.14.4, Node.js v22.22.1, WSL2, with internet
access. Cases 1-6 were run through the dashboard API, which is exactly what a chip click calls.
Lines that will differ on your run are listed under each case.

> **Changed 2026-11-22 (M2 PR 1, `docs/cavr-m2-plan.md` Q2).** OSV now lists 18 advisories for pypdf 6.19.0, so
> the VERIFIED demo pin is **pypdf 6.21.4**, and 6.19.0 is a REJECTED chip of its own. There are seven chips. The
> table below is the current list. The case transcripts further down were recorded on 2026-10-11 with the old pin
> and are kept as recorded; on a new run, read 6.21.4 where they say 6.19.0 for chips 1, 2, 6 and 7.

| # | Chip on the page | Request | Expected |
|---|---|---|---|
| 1 | 1. pypdf 6.21.4 | `pip install pypdf==6.21.4` | VERIFIED, cache lookup MISS |
| 2 | 2. pypdf 6.21.4 again | the same again | VERIFIED, `cache_hit: True` |
| 3 | 3. pypdf 6.19.0 (OSV) | `pip install pypdf==6.19.0` | REJECTED `KNOWN_VULNERABILITY` (18 advisories on 2026-11-22) |
| 4 | 4. pypdf 5.1.0 (OSV) | `pip install pypdf==5.1.0` | REJECTED `KNOWN_VULNERABILITY`, count and first 3 OSV ids |
| 5 | 5. left-pad 1.0 (not allowed) | `pip install left-pad==1.0` | BLOCK `NOT_ON_ALLOWLIST`, nothing downloaded |
| 6 | 6. Tampered wheel | `pip install pypdf==6.21.4`, one bit flipped on the way | REJECTED `HASH_MISMATCH` |
| 7 | 7. Network unavailable | `pip install pypdf==6.21.4`, PyPI unreachable | UNRESOLVED `REGISTRY_UNAVAILABLE` |

The same requests through the pip wrapper (the C1 entry point, with exit codes) are in
"The pip wrapper" after case 6. Read "Things to know before you present" at the end.

---

## 0. Before the demo

Needs: the repository's `.venv`, Node.js (for the dashboard build), internet access.
Use two terminals, both in the repository root.

### Step 1 (first, on every machine): build the dashboard

```bash
cd "$(git rev-parse --show-toplevel)" # run from anywhere inside the repository clone
npm --prefix frontend run build
```

`frontend/dist` is a local build and is not in git. Without this step the app serves an old
bundle (or none), and the page does not match the API: no six chips, no timeline from the proof.
The command ends with `✓ built in ...`. It may rewrite the tracked `frontend/tsconfig.tsbuildinfo`.
Inspect that file's diff afterward and preserve any pre-existing edits; do not restore it blindly.

### Step 2, terminal A: demo data directory and helpers

```bash
cd "$(git rev-parse --show-toplevel)" # run from anywhere inside the repository clone

# A separate data directory for the demo: its own verdict cache, verdict log and quarantine.
if [ -e runtime-demo ]; then
  echo 'runtime-demo already exists; preserve it and choose a new empty demo directory.'
  exit 1
fi
mkdir runtime-demo
export ASENT_DATA="$PWD/runtime-demo"

# Run one chip by its id, and print what the page shows for the run.
run_scenario() {
  curl -s -X POST "http://127.0.0.1:8000/api/cavr/run?scenario=$1" \
    | .venv/bin/python -c 'import json,sys; print(json.load(sys.stdin)["run_id"])'
}
show() {
  curl -s -N "http://127.0.0.1:8000/api/cavr/stream/$1" > /dev/null    # returns when the run has finished
  curl -s "http://127.0.0.1:8000/api/cavr/proof/$1" | .venv/bin/python -c '
import json, sys
p = json.load(sys.stdin); v = p["cavr_verdict"]; h = p["hash_comparison"]
print("request:", p["request"])
print("verdict:", v["status"], "| stage:", v["stage"], "| rule:", v["rule"])
print("reason:", v["reason"])
print("demo condition:", p["demo_condition"]["id"] if p["demo_condition"] else None)
print("hash expected (registry):", h["declared_or_expected"])
print("hash of what arrived:    ", h["actual_sha256"])
print("hash result:", h["rule"], "| matches:", h["matches"])
print("fast_gate_ms:", v["fast_gate_ms"], "| cache_hit:", v["cache_hit"], "| escalated:", v["escalated"], "| logged:", v["logged"])
for s in p["stages"]:
    first = s["values"][0]
    print("  stage", s["id"].ljust(8), ("ran" if s["ran"] else "did not run").ljust(11), "|", first["label"] + ":", first["value"])'
}

# The pip wrapper, pointed at the same project and policy the dashboard uses (section "The pip wrapper").
cavr() {
  .venv/bin/python -m backend.cavr.pip_shim \
    --cavr-project backend/cavr/sample_project \
    --cavr-policy backend/cavr/project_policy.json "$@"
}
```

- Project being protected: `backend/cavr/sample_project` (an invoice reader that uses pypdf inside
  `apply_configuration(jbig2dec_binary=None)`).
- Policy: `backend/cavr/project_policy.json` (approves `pypdf>=5,<7`; `left-pad` is not on it).
- Nothing is installed by any command in this script.

### Step 3, terminal B: start the app

```bash
cd "$(git rev-parse --show-toplevel)" # run from anywhere inside the repository clone
ASENT_DATA="$PWD/runtime-demo" .venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Leave it running. `ASENT_DATA` must be the same directory as in terminal A.

### Step 4: the chips are the backend's list

Open **http://127.0.0.1:8000**, go to the CAVR module. The seven chips are read from
`GET /api/cavr/scenarios`; the page holds no package name of its own.

```bash
curl -s http://127.0.0.1:8000/api/cavr/scenarios | .venv/bin/python -c '
import json, sys
for s in json.load(sys.stdin):
    print(s["id"].ljust(17), "|", s["display_name"].ljust(30), "|", s["request"].ljust(27), "|", s["condition"], "|", s["expected_status"])'
```

**Recorded output** (2026-11-22, the same lines printed from `api.list_scenarios()`, which this endpoint returns):

```text
verified          | 1. pypdf 6.21.4                | pip install pypdf==6.21.4   | None | VERIFIED
verified_again    | 2. pypdf 6.21.4 again          | pip install pypdf==6.21.4   | None | VERIFIED
recent_advisories | 3. pypdf 6.19.0 (OSV)          | pip install pypdf==6.19.0   | None | REJECTED
known_vulnerable  | 4. pypdf 5.1.0 (OSV)           | pip install pypdf==5.1.0    | None | REJECTED
not_on_allowlist  | 5. left-pad 1.0 (not allowed)  | pip install left-pad==1.0   | None | BLOCK
tampered_wheel    | 6. Tampered wheel              | pip install pypdf==6.21.4   | tampered_wheel | REJECTED
network_off       | 7. Network unavailable         | pip install pypdf==6.21.4   | network_off | UNRESOLVED
```

The last column is what the chip is meant to show. It is never used to compute a verdict
(`test_expected_status_of_a_scenario_is_not_used`).

For each case below: click the chip, or run the command. They do the same thing
(`POST /api/cavr/run?scenario=<id>`). The `stage` lines are the six steps of the page's timeline.

---

## Case 1 — chip "1. pypdf 6.19.0" -> VERIFIED

```bash
RUN=$(run_scenario verified); echo "run id: $RUN"; show $RUN
```

**What it shows:** C1 capture, C2 gate, C3 real download + SHA-256 against the registry + tree + OSV,
C4 contract from the project's call sites, AST scan, sink reachability, verdict.

**Expected:** `VERIFIED`, `HASH_MATCH` with the same SHA-256 on both lines, all six stages ran,
cache lookup `MISS`, `cache_hit: False`.

**Recorded output:**

```text
run id: cavr-1791668207427-c7286f
request: pip install pypdf==6.19.0
verdict: VERIFIED | stage: verdict | rule: ALL_CHECKS_PASSED
reason: 1 requested packages verified: pypdf==6.19.0
demo condition: None
hash expected (registry): 7e5d6e730e7dae87d560a2cee218b852f6498c8be61966f3cd02ead971e48d14
hash of what arrived:     7e5d6e730e7dae87d560a2cee218b852f6498c8be61966f3cd02ead971e48d14
hash result: HASH_MATCH | matches: True
fast_gate_ms: 3912.65 | cache_hit: False | escalated: False | logged: True
  stage capture  ran         | source: pip_command
  stage gate     ran         | result: PERMITTED
  stage artifact ran         | hash check: HASH_MATCH
  stage cache    ran         | lookup: MISS
  stage analysis ran         | contract: CONTRACT_INFERRED
  stage verdict  ran         | status: VERIFIED
```

**Will differ:** the run id and `fast_gate_ms`.
**Could differ one day:** if OSV publishes an advisory for 6.19.0, the correct answer becomes
REJECTED `KNOWN_VULNERABILITY`.

**On the page:** the timeline shows six ticks; open a stage to see its values (step 5 lists
59 Python files scanned and 2 sink calls judged). The **Triggers** tab lists the two
`subprocess.run` calls in `pypdf/filters.py` as `GUARD_DISABLED`.

**Points to say:** the SHA-256 is computed from the downloaded bytes and equals PyPI's; pypdf does
call `subprocess.run` twice, and both calls are switched off by the project's own guard, which is
why they are evidence and not a failure.

---

## Case 2 — chip "2. pypdf 6.19.0 again" -> cache hit

```bash
RUN=$(run_scenario verified_again); echo "run id: $RUN"; show $RUN
```

**Expected:** VERIFIED again, cache lookup `HIT`, `cache_hit: True`, everything else as in case 1.

**Recorded output:**

```text
run id: cavr-1791668211417-93ce95
request: pip install pypdf==6.19.0
verdict: VERIFIED | stage: verdict | rule: ALL_CHECKS_PASSED
reason: 1 requested packages verified: pypdf==6.19.0
demo condition: None
hash expected (registry): 7e5d6e730e7dae87d560a2cee218b852f6498c8be61966f3cd02ead971e48d14
hash of what arrived:     7e5d6e730e7dae87d560a2cee218b852f6498c8be61966f3cd02ead971e48d14
hash result: HASH_MATCH | matches: True
fast_gate_ms: 2117.81 | cache_hit: True | escalated: False | logged: True
  stage capture  ran         | source: pip_command
  stage gate     ran         | result: PERMITTED
  stage artifact ran         | hash check: HASH_MATCH
  stage cache    ran         | lookup: HIT
  stage analysis ran         | contract: CONTRACT_INFERRED
  stage verdict  ran         | status: VERIFIED
```

**Be exact about what the hit saves.** A cache hit skips the AST scan and the sink judgement only.
The wheel is downloaded and hashed again, the tree and the contract are rebuilt (they are fields
of the cache key), and OSV is asked again (advisories change while the file does not). Most of
both times is network. On the recorded run the hit took 2117.81 ms against 3912.65 ms for the
miss; a third run of the same request, also a hit, took 4524.49 ms (see "Things to know", item 2).
Do not promise a fixed speed-up.

**This chip is not a special request.** It sends the same request as chip 1. It is a hit only
because chip 1 stored an analysis for the same file, tree, contract, policy and analyzer. Clicked
first on an empty cache it is a miss
(`test_the_again_chip_is_the_same_request_and_hits_the_cache_only_when_an_analysis_is_stored`).

---

## Case 3 — chip "3. pypdf 5.1.0 (OSV)" -> REJECTED with the OSV ids

```bash
RUN=$(run_scenario known_vulnerable); echo "run id: $RUN"; show $RUN
```

**Expected:** gate `PERMITTED` (the policy allows `pypdf>=5,<7`), `HASH_MATCH` (it is the genuine
5.1.0 wheel), then `REJECTED`, stage `advisories`, rule `KNOWN_VULNERABILITY`; the reason gives
the count and the first three ids.

**Recorded output:**

```text
run id: cavr-1791668213619-9f0f52
request: pip install pypdf==5.1.0
verdict: REJECTED | stage: advisories | rule: KNOWN_VULNERABILITY
reason: pypdf==5.1.0: pypdf 5.1.0 is affected by 97 known advisories: GHSA-23w6-3w8w-8484, GHSA-248m-82v9-q6g6, GHSA-2q4j-m29v-hq73 and 94 more
demo condition: None
hash expected (registry): 3bd4f503f4ebc58bae40d81e81a9176c400cbbac2ba2d877367595fb524dfdfc
hash of what arrived:     3bd4f503f4ebc58bae40d81e81a9176c400cbbac2ba2d877367595fb524dfdfc
hash result: HASH_MATCH | matches: True
fast_gate_ms: 2919.3 | cache_hit: False | escalated: False | logged: True
  stage capture  ran         | source: pip_command
  stage gate     ran         | result: PERMITTED
  stage artifact ran         | hash check: HASH_MATCH
  stage cache    ran         | lookup: MISS
  stage analysis ran         | contract: CONTRACT_INFERRED
  stage verdict  ran         | status: REJECTED
```

**Will differ:** the run id, `fast_gate_ms`; the number of advisories (97 on the recorded run)
grows when OSV publishes more.

**On the page:** the **Overview** tab has an "OSV advisories" card: `97 affect this version`, the
line above with the first three ids, and a closed section "Show all 97 advisories" (id, aliases,
fixed in, summary). The same list as JSON is linked under it:
`/api/cavr/proof/<run id>`, at `cavr_verdict.packages[0].evidence.advisories[].affected`.
In the timeline, step 5 shows the contract but a dash for the AST scan: OSV rejected the request
before the scan ran.

**Points to say:** the allowlist let it through and the file is genuine; it is the advisory check,
with OSV's version ranges evaluated for 5.1.0, that rejects it. Nothing is stored in the verdict
cache for it.

---

## Case 4 — chip "4. left-pad 1.0 (not allowed)" -> BLOCK before any download

```bash
RUN=$(run_scenario not_on_allowlist); echo "run id: $RUN"; show $RUN
ls runtime-demo/cavr/quarantine        # proof that nothing was downloaded for it
```

**Expected:** `BLOCK`, stage `gate`, rule `NOT_ON_ALLOWLIST`; stages artifact, cache and analysis
did not run; both hashes `None`; no `left-pad` file in the quarantine directory.

**Recorded output:**

```text
run id: cavr-1791668216623-a934f6
request: pip install left-pad==1.0
verdict: BLOCK | stage: gate | rule: NOT_ON_ALLOWLIST
reason: left-pad is not on the project allowlist
demo condition: None
hash expected (registry): None
hash of what arrived:     None
hash result: None | matches: None
fast_gate_ms: 2.17 | cache_hit: False | escalated: False | logged: True
  stage capture  ran         | source: pip_command
  stage gate     ran         | result: BLOCK
  stage artifact did not run | hash check: None
  stage cache    did not run | lookup: None
  stage analysis did not run | contract: None
  stage verdict  ran         | status: BLOCK
pypdf-5.1.0-py3-none-any.whl
pypdf-6.19.0-py3-none-any.whl
```

The two files listed are the wheels of cases 1-3. 2.17 ms is the whole run: no network was used.

**On the page:** steps 3, 4 and 5 of the timeline say "did not run" and every value in them is a
dash (—). The proof drawer shows a dash for both hashes and for the hash result.

---

## Case 5 — chip "5. Tampered wheel" -> REJECTED on hash mismatch

Something has to sit between PyPI and CAVR to change the file. The demo condition
`tampered_wheel` wraps the real download and flips one bit of the wheel on the way in; the
pipeline then runs unchanged. The run downloads into its own directory,
`runtime-demo/cavr/quarantine-demo/tampered_wheel/`, never into the quarantine of the real runs.

```bash
sha256sum runtime-demo/cavr/quarantine/pypdf-6.19.0-py3-none-any.whl          # the genuine wheel, before
RUN=$(run_scenario tampered_wheel); echo "run id: $RUN"; show $RUN
ls runtime-demo/cavr/quarantine                                                # unchanged
sha256sum runtime-demo/cavr/quarantine/pypdf-6.19.0-py3-none-any.whl          # the genuine wheel, after
sha256sum runtime-demo/cavr/quarantine-demo/tampered_wheel/*.rejected          # the file that arrived, kept as evidence
```

**Expected:** `REJECTED | stage: artifact | rule: HASH_MISMATCH`; the registry hash is the
`7e5d6e73…` of case 1 and the arrived hash is different; `matches: False`; `logged: False`; the
genuine wheel has the same SHA-256 before and after; `sha256sum` of the `.rejected` file equals
"hash of what arrived".

**Recorded output:**

```text
7e5d6e730e7dae87d560a2cee218b852f6498c8be61966f3cd02ead971e48d14  runtime-demo/cavr/quarantine/pypdf-6.19.0-py3-none-any.whl
run id: cavr-1791668228892-f6e43c
request: pip install pypdf==6.19.0
verdict: REJECTED | stage: artifact | rule: HASH_MISMATCH
reason: pypdf==6.19.0: pypdf-6.19.0-py3-none-any.whl: SHA-256 of the downloaded file is a52a19f9f614cd13e3f7544c78e5a44fc0996507c8b1b620abd45da5d73ee7b9, the registry says 7e5d6e730e7dae87d560a2cee218b852f6498c8be61966f3cd02ead971e48d14
demo condition: tampered_wheel
hash expected (registry): 7e5d6e730e7dae87d560a2cee218b852f6498c8be61966f3cd02ead971e48d14
hash of what arrived:     a52a19f9f614cd13e3f7544c78e5a44fc0996507c8b1b620abd45da5d73ee7b9
hash result: HASH_MISMATCH | matches: False
fast_gate_ms: 1582.34 | cache_hit: False | escalated: False | logged: False
  stage capture  ran         | source: pip_command
  stage gate     ran         | result: PERMITTED
  stage artifact ran         | hash check: HASH_MISMATCH
  stage cache    did not run | lookup: None
  stage analysis did not run | contract: None
  stage verdict  ran         | status: REJECTED
pypdf-5.1.0-py3-none-any.whl
pypdf-6.19.0-py3-none-any.whl
7e5d6e730e7dae87d560a2cee218b852f6498c8be61966f3cd02ead971e48d14  runtime-demo/cavr/quarantine/pypdf-6.19.0-py3-none-any.whl
a52a19f9f614cd13e3f7544c78e5a44fc0996507c8b1b620abd45da5d73ee7b9  runtime-demo/cavr/quarantine-demo/tampered_wheel/pypdf-6.19.0-py3-none-any.whl.rejected
```

On the recorded run the genuine wheel also kept its modification time and inode across the
tampered run (`stat -c '%y %i'` gave `2026-10-11 02:36:52.934584409 +0500 120873` before and after).
The last four lines were recorded after case 6 had also run; case 6 downloads nothing.

**Will differ:** the run id and `fast_gate_ms`. The arrived hash is the same every time (the same
bit of the same file is flipped).

**Points to say:** this is a demo condition and the page says so (a "DEMO CONDITION" banner in the
Overview tab, and the proof). The condition only replaces the transport, so it can cause a
mismatch but can never produce a VERIFIED. Such runs are not written to the verdict log
(`logged: False`), so they are not in the report numbers, and they cannot touch a real run's files.

---

## Case 6 — chip "6. Network unavailable" -> UNRESOLVED

```bash
RUN=$(run_scenario network_off); echo "run id: $RUN"; show $RUN
```

**Expected:** `UNRESOLVED | stage: artifact | rule: REGISTRY_UNAVAILABLE`, both hashes `None`,
`matches: None` (nothing was hashed, so there is neither a match nor a mismatch), `logged: False`.
Not VERIFIED, although the same request was VERIFIED and cached in cases 1 and 2.

**Recorded output:**

```text
run id: cavr-1791668230579-72878e
request: pip install pypdf==6.19.0
verdict: UNRESOLVED | stage: artifact | rule: REGISTRY_UNAVAILABLE
reason: pypdf==6.19.0: cannot read the registry: ConnectError: the network is off (dashboard demo condition)
demo condition: network_off
hash expected (registry): None
hash of what arrived:     None
hash result: REGISTRY_UNAVAILABLE | matches: None
fast_gate_ms: 3.09 | cache_hit: False | escalated: False | logged: False
  stage capture  ran         | source: pip_command
  stage gate     ran         | result: PERMITTED
  stage artifact ran         | hash check: REGISTRY_UNAVAILABLE
  stage cache    did not run | lookup: None
  stage analysis did not run | contract: None
  stage verdict  ran         | status: UNRESOLVED
```

**Points to say:** the cache cannot turn "I could not download it" into VERIFIED, because the
SHA-256 of the downloaded file is one of the eight key fields. Unknown stays UNRESOLVED.
A real connection failure, with no demo switch, is case W6 in the next section.

---

## The pip wrapper (C1 entry point)

The same pipeline behind `pip`. It prints the evidence as text and returns an exit code; it
installs nothing unless `--install` is added (not used in this script). These were run after
cases 1-6, in the same `ASENT_DATA`, so W1 is a cache hit on the analysis the dashboard stored.

### W1 — `pypdf==6.19.0` -> VERIFIED, exit 0

```bash
cavr install pypdf==6.19.0; echo "exit code: $?"
```

**Recorded output:**

```text
CAVR verdict: VERIFIED
  stage: verdict   rule: ALL_CHECKS_PASSED
  reason: 1 requested packages verified: pypdf==6.19.0
  request: pip install pypdf==6.19.0
  fast_gate_ms: 2161.04   cache_hit: True   escalated: False
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

If you run the wrapper first, on an empty `runtime-demo`, the last package line is
`cache: MISS, stored` and `cache_hit` is `False`.

### W3 — `pypdf==5.1.0` -> REJECTED, exit 1

```bash
cavr install pypdf==5.1.0; echo "exit code: $?"
```

**Recorded output:**

```text
CAVR verdict: REJECTED
  stage: advisories   rule: KNOWN_VULNERABILITY
  reason: pypdf==5.1.0: pypdf 5.1.0 is affected by 97 known advisories: GHSA-23w6-3w8w-8484, GHSA-248m-82v9-q6g6, GHSA-2q4j-m29v-hq73 and 94 more
  request: pip install pypdf==5.1.0
  fast_gate_ms: 2833.54   cache_hit: False   escalated: False
  gate: PERMITTED (ALLOWED)   policy version: e4b357a45bb7400290f240991bbe174606fafa750e9fd08dba7fb18c0984fc46
package pypdf==5.1.0: REJECTED (advisories / KNOWN_VULNERABILITY)
  reason: pypdf 5.1.0 is affected by 97 known advisories: GHSA-23w6-3w8w-8484, GHSA-248m-82v9-q6g6, GHSA-2q4j-m29v-hq73 and 94 more
  artifact: pypdf-5.1.0-py3-none-any.whl HASH_MATCH
    sha256 3bd4f503f4ebc58bae40d81e81a9176c400cbbac2ba2d877367595fb524dfdfc
    registry 3bd4f503f4ebc58bae40d81e81a9176c400cbbac2ba2d877367595fb524dfdfc
  tree: TREE_BUILT, 1 file(s), subtree digest 724a6fc8a993064e5b2900af588536d1710f877557e42f48b369ea8b010884ef
    pypdf==5.1.0 sha256 3bd4f503f4ebc58bae40d81e81a9176c400cbbac2ba2d877367595fb524dfdfc
  contract: CONTRACT_INFERRED, 4 call site(s), digest 6dac79316ba769a26d0c3bb448c55b3b37fcadee2c26b6acc8ccf50d9e1e07ce
  advisories: pypdf 5.1.0 KNOWN_VULNERABILITY: 97 advisories: GHSA-23w6-3w8w-8484, GHSA-248m-82v9-q6g6, GHSA-2q4j-m29v-hq73 and 94 more (every id: --cavr-json)
  cache: MISS
install: not requested; nothing was installed (run again with --install after a VERIFIED verdict)
exit code: 1
```

Every id, from the JSON output:

```bash
cavr install pypdf==5.1.0 --cavr-json | .venv/bin/python -c '
import json, sys
d = json.load(sys.stdin)
ids = [a["id"] for a in d["verdict"]["packages"][0]["evidence"]["advisories"][0]["affected"]]
print(len(ids), "ids in the JSON; first", ids[0], "last", ids[-1], "| GHSA-7hfw-26vp-jp8m present:", "GHSA-7hfw-26vp-jp8m" in ids, "| exit code in the JSON:", d["exit_code"])'
```

**Recorded output:**

```text
97 ids in the JSON; first GHSA-23w6-3w8w-8484 last PYSEC-2026-4160 | GHSA-7hfw-26vp-jp8m present: True | exit code in the JSON: 1
```

### W4 — `left-pad==1.0` -> BLOCK, exit 3

```bash
cavr install left-pad==1.0; echo "exit code: $?"
```

**Recorded output:**

```text
CAVR verdict: BLOCK
  stage: gate   rule: NOT_ON_ALLOWLIST
  reason: left-pad is not on the project allowlist
  request: pip install left-pad==1.0
  fast_gate_ms: 1.69   cache_hit: False   escalated: False
  gate: BLOCK (NOT_ON_ALLOWLIST)   policy version: e4b357a45bb7400290f240991bbe174606fafa750e9fd08dba7fb18c0984fc46
install: not requested; nothing was installed (run again with --install after a VERIFIED verdict)
exit code: 3
```

**Variants, same exit code 3** (not recorded for this file): `cavr install requests-security==2.31.0`
gives rule `DENYLIST`; `cavr install pypdf` (no version) gives rule `NOT_PINNED`.

### W6 — a real connection failure -> UNRESOLVED, exit 2

The three variables send every HTTPS request to a local port where nothing listens, so the
connection is really refused. No demo switch is involved.

```bash
HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 ALL_PROXY=http://127.0.0.1:9 \
  cavr install pypdf==6.19.0; echo "exit code: $?"
```

**Recorded output:**

```text
CAVR verdict: UNRESOLVED
  stage: artifact   rule: REGISTRY_UNAVAILABLE
  reason: pypdf==6.19.0: cannot read the registry: ConnectError: [Errno 111] Connection refused
  request: pip install pypdf==6.19.0
  fast_gate_ms: 66.58   cache_hit: False   escalated: False
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

The `advisories` line is the dated OSV answer saved by the earlier cases (OSV could not be reached
either). It does not rescue the verdict: without the file there is nothing to verify.

---

## Numbers for the supervisor's report

With terminal B running (the **Metrics** tab shows the same numbers as three tables):

```bash
curl -s http://127.0.0.1:8000/api/cavr/metrics | .venv/bin/python -c '
import json, sys
m = json.load(sys.stdin)
print({k: m[k] for k in ("verdicts", "cache_hits", "cache_hit_rate", "cache_lookups", "cache_hit_rate_of_lookups", "by_status")})
t = m["fast_gate_ms"]
print("by verdict:")
for name, g in t["by_status"].items(): print("  ", name.ljust(11), "count", g["count"], "| p50", g["p50"], "| p95", g["p95"])
print("by cache lookup:")
for name, g in t["by_cache_lookup"].items(): print("  ", name.ljust(11), "count", g["count"], "| p50", g["p50"], "| p95", g["p95"])
print("by verdict and cache lookup:")
for g in t["by_status_and_cache_lookup"]: print("  ", g["status"].ljust(11), g["cache_lookup"].ljust(11), "count", g["count"], "| p50", g["p50"], "| p95", g["p95"])
print("last verdicts (newest first):")
for r in m["recent"]: print("  ", r["id"], r["status"], r["stage"], r["rule"], r["fast_gate_ms"], r["cache_lookup"], "|", r["requested"])'
```

**Recorded output** (taken before the wrapper runs, after cases 1-6 and one more click of chip 2,
`RUN=$(run_scenario verified_again); show $RUN`, which is not one of the six cases; without that
extra click you get 4 verdicts, 1 cache hit and 1 hit of 3 lookups):

```text
{'verdicts': 5, 'cache_hits': 2, 'cache_hit_rate': 0.4, 'cache_lookups': 4, 'cache_hit_rate_of_lookups': 0.5, 'by_status': {'BLOCK': 1, 'REJECTED': 1, 'VERIFIED': 3}}
by verdict:
   VERIFIED    count 3 | p50 3912.65 | p95 4524.49
   REJECTED    count 1 | p50 2919.3 | p95 2919.3
   BLOCK       count 1 | p50 2.17 | p95 2.17
   UNRESOLVED  count 0 | p50 None | p95 None
by cache lookup:
   HIT         count 2 | p50 2117.81 | p95 4524.49
   MISS        count 2 | p50 2919.3 | p95 3912.65
   NOT_REACHED count 1 | p50 2.17 | p95 2.17
by verdict and cache lookup:
   BLOCK       NOT_REACHED count 1 | p50 2.17 | p95 2.17
   REJECTED    MISS        count 1 | p50 2919.3 | p95 2919.3
   VERIFIED    HIT         count 2 | p50 2117.81 | p95 4524.49
   VERIFIED    MISS        count 1 | p50 3912.65 | p95 3912.65
last verdicts (newest first):
   5 VERIFIED verdict ALL_CHECKS_PASSED 4524.49 HIT | pip install pypdf==6.19.0
   4 BLOCK gate NOT_ON_ALLOWLIST 2.17 NOT_REACHED | pip install left-pad==1.0
   3 REJECTED advisories KNOWN_VULNERABILITY 2919.3 MISS | pip install pypdf==5.1.0
   2 VERIFIED verdict ALL_CHECKS_PASSED 2117.81 HIT | pip install pypdf==6.19.0
   1 VERIFIED verdict ALL_CHECKS_PASSED 3912.65 MISS | pip install pypdf==6.19.0
```

How to read it:

- Rows 1-4 are cases 1-4. Row 5 is the extra click of chip 2 after case 6. It says nothing about
  the genuine wheel (every run downloads the wheel again); the `sha256sum` lines of case 5 are the
  evidence for that. Cases 5 and 6 are not in the log, as intended.
- There is no single p50 any more. The BLOCK took 2.17 ms and sits in its own row; it no longer
  pulls down the time reported for verifying a package.
- `UNRESOLVED` has no logged request here (case 6 is a demo run), so its times are `None`
  (a dash on the page), not 0.
- Two hit rates: 2 of 5 verdicts (0.4), and 2 of the 4 verdicts that reached the cache lookup (0.5).
  The BLOCK is `NOT_REACHED`: it never looked anything up.
- With 1-3 requests per row these are observations, not statistics. Say the counts with them.

The verdict cache after the run (`GET /api/cavr/cache`, the Cache box shows "1 stored"):

```text
pypdf 6.19.0 VERIFIED 7e5d6e730e7dae87d560a2cee218b852f6498c8be61966f3cd02ead971e48d14 CAVR verdict cache 2026-10-10T21:36:51.329710+00:00
```

One row only: 5.1.0 was rejected by an advisory (never cached), the BLOCK analysed nothing, and
demo runs get no store.

---

## Things to know before you present

Cases 1-6 all gave the expected verdict, stage and rule, and the four wrapper runs (W1, W3, W4, W6)
the expected exit codes.

1. **The page was not opened in a browser for this file** (none is installed in the environment
   the script was recorded in). What was checked instead: the build succeeds; the app serves the
   new bundle (`GET /` answered 200 with `assets/index-MG-bm2ic.js`); the six cases through the
   same endpoints the page calls; and the page's own components rendered to HTML with
   `react-dom/server` from the recorded answers of cases 3, 5 and 6 and the metrics, where the
   values above appear and missing ones are dashes. Clicks, the live event stream and the layout
   were not exercised. Do one dry run in the browser before the demo.
2. **A cache hit is not always faster.** Hits took 2117.81 ms and 4524.49 ms, the miss 3912.65 ms.
   Every run downloads the wheel and asks OSV; only the scan is skipped. Do not quote a speed-up.
3. **Chip 2 depends on chip 1.** On an empty cache it is a miss. Click 1 first.
4. **Chips are disabled while a run is in progress** (a few seconds for cases 1-3 and 5).
5. **The timeline fills in at the end of a run, not stage by stage.** The pipeline is one call; the
   page gets the stages from the proof when the verdict is known. There is no time per stage
   because only `fast_gate_ms` for the whole request is measured.
6. **Wrapper output for W6 shows `artifact: None`, `sha256 None`, `cache: None`.** Correct (nothing
   was downloaded, the cache was never reached) but it reads oddly. Not changed.
7. **Tabs with no data on the fast gate** (Counterfactual Runs, Causal Graph, Repair) say "Not run",
   and the Environment box shows a dash: sandbox execution is deep analysis (M2).
8. **An old `runtime` database** gets the new `cache_lookup` column when the app starts. Its older
   rows are listed as `NOT_RECORDED` and are not in the hit rate of lookups; the demo uses a fresh
   `runtime-demo`, so this does not appear there.
9. **Not run for this file:** `--install` (covered by the live test
   `test_live_pip_wrapper_installs_only_with_the_flag_and_only_the_verified_wheel`, last run on
   2026-10-10), the two variants of W4, and anything in a browser.

---

## After the demo

Stop terminal B with Ctrl+C. Keep `runtime-demo` for inspection, or remove it only after verifying
that exact path contains only this demo's data. Do not remove a general project directory or
restore `frontend/tsconfig.tsbuildinfo` over edits you did not create.

Nothing was installed by any command in this script.


---

## M2 demo: real wheels

The M2 deep stage (docs/cavr-m2-plan.md PRs 9-13): an escalated package gets a **canary-only run**, then one
**counterfactual run per trigger** of its frontier (at most 8 runs), each in the CAVR sandbox
(`asent-cavr-sandbox:local`: no network, read-only, package code as UID 10001, fake canary secrets only), with the
project's literal-only call sites called; every verdict names its **cause** from the causal graph of those runs.

Each wheel below is a real wheel built on the fly and served by a local package index (they are not on PyPI); the
repository, the commit, `asent gate`, the container and the trace are real. The wheel files and the expected results
are in `tests/test_cavr_m2_wheels.py`, which is also the test (`CAVR_DOCKER=1 pytest tests/test_cavr_m2_wheels.py`).

Before: the image must be built (`bash docker/cavr-sandbox/build.sh`, once) and Docker running.

One command per wheel (prints the `asent report` text of that gate run):

```bash
CAVR_DOCKER=1 .venv/bin/python tests/test_cavr_m2_wheels.py env_ci
```

Replace `env_ci` by any name in the table; with no name it runs all 14 (about 3 minutes on this machine). Each run makes a new
temporary repository and data directory and removes them afterwards.

**Recorded output** (2026-11-24, branch `cavr-m2-loop` with PR 13, image `sha256:0e88dd461ca4…`, Docker 29.9.3, WSL2;
the `CAVR deep` line of each run, exactly as printed). `guard_out_of_scope` was added and recorded the same day after the
`other_guards` rule was widened (report notes Step M2-20); on that re-run the other 13 lines were byte for byte the same.

| Wheel | What the wheel does | Policy | Decision | `asent report` deep line |
|---|---|---|---|---|
| `env_ci` | `if os.environ.get('CI') == 'true': connect(198.51.100.24:443)` | default policy (connect denied) | BLOCK (exit 1) | `` demo==1.0 REJECTED DEEP_CONTRACT_VIOLATION - NETWORK_CONNECT connect 198.51.100.24:443 = ENETUNREACH caused by CI=true `` |
| `date` | `if date.today() >= date(2027, 1, 1): connect(...)` | default policy | BLOCK (exit 1) | `` demo==1.0 REJECTED DEEP_CONTRACT_VIOLATION - NETWORK_CONNECT connect 198.51.100.24:443 = ENETUNREACH caused by clock 2027-01-02T12:00:00 `` |
| `hostname` | `if socket.gethostname() == 'build-prod-7': connect(...)` | default policy | BLOCK (exit 1) | `` demo==1.0 REJECTED DEEP_CONTRACT_VIOLATION - NETWORK_CONNECT connect 198.51.100.24:443 = ENETUNREACH caused by hostname build-prod-7 `` |
| `argv` | `if '--deploy' in sys.argv: connect(...)` | default policy | BLOCK (exit 1) | `` demo==1.0 REJECTED DEEP_CONTRACT_VIOLATION - NETWORK_CONNECT connect 198.51.100.24:443 = ENETUNREACH caused by argv ['-c', '--deploy'] `` |
| `file_flag` | `if os.path.exists('~/.cache/deploy.flag'): connect(...)` | `FILE_READ:/tmp/home/.cache` granted, connect denied | BLOCK (exit 1) | `` demo==1.0 REJECTED DEEP_CONTRACT_VIOLATION - NETWORK_CONNECT connect 198.51.100.24:443 = ENETUNREACH caused by /tmp/home/.cache/deploy.flag exists `` |
| `file_kube` | `if os.path.exists('~/.kube/config'): connect(...)` | default policy | BLOCK (exit 1) | `` demo==1.0 REJECTED DEEP_CONTRACT_VIOLATION - SECRET_READ newfstatat /tmp/home/.kube/config = ENOENT in the canary-only run (no trigger needed) `` |
| `canary_exfil` | import reads `~/.aws/credentials`, sends the secret by UDP | default policy | BLOCK (exit 1) | `` demo==1.0 REJECTED DEEP_CONTRACT_VIOLATION - SECRET_READ openat /tmp/home/.aws/credentials = ok in the canary-only run (no trigger needed) `` |
| `driven_reject` | `def send(data): connect(...)`; the app calls `demo.send('x')` | default policy | BLOCK (exit 1) | `` demo==1.0 REJECTED DEEP_CONTRACT_VIOLATION - NETWORK_CONNECT connect 198.51.100.24:443 = ENETUNREACH caused by calling demo.send('x') at app/uses_demo.py:5 `` |
| `driven_verify` | the same wheel and call | `NETWORK_CONNECT:198.51.100.24:443` granted | ACCEPT (exit 0) | `` demo==1.0 VERIFIED DEEP_RUN_CLEAN (1 run(s): canary-only + 0 counterfactual, 1 call site(s) driven; nothing outside the contract) `` |
| `benign_triggered` | `if CI == 'true': connect(198.51.100.24:443)` | `NETWORK_CONNECT:198.51.100.24:443` granted | ACCEPT (exit 0) | `` demo==1.0 VERIFIED DEEP_RUN_CLEAN (2 run(s): canary-only + 1 counterfactual, 1 call site(s) driven; nothing outside the contract) `` |
| `win32` | `if sys.platform == 'win32': connect(...)` | default policy | REVIEW (exit 2) | `` demo==1.0 UNRESOLVED TRIGGER_UNSIMULABLE - demo/__init__.py:2 `(sys.platform == 'win32')`: not run: unsimulable (the condition is true only when sys.platform is 'win32' (os.name 'nt', platform.system() 'Windows'); the sandbox runs Linux) `` |
| `budget` | 8 branches `if DEPLOY_i == 'yes': connect(...)` | `NETWORK_CONNECT:198.51.100.24:443` granted | REVIEW (exit 2) | `` demo==1.0 UNRESOLVED DEEP_RUN_BUDGET_EXHAUSTED - demo/__init__.py:37 `(os.environ.get('DEPLOY_8') == 'yes')`: not run: the budget of 8 sandbox runs for this package is used up `` |
| `function_sink` | `def send(data): connect(...)`; the app calls only `demo.run()` | default policy | REVIEW (exit 2) | `` demo==1.0 UNRESOLVED DEEP_SINK_NOT_EXERCISED - not exercised: demo/net.py:5 socket.create_connection (function send) `` |
| `guard_out_of_scope` | `if hash('cavr') % 7 == 99: connect(203.0.113.9:443)` (a guard CAVR cannot evaluate) | `NETWORK_CONNECT:198.51.100.24:443` granted | REVIEW (exit 2) | `` demo==1.0 UNRESOLVED DEEP_GUARD_UNEXPLORED - unevaluable guard demo/__init__.py:2 `hash('cavr') % 7 == 99` gates NETWORK_CONNECT (medium risk), no run showed it `` |

What each row shows:

- **A trigger REJECTED with its cause** (`env_ci`, `date`, `hostname`, `argv`, `file_flag`): the canary-only run is
  clean, the run with the synthesized environment connects, and the connect is in that run only, so the graph's
  `caused` edge goes from the trigger to the event. The clock is the one the frontier synthesized (one day and a half
  after the constant).
- **`file_kube` and `canary_exfil`: no trigger needed.** Checking `~/.kube/config` is itself an attempt to read a
  credential path, and reading `~/.aws/credentials` at import is a violation in the canary-only run already. The
  canary leak is in the same run's evidence: a `CANARY_EXFIL_ATTEMPT` (`sendto` to 198.51.100.24:53 carrying the fake
  secret), in the key events and in the graph.
- **A driven call** (`driven_reject`, `driven_verify`): the sink is inside `send()`, which an import never runs; the
  app's call `demo.send('x')` passes only a literal, so CAVR calls it in a drive step. Denied -> REJECTED, caused by the
  call; granted for that endpoint -> VERIFIED (1 run: no frontier entry, the drive exercised the sink).
- **`benign_triggered`: VERIFIED.** The guarded branch connects only to the granted endpoint; the CI=true run explores
  it and stays inside the contract.
- **`win32`: UNRESOLVED.** No Linux environment makes `sys.platform == 'win32'` true; an unsimulable trigger can never
  give VERIFIED.
- **`budget`: UNRESOLVED.** 1 canary-only + 7 trigger runs use the 8 runs; `DEPLOY_8` was never run.
- **`guard_out_of_scope`: UNRESOLVED.** `hash('cavr') % 7 == 99` reads nothing CAVR can set (no variable, clock, file,
  host, user, argv or platform), so no run can be made to take the branch; behind it is a connect to an address the
  grant does not cover. A guard CAVR cannot evaluate in front of a sink not granted with `*` is unexplored, so the
  package cannot be VERIFIED (before this rule it was UNRESOLVED for another reason, `DEEP_SINK_NOT_EXERCISED`).
- **`function_sink`: UNRESOLVED.** The app only calls `demo.run()`; driving it shows no connect, so the sink in
  `send()` is not exercised.

Full recorded output of the first command (`env_ci`); the temporary paths and commit ids differ on every run:

```text
ASENT gate: BLOCK (exit 1)
Repository: /tmp/cavr-m2-demo-wx1ngjn1/repo
Base: base (5f48584a251b)   Head: head (bd10d5ed23ea)
Generated: 2026-11-24T16:35:07.009942+00:00 by ASENT 1.0.0
Config: base commit 5f48584a251bd8ed785038430e11af8f2d922b77: .asent/; digest 6aedd0da60c14338ce9f3da4040e6242abb143b755456c41073c285720a95a28

Modules:
  CAVR   block                                    requirements.txt: REJECTED DEEP_CONTRACT_VIOLATION: demo==1.0: demo 1.0: run 2 (the counterfactual run spec-ded3a61ac21291f8): 2 event(s) outside the contract; 
  SATRA  not assessed (disabled by base config)   not part of this test
  SABLE  not assessed (disabled by base config)   not part of this test
  CAVR deep: demo==1.0 REJECTED DEEP_CONTRACT_VIOLATION - NETWORK_CONNECT connect 198.51.100.24:443 = ENETUNREACH caused by CI=true

Reasons:
  - CAVR: REJECTED

Report: asent-report.json
```

Lines that will differ on your run: the temporary paths, commit ids, `Generated`, the spec id (a hash of the trigger's
place in the wheel), the canary values (random per run, never printed here).
