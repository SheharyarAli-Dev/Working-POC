# CAVR report figures (screenshots of 2026-10-11)

Browser bar removed, cropped to content. Use from `report/figures/cavr/`.

| File | Shows | Suggested caption | Where |
|---|---|---|---|
| cavr-01-verified-pipeline.png | Chip 1, six-stage timeline, VERIFIED | Six-stage CAVR fast gate for `pip install pypdf==6.19.0`: all stages pass and the verdict is VERIFIED; nothing is installed. | Ch 6 |
| cavr-02-verified-verdict.png | Verdict card, SHA-256, OSV 0 advisories, honesty wording | VERIFIED verdict card with the artifact SHA-256 (HASH_MATCH), a live OSV answer and the limits of the verdict. | Ch 7 (case 1) |
| cavr-03-rejected-osv-pipeline.png | Chip 3 timeline, REJECTED | `pypdf==5.1.0` passes the gate and hash check but is REJECTED for known vulnerabilities. | Ch 7 (case 3) |
| cavr-04-rejected-osv-verdict.png | 97 OSV advisories | REJECTED (KNOWN_VULNERABILITY): 97 live OSV advisories affect pypdf 5.1.0. | Ch 7 (case 3) |
| cavr-05-block-pipeline.png | Chip 4, stages 3-5 "did not run" | `left-pad==1.0` is blocked at the requirement gate (C2); later stages do not run. | Ch 7 (case 4) |
| cavr-06-block-verdict.png | BLOCK card, no hash | BLOCK (NOT_ON_ALLOWLIST): nothing was downloaded, so no hash exists. | Ch 7 (case 4) |
| cavr-07-tampered-pipeline.png | Hash mismatch evidence | Tampered wheel: downloaded SHA-256 differs from the registry digest (HASH_MISMATCH). | Ch 7 (case 5) |
| cavr-08-tampered-verdict.png | REJECTED card, demo condition | REJECTED (HASH_MISMATCH) under the tampered-wheel demo condition. | Ch 7 (case 5, optional) |
| cavr-09-unresolved-pipeline.png | Network off, fail-closed | With the registry unreachable the run fails closed: UNRESOLVED (REGISTRY_UNAVAILABLE). | Ch 7 (case 6) |
| cavr-10-unresolved-verdict.png | NEEDS_REVIEW card | "Unknown is not treated as a pass": the UNRESOLVED verdict card. | Ch 7 (case 6, optional) |
| cavr-11-capability-contract.png | Capability contract matrix | Capability contract inferred for pypdf 6.19.0: 2 capabilities required, 8 denied, with static sink findings. | Ch 6 (C4) |
| cavr-12-ast-scan-sinks.png | AST scan + reachability proof | AST scan of 59 files: two `subprocess.run` sinks judged GUARD_DISABLED by an accepted reachability proof. | Ch 6 (C4) |
| cavr-13-requirements-traceability-1.png | Threat model + FR-1..FR-4 | CAVR scope, threat model and requirements traceability (FR-1 to FR-4). | Ch 6 or App. B |
| cavr-14-requirements-traceability-2.png | FR-5..FR-10, NFR-1, NFR-2 | Requirements traceability (FR-5 to NFR-2); M2 items show a dash, not a fake PASS. | Ch 6 or App. B |
| cavr-15-assurance-certificate-verified.png | 7-record hash chain + certificate | Hash-chained evidence (7 records) and the bounded trust certificate for a VERIFIED run, with all digests. | Ch 6 |
| cavr-16-assurance-chain-unresolved.png | 5-record chain, UNRESOLVED cert | Certificate for the UNRESOLVED run: unreached checks are listed as NOT_REACHED. | App. B (optional) |
| cavr-17-certificate-limits.png | "What this certificate does not establish" | Stated limits of the certificate and of the fast gate. | Ch 6 / limitations |
| cavr-18-metrics.png | Verdict counts, cache hit rate, p50/p95 | Dashboard metrics: verdicts logged, cache hit rate and fast-gate latency by verdict. | Ch 7 |
| cavr-19-verdict-log.png | Verdict log rows | Verdict log: each request, status, rule, latency and cache lookup. | Ch 7 or App. B |
| cavr-20-tests-cavr.png | 1273 passed, 7 skipped | CAVR test suite: 1273 passed; 7 live-network tests skipped by default. | Ch 7 |
| cavr-21-tests-full-suite.png | 1338 passed | Full project test suite: 1338 passed, 0 failed. | Ch 7 |
| cavr-22-tests-live.png | 7 live tests passed | Opt-in live tests (`CAVR_LIVE=1`) against real PyPI and OSV: 7 passed. | Ch 7 |

## Notes for captions (keep the report honest)
- **cavr-01/02:** this run shows `lookup: HIT` / `Cache hit: yes`, because the server had already cached pypdf 6.19.0 earlier. Do **not** caption it as "first run, cache MISS".
- **Chip 2 (cache hit) screenshots were dropped:** they look the same as chip 1, and the cache hit took longer (4030 ms vs 2855 ms), so don't claim "a cache hit is faster" from them. The MISS-then-HIT evidence is in cavr-19 (6:34:01 PM MISS, then HIT rows) and cavr-15 (`cache_hit: true`).
- **cavr-18/19:** these show 10 logged verdicts from several demo rehearsals, not one clean run. Caption them as "after repeated demo runs".
- **The dashboard header says "VERDICT: BLOCK"** for REJECTED runs (policy state REJECTED). If asked: the header is the overall gate action; the policy state is the CAVR verdict.
- **Dropped:** two duplicates of the contract and triggers tabs, and a partial test screenshot.
