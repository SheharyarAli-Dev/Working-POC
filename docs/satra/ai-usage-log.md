# AI usage log

| Phase | What was generated | Files | What the owner must review |
|---|---|---|---|
| 0 | Environment setup scripts, audit of prototype, baseline report | `docs/satra/baseline-report.md` | The classification table against the code lines it cites |
| 1 | Settings, ingestion, CLI, tests | `backend/satra/settings.py`, `ingest.py`, `cli.py`, `tests/test_satra_gitkit.py`, `tests/test_satra_ingest.py` | Git argument handling in `run_git`, parsing of `-z` output, allowlist logic |
| 2 | Trusted policy, SRS, trusted tests, manifest, seed app and scenarios | `backend/satra/trusted/*`, `trust.py`, `scripts/satra_seed*`, `tests/test_satra_trust_and_seed.py` | That each trusted assertion matches the SRS sentence it claims to enforce |

Later phases append rows below.
