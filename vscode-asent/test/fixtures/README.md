# Test fixtures: real `asent` output

Every JSON file here was written by `scripts/make_fixtures.py` from a real run of the ASENT CLI
(`backend.cli.main`) on a throwaway git repository with real base and head commits. None of it is
hand-written or edited. To regenerate (from the repository root):

    .venv/bin/python vscode-asent/scripts/make_fixtures.py

| File | Command | Result |
|---|---|---|
| `reports/accept.json` | `asent gate --json` | ACCEPT: CAVR pass (pypdf 6.19.0 verified), SATRA/SABLE disabled by base config |
| `reports/cavr-block.json` | `asent gate --json` | BLOCK: CAVR REJECTED, `reqeusts==2.31.0` on the denylist |
| `reports/review.json` | `asent gate --json` | REVIEW: the head edits `.asent/` (config changed in head); CAVR itself passes |
| `reports/sable-block.json` | `asent gate --json` | BLOCK: SABLE REGRESSED (`scenarios/sable/regressed`) |
| `reports/satra-block.json` | `asent gate --json` | **not here yet**: needs Docker. Run the manual workflow "VS Code extension fixtures" and commit its `satra-block.json`. The test that needs it is skipped until then. |
| `doctor/doctor.json` | `asent doctor --json` | not ready: Docker is not installed on the machine that wrote it |
| `init/init.json` | `asent init --json` | starter `.asent/` written |
| `dashboard/dashboard.json` | the line `asent dashboard --json` prints | the server itself was not started |

`asent gate --json` prints exactly the report it writes to `asent-report.json`
(`tests/test_cli_gate.py::test_gate_json_prints_exactly_the_written_report`), so the report fixtures
serve for both `gate --json` and `report --json`.

CAVR's PyPI and OSV answers in these runs are the recorded real answers the gate tests use
(`tests/test_cavr_support.py`: the real pypdf 6.19.0 wheel and registry response), so no network was
needed. Paths inside the files (`/tmp/asent-fixture-…`, the ASENT checkout) are those of the machine
that ran the generator.
