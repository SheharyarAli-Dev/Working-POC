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
| `reports/satra-block.json` | `asent gate --json` | BLOCK: SATRA REJECT (`can_access` returns True; trusted test `test_other_user_denied` fails), CAVR VERIFIED (`NOTHING_TO_VERIFY`). Written on a GitHub runner with Docker by the manual workflow "VS Code extension fixtures" (artifact `vscode-asent-fixtures`); the artifact's `doctor.json` was not used. |
| `doctor/doctor.json` | `asent doctor --json` | not ready: Docker is not installed on the machine that wrote it |
| `init/init.json` | `asent init --json` | starter `.asent/` written |
| `dashboard/dashboard.json` | the line `asent dashboard --json` prints | the server itself was not started |

The SATRA scenario's CAVR section is `verify: "changed"`: the head edits only `app/security.py`, so CAVR
checks an edit of `requirements.txt` that asks for nothing and is VERIFIED (`NOTHING_TO_VERIFY`). The BLOCK in
`satra-block.json` is SATRA's alone. With the default `"all"`, the empty requirements file is UNRESOLVED
(`CAPTURE_INCOMPLETE`) and the gate would answer REVIEW.

`asent gate --json` prints exactly the report it writes to `asent-report.json`
(`tests/test_cli_gate.py::test_gate_json_prints_exactly_the_written_report`), so the report fixtures
serve for both `gate --json` and `report --json`.

CAVR's PyPI and OSV answers in these runs are the recorded real answers the gate tests use
(`tests/test_cavr_support.py`: the real pypdf 6.19.0 wheel and registry response), so no network was
needed.

## Neutral paths (the only edit)

Before a file is written, `neutral()` in the generator replaces the paths of the machine that ran it with
placeholders. Nothing else is changed: same keys, same order, same numbers, booleans, SHAs and digests.

The paths are taken from the environment of the run (`machine_paths()`), so the same generator works on a
developer machine and on a GitHub runner (`/home/runner/work/...`, `$RUNNER_TEMP`, `$GITHUB_WORKSPACE`):

| Real path | Placeholder |
|---|---|
| the scenario's throwaway repository (`/tmp/asent-fixture-<name>-<random>/repo`) | `/workspace/project` |
| the scenario's temp folder itself | `/workspace` |
| the ASENT checkout or install (`ASENT_HOME`), and `$GITHUB_WORKSPACE` when set | `/opt/asent` |
| `$RUNNER_TEMP` when set | `/tmp/runner-temp` |
| the temp folder (`tempfile.gettempdir()`, `$TMPDIR`, `$TEMP`, `$TMP`) | `/tmp` |
| asent's own temp folders inside a temp folder (`/tmp/asent-gate-<random>`, any `tempfile.mkdtemp` name) | that folder's placeholder + `/<prefix>run`, e.g. `/tmp/asent-gate-run` |
| the home folder | `/home/user` |

Unset, empty, relative or `/` values are ignored. A path ends on a whole segment (`/home/runner2` is not
`/home/runner`) but may start anywhere, so `-I/home/runner/include` is replaced too. The mkdtemp rule
matches any `<prefix>-<8 lowercase characters>` name directly in a temp folder, so an ordinary folder such as
`/tmp/my-project-database` would also become `/tmp/my-project-run`. Paths are replaced, inside JSON string
values and keys, in one pass. If any of these machine paths, or the user name as a path segment (`/runner/`),
is still found afterwards the generator writes nothing. The user name as a plain word does not count: SATRA's
report has a `runner` key (`sandbox_image.runner`) and a GitHub runner's user is `runner`. A key that
would become the same as another key, or a value that is not JSON, is refused as well.

One consequence: hashes that asent computed over a record that contains a path (for example an evidence
record's `content_hash`) were computed over the original path and do not re-verify against the edited text.
The extension never verifies them; it only displays the report.
