# SATRA gate mode — threat model

Scope: SATRA in a gate run (`backend/satra/gate_mode.py::analyze_configured`). It does not cover the built-in
InvoiceHub demo path, SABLE, CAVR, or the shared orchestrator (see `docs/implementation-notes.md`).

## What an ACCEPT claims

The base commit's trusted contract tests pass on the head, they fail on one RETURN_TRUE counterfactual of the
contract target, and the head's own tests (when present) pass. It is bounded to that contract and is evidence
for the shared gate, not a proof of security.

## Trust boundary

| Trusted | Not trusted (adversary-controlled) |
|---|---|
| Base commit and its frozen `.asent/` config (contract, trusted tests, ini, limits) | Every file of the head commit |
| ASENT host process, the container engine and its daemon | Anything the head's code does at run time |
| `asent-satra-runner:local` and the CAVR-approved, hash-pinned wheels of the base lockfile | The head's `.asent/`, SRS.md, policy files (ignored) |
| The threat repository's enabled SATRA rules | |

Adversary: the author of the pull request, who can add, change or delete any head file, including files that
are executed when the trusted tests import the code under test.

## Threats and controls

| Threat | Control | Where | Evidence |
|---|---|---|---|
| Head rewrites the trusted tests, contract or SRS | Tests and contract come from the frozen base `.asent/` | `gate_mode.py` | `test_trusted_tests_come_from_base_even_when_head_edits_them`, `test_candidate_srs_cannot_switch_satra_off_in_a_gate_run` |
| Head adds a package to the test image | Image built from the base lockfile, CAVR-approved wheels only | `project_image.py` | `test_head_cannot_add_a_package_to_the_gate_image` |
| Head code reaches the network or host | Container: `--network none`, read-only root, `--cap-drop ALL`, no-new-privileges, CPU/memory/pids limits | `pytest_runner.py` | `test_every_gate_test_run_uses_the_project_image_with_full_isolation` |
| Head replaces pytest (`pytest.py`, `pytest/`, `_pytest/`) or adds start-up hooks (`sitecustomize`, `usercustomize`, `.pth`) | `python -P -s`; head appended to the end of `sys.path` only after pytest is loaded | `pytest_runner.py`, `trusted_run_plugin.py` | `test_head_harness_files_do_not_change_the_trusted_result` |
| Head conftest or pytest settings (`pytest.ini`, `pyproject.toml`, `setup.cfg`, `tox.ini`) steer the trusted run | Trusted tests and base ini at `/trusted` (read-only); `-c /trusted/pytest.ini --rootdir=/trusted --confcutdir=/trusted`, autoload off, no cacheprovider | `pytest_runner.py` | same test, settings and conftest cases |
| Head plants or overwrites the results file | `--junitxml` on a fresh tmpfs directory outside `/work`; head `results.xml` files deleted first; file read without following links, size-capped, must agree with the exit code | `pytest_runner.py::read_results` | step 2 tests in `tests/test_satra_harness_isolation.py` |
| Head adds a native module (`.so`/`.pyd`/`.dylib`) that Python imports instead of the `.py` beside it | Tripwire: any added or changed native module → INCONCLUSIVE, "test-harness tampering suspected: native module <path>" | `harness_guard.py` | `test_native_module_beside_a_broken_module_makes_the_gate_inconclusive` |
| Any attempt at the above | Tripwire: head changes to harness files, pytest settings, or non-test code importing pytest/_pytest or writing `sys.modules` → INCONCLUSIVE, "test-harness tampering suspected" | `harness_guard.py` | `tests/test_satra_harness_guard.py` |

## Stated limits (not solved)

1. **Code under test runs in the same process as the trusted tests.** The trusted tests must import the head's
   modules to test them, so head code runs inside the pytest process with the same rights. A fully adversarial
   head can still make a failing trusted run look like a pass: it can patch pytest objects it reaches at run time
   (through `sys.modules`, `gc`, stack frames or `builtins`), replace the functions the tests call, write a
   consistent results file at the `--junitxml` path it reads from `sys.argv`, and exit 0. The isolation above
   removes the routes that need no code (files pytest loads by itself), and the tripwire makes the obvious code
   routes visible, but a static check can be evaded (for example `getattr(__import__("s" + "ys"), "modules")`).
   This is recorded as a strict xfail: `test_known_limit_in_process_code_under_test_can_still_forge_results`.
   **A SATRA ACCEPT therefore does not hold against a head that attacks the test process itself;** it is one
   input to the shared gate and to human review. Closing this needs the code under test in a separate process
   from the harness (for example tests that reach the application only over a socket), which is deferred.
2. **The tripwire is a heuristic.** It has false positives (a legitimate new `conftest.py` or pytest setting goes
   to review) and false negatives (indirect imports, aliasing, dynamic code). It compares added and changed files
   only.
3. **The head's own tests use the head's configuration.** Ordinary project tests (`tests/`) run in `/work` with the
   head's conftest and settings; the head controls them anyway. They can only add a REJECT, never stand in for
   the trusted tests. Project security tests run on base copies with only the head's test file, which must pass
   the preflight (only `pytest` may be imported).
4. **The container engine is trusted.** A local attacker with access to the Docker daemon is out of scope. The host
   test harness (`container_on_host`) does not enforce read-only mounts; the real container path runs in CI.
5. **Results directory on tmpfs** uses the host's `/dev/shm` when it exists and is writable; otherwise a fresh
   system temporary directory (still outside `/work`, still removed after the run).
