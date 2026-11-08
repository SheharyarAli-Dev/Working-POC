# SATRA trusted suite: what a trusted test can rely on in a gate run

This is the interface between a project's trusted tests (`.asent/satra/trusted_tests/`) and SATRA's
gate runs. It holds for every trusted run: base, head and counterfactual. Why it is built this way:
[harness-isolation.md](harness-isolation.md). Code: `backend/satra/pytest_runner.py::_trusted_layout`,
`backend/satra/trusted_run_plugin.py`, `backend/satra/trusted_data.py`.

## Where things are

| Path in the container | What it is | Comes from | Mode |
|---|---|---|---|
| `/trusted/asent_assurance/` | the trusted tests, including their `conftest.py` | base `.asent/<trusted_tests>/` | read-only |
| `/trusted/pytest.ini` | the trusted pytest settings | base `.asent/<pytest_ini>`, or `[pytest]` when none is configured | read-only |
| `/trusted/<path>` | each declared `trusted_data` file or folder | the **base** commit, at the same project path | read-only |
| `/work/` | the code under test (base, head or mutant copy); the working directory | the commit under test | read-write copy |
| `/results/` | the JUnit file pytest writes | fresh per run, outside `/work` | read-write |
| `/tmp/` | scratch space (`tmp_path`, `tmp_path_factory`) | empty tmpfs, 64 MB | read-write |

Nothing else is in `/trusted`. There is no network.

## What a trusted test can do

1. **Import the code under test by its normal name.** `from app.main import create_app` works. The head
   (`/work`) is appended to the end of `sys.path`. Each `pythonpath` entry of the trusted `pytest.ini`
   points to the same path inside `/work` (`pythonpath = src` means `/work/src`), and these come before
   `/work` itself. Because they are appended last, pytest, the standard library and the installed packages
   always come from the image, never from the head.
2. **Find a declared data file next to itself.** `Path(__file__).resolve().parents[1]` is `/trusted`, so
   `parents[1] / "fixtures" / "invoice.pdf"` is `/trusted/fixtures/invoice.pdf` when `fixtures` is in
   `trusted_data`. The bytes are the base commit's. A pull request that changes `fixtures/` does not change
   what the trusted tests read. The project's own tests (`tests/`, run from `/work`) still use the head's copy.
3. **Use installed packages** only as the base `dependencies.lock.json` approves them (the per-project
   image, [per-project-sandbox.md](per-project-sandbox.md)).

## What a trusted test cannot do

- **Read an undeclared project file through a path relative to itself.** It is not there. The test then
  fails or errors on the base commit, and SATRA reports INCONCLUSIVE ("Trusted tests do not pass on the base
  commit, or execution is unavailable"). Declare the file or folder in `trusted_data`.
- **Write to `/trusted`.** It is read-only. Write to `tmp_path` instead.
- **Import helper modules from `/trusted`.** pytest puts `/trusted/asent_assurance` (and `/trusted`, when the
  trusted ini says `pythonpath = .`) on `sys.path` before the head. That is why `trusted_data` refuses code:
  a data folder there is at most an empty namespace package, and a regular head package with the same name
  still wins (`test_trusted_data_folder_inside_a_head_package_does_not_shadow_it`). Put shared helpers in the
  suite's `conftest.py`.
- **Find the project root with `Path(__file__).parent.parent`.** That is `/trusted`, not the project. To
  read a file the application ships, declare it in `trusted_data`. To import application code, use its
  module name (point 1).

## Declaring data: `SATRA.trusted_data`

```json
"SATRA": {"enabled": true, "trusted_tests": "satra/trusted_tests", "pytest_ini": "satra/pytest.ini",
          "trusted_data": ["fixtures"]}
```

Each entry is a project path (relative, `/`-separated, no `..`, not `.git` or `.asent`), either a file or
a folder. SATRA reads the entries from the base commit once, before any image is built, and writes exactly
those bytes to `/trusted/<path>` for every trusted run. The run is **INCONCLUSIVE**, with no build and no
test run, and the reason starts with `Trusted data refused:`, when:

- an entry is not in the base commit, or is a folder with no files;
- an entry, or any folder on the way to it, is a symbolic link, or anything inside a folder is not a
  regular file or folder (a link, a FIFO, a device);
- the first part of an entry is `asent_assurance` or `pytest.ini`;
- a file is Python code or a native module (`.py`, `.pyc`, `.pyo`, `.pyw`, `.pyi`, `.pth`, `.so`, `.pyd`,
  `.dylib`, `.dll` and the interpreter's extension suffixes), or a pytest or Python settings file
  (`conftest.py`, `pytest.ini`, `.pytest.ini`, `pytest.toml`, `.pytest.toml`, `pyproject.toml`, `tox.ini`,
  `setup.cfg`, `sitecustomize.py`, `usercustomize.py`);
- there are more than **1000 files** or more than **20 MiB** in total.

Files that a gate snapshot never contains (for example `.env*`, `*.pyc`, `__pycache__/`) count as
not in the base commit. The report lists each copied file with its size and SHA-256 under
`details.trusted_data`.

Data only, never code: a data folder sits next to `asent_assurance/` and contains nothing Python can import
and nothing that changes pytest's configuration. So the security properties in
[harness-isolation.md](harness-isolation.md) are unchanged: no head file is loaded by pytest, `/trusted`
is read-only, and dependencies come from the base only.
