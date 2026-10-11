# Phase 1 walkthrough: real commit ingestion

Files: `backend/satra/settings.py`, `backend/satra/ingest.py`, `backend/satra/cli.py`, `tests/test_satra_gitkit.py`, `tests/test_satra_ingest.py`.

## settings.py

Analogy: the control panel by the door. Every dial (which repo, where to work, which model) is read once, with a safe default.

| Function | What it does | Worked example | Breaks if deleted |
|---|---|---|---|
| `gateway_address` | Reads `ip route` and returns the default gateway, which in WSL2 is the Windows host | returns `172.27.0.1` | Ollama on Windows is unreachable from WSL |
| `responds` | GETs `/api/tags` and checks for JSON | `responds("http://172.27.0.1:11434")` is `True` when Ollama runs | cannot tell a live endpoint from a dead one |
| `pick_ollama_endpoint` | Uses `OLLAMA_HOST` if set, else localhost, else the gateway | in this WSL, localhost fails and `http://172.27.0.1:11434` wins | every Ollama call needs manual configuration |
| `load_settings` | Builds the frozen `SatraSettings` from environment variables with defaults; the token is hidden from `repr` | `SATRA_MAX_REPAIR_ATTEMPTS` unset gives `3` | no component knows its configuration |

## ingest.py

Analogy: a customs officer. Nothing enters the analysis until the paperwork (SHA, URL, ref) is checked, and the officer never opens a shell to do the inspection.

| Function | What it does | Worked example (real output) | Breaks if deleted |
|---|---|---|---|
| `require_sha` | Accepts only 40 lowercase hex characters | `--upload-pack=x` raises `IngestError` | option injection through a SHA |
| `require_allowed_url` | Accepts only allowlisted repo slugs | `github.com/evil/x` raises | analysis of arbitrary repositories |
| `run_git` | Runs git with an argument list, scrubbed `GIT_*` environment, 120 s timeout | `run_git(repo, "rev-parse", "HEAD")` | every git call; also the no-`shell=True` guarantee |
| `ensure_repository` | Clones the allowlisted repo into `workspace/repos/` or fetches it | first run clones `~/projects/Threat-Repository` | no local copy to analyze |
| `list_recent_commits` | `git log --branches --remotes` with branch labels | `eb53da2  main,origin/main  This is the test file...` | the UI cannot offer a commit picker |
| `fetch_forge_commits` | Optional GitHub REST listing; reports rate limits instead of failing | rate limited gives `{"available": false, "reason": "forge rate limit reached"}` | no remote listing (local listing still works) |
| `require_ref` | Rejects empty, `-`-prefixed and unknown refs using `rev-parse --verify` | `-n` raises | option injection through a ref |
| `resolve_commit` | Validates the SHA, requires object type `commit`, returns author, date, parents | `0000...` raises "not present" | analysis of nonexistent commits |
| `empty_tree_hash` | Asks git for the empty tree hash | `4b825dc642cb6eb9a060e54bf8d69288fbee4904` | root commits have no base |
| `resolve_base` | First parent, or empty tree for a root, and flags merges | root commit gives kind `root` | wrong base (the tip of main) is compared |
| `parse_name_status` / `parse_numstat` | Parse NUL-delimited git output, including renames | `R100 before.py after.py` gives one `renamed` row | file names with spaces or newlines break parsing |
| `build_change_set` | Per file: status, old and new path, additions, deletions, binary flag, unified diff | on the real root commit: `added TestFile.py +226 -0` | no change set for any later phase |
| `ingest_commit` | resolve plus build in one call | used by the CLI | CLI loses its core |
| `prepare_run_dirs` / `release_run_dirs` | Disposable git worktrees for baseline and candidate, removed after the run while the run directory stays | baseline holds `x = 1`, candidate holds `x = 2` | no isolated copies to execute or mutate |

## cli.py

`command_ingest` prints SHA, parent, author, files and diff. `build_parser` and `main` wire the subcommand and turn `IngestError` into exit code 3.

## Evidence

`tests/test_satra_ingest.py`: 25 tests (modified, added, deleted, renamed, binary, root, merge, hostile SHA and ref, wrong URL, clone, worktree lifecycle). A CLI run against the real clone printed the exact SHA, `base ... (root)`, the file list and the 226-line diff.
