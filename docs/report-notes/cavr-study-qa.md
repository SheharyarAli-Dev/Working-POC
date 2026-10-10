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
