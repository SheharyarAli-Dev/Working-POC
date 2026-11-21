# Dashboard server — report notes

## Host-header check against DNS rebinding (2026-11-21)

**Problem (from review):** `backend/main.py` accepted any `Host`. A page on `evil.example` can re-point its DNS
name to 127.0.0.1 and then read the unauthenticated dashboard as same-origin. The existing `local_origin`
middleware only checks `Origin` on non-GET requests, so GET routes, the SSE stream and report download were exposed.

**Implementation:**
- `backend/host_check.py` (new): `DEFAULT_HOSTS = ("127.0.0.1", "localhost", "[::1]")`; `allowed_hosts(environ)`
  adds the comma-separated `ASENT_ALLOWED_HOSTS` entries (lower-cased, de-duplicated, validated against a strict
  host-name / bracketed-IPv6 pattern; `*`, ports, schemes, paths or trailing dots raise `ValueError` at startup);
  `protect(app, environ)` installs Starlette's `TrustedHostMiddleware` with `www_redirect=False`.
- `backend/main.py`: `protect(app, os.environ)` after `local_origin`, so it is the outermost middleware and covers
  every route, the `/invoicehub` and static mounts, HTTP and WebSocket scopes.
- Docs: README "Allowed hosts" paragraph; `backend/commands/dashboard.py` docstring.

**Design decisions:**
- Starlette `TrustedHostMiddleware` over a hand-written check: it already covers `http` + `websocket`, refuses a
  missing/malformed Host with 400 and parses `[::1]:port` (Starlette 1.7.0). Less code to defend.
- Port is ignored, hostname must match exactly: keeps the Vite proxy (`localhost:5173`, no `changeOrigin`) working
  without adding anything; `127.0.0.1.evil.example` cannot match a suffix.
- Invalid setting fails loudly at startup instead of being skipped: a typo like `host:8000` would otherwise never
  match and look like a bug; `*` would silently disable the defence.
- `testserver` (TestClient default) is not allowed; tests set the Host explicitly instead of widening the rule.

**Who sends which Host (checked):** Vite dev/preview proxy → browser Host `127.0.0.1:5173`/`localhost:5173`;
`asent dashboard`, `asent` CLI (`ASENT_URL`), VS Code extension, `scripts/qa/*` → `127.0.0.1:PORT`. No existing
test sends HTTP to `backend.main:app`. Docker reached by LAN IP / service name needs `ASENT_ALLOWED_HOSTS`.

**Test cases (`tests/test_dashboard_host_check.py`, 44 tests):**

| Test | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_loopback_hosts_with_or_without_port_are_allowed` (8) | defaults pass on real app | 127.0.0.1[:8000/:5173], localhost[:8000/:5173], [::1][:8000] | 200 | pass |
| `test_other_hosts_and_a_missing_host_are_refused_with_400` (12) | rebinding / malformed | evil.example[:8000], 127.0.0.1.evil.example, localhost.evil.example, evil.localhost.example, "", `[::1`, `127.0.0.1:abc`, `::1`, 127.0.0.2, 0.0.0.0, no Host | 400 | pass |
| `test_sse_stream_is_checked_before_routing` | SSE covered | `/api/runs/x/stream` | 404 loopback / 400 evil | pass |
| `test_mounted_apps_post_and_download_are_covered` | mounts, POST, download | evil Host | 400 (not 403) | pass |
| `test_extra_host_is_refused_by_default` | setting empty by default | asent.internal | 400 | pass |
| `test_setting_adds_a_host_on_the_real_app` | setting works | `ASENT_ALLOWED_HOSTS=asent.internal` | 200 for it, 400 others | pass |
| `test_default_is_loopback_only`, `test_setting_appends_lowercased_deduplicated_hosts` | parsing | env values | exact lists | pass |
| `test_invalid_setting_fails_at_startup` (13) | fail closed | `*`, `*.example`, `http://…`, `host:8000`, `::1`, `[::1]:8000`, trailing dot, … | `ValueError` | pass |
| `test_websocket_with_loopback_host_connects` / `…rebinding_host_is_refused_with_400` (2) / `test_setting_adds_a_host_for_websocket_and_http` | WebSocket scope | small app with `/ws` | connect / denial 400 | pass |
| `test_test_client_default_host_is_not_allowed` | rule not widened for tests | Host testserver | 400 | pass |

Full suite (`.venv/bin/python -m pytest -q`, staged tree): 2245 passed, 20 skipped (Docker not available), 1 xfailed. A first run had 1 failure, `test_cli_packaging.py::test_wheel_holds_nothing_else`, because `backend/host_check.py` was not yet tracked by git (the test accepts only tracked files); it passes once the file is staged.

**Defects found and fixed:** WebSocket tests first failed: `TestClient.websocket_connect` ignores `base_url` and
always sends `Host: testserver`, which the check (correctly) refused. Fixed in the tests by passing the Host header.

**Known limitations (fail closed):** Host match is case-sensitive (`LOCALHOST` refused; browsers send lower case).
With duplicate Host headers Starlette uses the first, the same one routing uses; browsers cannot send two.

**Tool disclosure:** Claude Code wrote the module, wiring, tests and docs; Maryam approved the plan and scope
(main.py, host_check.py, README, dashboard.py); verified by the tests above and the full pytest run.

**Supervisor Q&A prep:**
- *Why not just bind 127.0.0.1?* Binding stops other machines, not the user's own browser: rebinding makes the
  browser connect to 127.0.0.1 itself. Only the Host header still names the attacker's domain.
- *Why 400 and not 403?* The request is malformed for this server (wrong authority); 400 is what
  `TrustedHostMiddleware` returns and it happens before routing, so no route behaviour is revealed.
