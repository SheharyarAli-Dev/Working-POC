# Rules for this branch (cavr, owner: Maryam Fatima)

## Scope
- Only edit backend/cavr/, tests/test_cavr_*, frontend/src/components/cavr/.
- Ask before touching backend/main.py, backend/orchestrator/, backend/integrations/,
  or anything in backend/satra/ or backend/sable/ (other members' modules).

## Mid (M1) goals for CAVR
- C1 capture: pip wrapper/gateway that captures real `pip install X==Y` and requirements.txt edits.
- C2 requirement gate: allowlist/lockfile/policy check -> immediate BLOCK if not permitted.
- C3 fast gate on real PyPI artifacts: real SHA-256 of the downloaded file vs registry digest,
  transitive tree from real metadata (Requires-Dist), OSV with correct version-range checks,
  light AST risk scan, verdict cache keyed on the 8-field digest
  (ecosystem, name, version, artifact sha256, subtree digest, contract digest, policy version, analyzer version).
- C4 capability contract from the project's real imports and call sites.
- Output VERIFIED / REJECTED / UNRESOLVED with evidence.

## Rules
- No fixture-faked results: hashes come from real files; anything unknown -> UNRESOLVED (fail closed).
- Every feature gets pytest tests, including failure/edge cases.
- Run `.venv/bin/python -m pytest -q` before each commit.
- Small commits with clear messages (feat(cavr): ..., fix(cavr): ..., test(cavr): ...).
- Explain every change so I can defend it line by line.
