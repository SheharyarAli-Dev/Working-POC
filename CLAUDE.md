# Rules for this branch (cavr, owner: Maryam Fatima)

## Scope
- Only edit backend/cavr/, tests/test_cavr_*, frontend/src/components/cavr/, docs/report-notes/.
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

## Report notes (do this at the end of EVERY plan step)
Append to docs/report-notes/cavr-report-notes.md, under a heading "Step N — <title> (<date>)":
- **Ch 6 Implementation:** files/classes/functions added or changed, what each does, key algorithm in 3–5 lines.
- **Design decisions:** each choice made, alternatives considered, and why (trade-offs).
- **Requirements covered:** which CAVR FRs/NFRs this step implements (e.g. FR-CAVR-03) with one-line acceptance check.
- **Ch 7 Test cases:** a table: Test ID | Purpose | Input | Expected | Result (pass/fail) — include edge/failure cases.
- **Defects found and fixed:** what the reviewer or tests caught, and the fix.
- **Known limitations / deferred:** what is out of scope and where it will be handled.
- **Tool disclosure (Ch 8.7):** what Claude Code generated, what Maryam reviewed/changed, and how it was verified.
- **Supervisor Q&A prep:** 2–3 likely questions with short answers.
Keep it factual and short; real file names, test names and numbers only. Never invent results.
Record review outcomes in ONE line per step (number of passes, verdict, open MINOR count). Do not narrate review history.

## Study Q&A
When Maryam asks an "explain" or "why" question about CAVR, also append the question and a short plain-language answer (with file/function names and one example) to docs/report-notes/cavr-study-qa.md under a heading for the current batch. Keep each answer under 15 lines.
