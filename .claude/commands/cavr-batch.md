Read CLAUDE.md and docs/cavr-m1-plan.md. Implement plan steps $ARGUMENTS in order, without asking me between steps.
For EACH step:
1. Write tests first (including failure/edge cases), then the code.
2. Run `.venv/bin/python -m pytest tests/test_cavr_*.py -q` until it passes; check the full suite has no new failures beyond the 7 known baseline ones.
3. Write that step's report notes as CLAUDE.md describes.
4. Run `git restore reports/scenario-validation.json`, stage ONLY that step's files by name (never reports/ or .claude/settings.local.json), and commit with the plan's message for that step.
Stop and ask me ONLY if: a test cannot be made to pass without weakening it, the plan needs a real change, or a file outside the allowed scope must be edited.
After the last step: note the commit hash before the batch started, have the cavr-reviewer agent review `git diff <that hash>..HEAD`, fix any BLOCKERs in one extra commit, and put MINOR items in "Known issues deferred".
Finally give me a short summary per step: what it does in plain words, key design decisions, test count, commit hash. Never git push.
