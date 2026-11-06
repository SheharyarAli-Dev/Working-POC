# ASENT repository guidance

## Project and module boundaries

ASENT is a local, evidence-driven assurance prototype for AI-assisted software changes. It routes a candidate snapshot to applicable specialized analyzers and combines their current, integrity-checked evidence at the shared orchestrator/final gate before accepting, blocking, or requesting review. A standalone module verdict is not the shared ASENT gate.

- **CAVR** evaluates dependency/package provenance, risk, and bounded behavior evidence before dependencies are trusted.
- **SATRA-RV** evaluates supported application-code security contracts and differential tests, and accepts repairs only after trusted checks pass in the configured isolation boundary.
- **SABLE** evaluates continuity of a previously established Terraform security obligation through structural refactors. Its bounded model covers supported Terraform/HCL constructs for AWS S3 buckets, IAM roles, and modeled identity policies, resource correspondence, and authorization projection.

SABLE does not establish arbitrary Terraform/HCL or IAM semantics, deployed AWS state, live AWS validation, or equivalence beyond the modeled constructs. Unresolved bindings, ambiguity, unsupported syntax, missing baselines, and missing/untrusted evidence must remain UNKNOWN, INCONCLUSIVE, or REVIEW as appropriate; never turn them into acceptance.

## Evidence and research discipline

- Label statements as verified facts, code-derived inferences, assumptions, or unknowns when that distinction matters. Trace UI claims through handlers, API, implementation, outputs, and tests.
- Do not infer implementation from a tab, label, fixture, or historical report. Distinguish current test evidence from dated logs/screenshots and authored benchmark labels from independently reviewed ground truth.
- Never invent rubric requirements, official dates, benchmark definitions, reviewers, labels, test results, or implementation status. Verify the official final-evaluation date and rubric from actual official artifacts before stating them; otherwise say they remain unverified.
- Keep unsupported or unmeasured semantics explicit. Do not claim independent validation or comparative superiority without independent review and reproducible measurements.

## Git and integration safety

- Before edits or integration, inspect branch, HEAD, status, staged/unstaged diffs, untracked files, remotes, refs, and relevant history. Local remote-tracking refs may be stale; use live remote evidence when a task requires current GitHub state.
- Preserve dirty, untracked, stashed, and teammate work. Inspect both index and worktree versions before editing a staged file. Back up outside the repository before integration and verify the backup.
- Do not use destructive reset/clean, discard work, blind checkout, or overwrite files wholesale. Do not force-push. Never push to the team repository without explicit authorization. Push to a personal repository only when explicitly authorized and after reviewing the exact publication set, history, and remote tip.
- Do not change repository visibility/default branch or delete branches without explicit authorization and accounting for unique history.
- Keep the submitted midterm report/PDF closed and unchanged unless the user explicitly reopens that work.

## Publication and privacy review

Before preparing a public commit, scan the exact files and reachable history intended for publication for credentials, tokens, private student information, local absolute paths, machine identities, and unrelated material. Do not print secret values. Review reports, PDFs, screenshots, generated scenario reports, diagrams, handoffs, and bulk evidence individually; exclude them until appropriate for publication. Check test claims against the exact tested revision and identify historical evidence as historical. A heuristic scan is not a comprehensive secret audit.

## Testing and change practice

- Inspect the relevant implementation and tests together; make the smallest scoped change that addresses a confirmed defect. Do not rewrite teammate modules blindly or weaken sandboxing, trust checks, or fail-closed behavior to make tests green.
- Run focused tests after a logical change, then appropriate broader suites/builds when scope warrants. Report exact commands, exit status, counts, skips/warnings, and environment blockers. Distinguish passed, failed, skipped, and not run. Never present historical output as a current result.
- Avoid running tests that overwrite tracked/generated reports without first checking their effects and preserving existing content.
- Keep Terraform/Checkov, container, model, and other optional-tool claims bounded to what was actually available and executed.

## Collaboration and reporting

Work in coherent batches: inspect state and requirements, trace the relevant end-to-end path, make a bounded change, verify it, inspect the final diff, then report decisions, evidence, risks, exact commands/results, and next actions together. Prefer reasonable assumptions and action over unnecessary clarification; ask only when a missing user decision or external prerequisite blocks safe progress.
