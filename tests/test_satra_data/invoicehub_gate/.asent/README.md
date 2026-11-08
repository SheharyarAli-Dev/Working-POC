# ASENT configuration for InvoiceHub

Reviewed configuration (started from `asent init`). ASENT reads this folder from the BASE commit of
every change it gates, so a change to anything here needs a maintainer to merge it on purpose.
Format: docs/asent-config.md in the ASENT repository.

- `config.json`: CAVR, SATRA and SABLE are all enabled.
- `cavr/policy.json`: approves exactly `pypdf==6.21.4` (requirements.txt and dependencies.lock.json).
  The capability scopes describe the one pypdf call site, `app/pdf_adapter.py`: it reads the
  supplied invoice PDF from memory with the JBIG2 decoder binary disabled. Everything else is denied.
- `satra/contract.json`: AUTHZ.IDOR.001, SRS FR-03 (another user's invoice: 403, no state change).
  Counterfactual: `app/security.py::can_access_invoice` returns True; the trusted tests must fail on it.
- `satra/trusted_tests/`: trusted pytest files, each test tied to an SRS requirement. SATRA copies them
  to `asent_assurance/` in the project, so `conftest.py` finds `fixtures/invoice.pdf` at `parents[1]`.
- `satra/pytest.ini`: pytest config for the trusted tests, so the project's pytest.ini cannot change it.
- `sable/obligations.json`: `aws_iam_role.app` may only `s3:GetObject` and `s3:PutObject` on the objects
  of `aws_s3_bucket.invoice_data` (SRS FR-06, FR-07).
