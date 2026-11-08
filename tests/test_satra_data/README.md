# SATRA test data

`invoicehub_gate/` is an overlay for the real InvoiceHub trusted suite through gate mode
(`tests/test_satra_config.py::test_invoicehub_trusted_suite_passes_through_gate_mode_on_the_host_harness`,
`tests/test_satra_project_image_docker.py::test_real_gate_run_of_the_invoicehub_trusted_suite_passes_on_its_base`).

- Source: `maryamfatimaaaaa/asent-target-invoicehub`, base commit `57ae3dc24f7ff705d04ec1538548726692ae2453`
  (the base of the `.gitignore`-only pull request whose gate gave SATRA INCONCLUSIVE), via
  `git archive 57ae3dc .asent dependencies.lock.json requirements.txt`. Byte copies.
- One edit: `.asent/config.json` declares `"trusted_data": ["fixtures"]`, which is the target's config
  once that line is added there.
- The rest of the project (`app/`, `tests/`, `fixtures/`, `SRS.md`, `plan.md`, `policy.json`, `pytest.ini`)
  is identical at that commit to `demo_project/InvoiceHub/`, so the tests take it from there.
- `.asent/` folders are not collected by pytest (`norecursedirs` default `.*`).
