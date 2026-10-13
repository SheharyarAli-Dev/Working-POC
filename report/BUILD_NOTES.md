# Report build notes

The report was built from `main.tex` with Tectonic 0.17.0 using the included
`build_support/tectonic_compat.tex` wrapper. Run this command from the `report`
directory in PowerShell:

```powershell
New-Item -ItemType Directory -Force build | Out-Null
Get-Content -LiteralPath 'build_support\tectonic_compat.tex' -Raw -Encoding utf8 |
  & 'tectonic.exe' --outdir 'build' --keep-intermediates --keep-logs -
```

Tectonic writes `build\texput.pdf`. The wrapper suppresses the pdfTeX-only
compression primitive and supplies numeric natbib options for IEEEtran. A fresh
Tectonic installation may need network access once to obtain its TeX bundle and
font metrics. The source and figures are self-contained; the compiler bundle is
an external build prerequisite.

The verified implementation snapshot documented in the report is the merged
`master` snapshot at `ffe8aa91ca89702e5db65b8f7ff129aa72f761cc`. Build output
is ignored by Git and excluded from the source archive.

## Historical post-sync verification (12 October 2026)

The report branch was reconciled with the then-current `origin/master` at
`36671ee` by merge commit `afc9a77`. After that merge, Tectonic 0.17.0 rebuilt
this source successfully to a 160-page PDF. Text extraction confirmed the cover,
contents, SABLE decision evidence, and bibliography; no undefined references
or fatal build errors were found. The build still reports existing TeX box
warnings (including an overfull box in the appendix diagrams), duplicate
`@page` object warnings from PDF generation, and a non-fatal Fontconfig
configuration warning. This records the warnings rather than claiming a
warning-free layout.

## Final report pass (13 October 2026)

The report branch was merged with current `origin/master` (`ffe8aa91`) using
merge commit `ea1abf92e09cd6b0ddd5ad8bd0c7cb4a094b2f54`. Tectonic 0.17.0 compiled the updated report from
`main.tex` successfully to 162 pages. Text extraction found no unresolved
references. The use-case, architecture, SABLE process, and domain-model pages
were visually reviewed. The PDF contains four editable TikZ design diagrams
and the preserved live SABLE evidence. The build emits TeX box warnings and
duplicate PDF page-object warnings, plus a non-fatal Fontconfig message; it is
not warning-free. The GitHub report workflow artifact is pending push and
workflow completion.

The focused source tests passed on the merged tree: 39 tests across
`test_sable_isolation.py`, `test_sable_frontend_contract.py`, and
`test_shared.py`. The initial collection attempt before installing the locked
requirements could not import `hcl2`; it is not counted as a test result. The
successful run used locked dependencies installed under the ignored
`report/build/test-deps` directory.
