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

The verified implementation snapshot documented in the report is
`integration/sable-satra-cavr` at
`665b2241693c4833e9815038d8a8cdf63707bd6d`. Build output is ignored by Git and
excluded from the source archive.

## Post-sync verification (12 October 2026)

The report branch was reconciled with the then-current `origin/master` at
`36671ee` by merge commit `afc9a77`. After that merge, Tectonic 0.17.0 rebuilt
this source successfully to a 160-page PDF. Text extraction confirmed the cover,
contents, SABLE decision evidence, and bibliography; no undefined references
or fatal build errors were found. The build still reports existing TeX box
warnings (including an overfull box in the appendix diagrams), duplicate
`@page` object warnings from PDF generation, and a non-fatal Fontconfig
configuration warning. This records the warnings rather than claiming a
warning-free layout.
