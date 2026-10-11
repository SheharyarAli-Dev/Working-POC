# Build notes

The included `ASENT_FYP1_Mid_Report_Team_Review.pdf` was built on Windows with **Tectonic 0.17.0**. The standard `pdflatex`/BibTeX route written in `README.txt` was unavailable in the build environment and was **not verified**.

Tectonic required the included build-only `tectonic_compat.tex` wrapper because the report class contains the pdfTeX-only `\pdfcompresslevel` primitive and its `natbib` options conflict with the IEEEtran numeric bibliography style. The wrapper suppresses that compression assignment and loads numeric `natbib` options. It does not alter the report source. Tectonic ran the bibliography and TeX rerun passes and produced an 84-page PDF.

To repeat the compatibility-assisted build from this `report_source` directory in PowerShell, after installing Tectonic 0.17.0:

```powershell
New-Item -ItemType Directory -Force build | Out-Null
Get-Content -LiteralPath 'build_support\tectonic_compat.tex' -Raw -Encoding utf8 |
  & 'tectonic.exe' --outdir 'build' --keep-intermediates --keep-logs -
```

Tectonic writes `build\texput.pdf` when the wrapper is piped through standard input. Rename or copy that output to the team-review PDF filename after verifying it. This repeat command is provided as a reproducible route; the verified build used the same wrapper and options with Tectonic's extracted executable and `build\pdf` output directory.
