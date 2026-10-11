ASENT FYP-I Mid-Evaluation Report Source

This directory contains the editable LaTeX report, bibliography, FAST-NUCES
class and style files, and figures used by the report. The report is scoped to
the mid-evaluation implementation; it is not the final FYP submission.

Rebuild with Tectonic 0.17.0 from this directory in PowerShell:

  New-Item -ItemType Directory -Force build | Out-Null
  Get-Content -LiteralPath 'build_support\tectonic_compat.tex' -Raw -Encoding utf8 |
    & 'tectonic.exe' --outdir 'build' --keep-intermediates --keep-logs -

The PDF is written as build\texput.pdf. Rename or copy it only after checking
the build log and rendered pages. The wrapper handles the class's pdfTeX
compression primitive and selects numeric natbib options for IEEEtran.

The code branch verified for this report is integration/sable-satra-cavr at
665b2241693c4833e9815038d8a8cdf63707bd6d. See Chapter 8 for CI provenance and
Chapter 9 for SABLE UI evidence. Run repository setup scripts from the project
root, not from this report directory.

Some team records remain pending official evidence: proposal-panel actions,
meeting/progress minutes, approved schedule, coordinator name, and member-level
contribution/disclosure confirmations. The report leaves these unclaimed.
