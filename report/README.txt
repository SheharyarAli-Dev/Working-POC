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

The integrated implementation is merged to master at
ffe8aa91ca89702e5db65b8f7ff129aa72f761cc from exact tested PR #5 head
554b6d51acca29f99c396c3040362015ee460262. Some dedicated SABLE UI figures in
Chapter 8 are explicitly identified as historical captures from earlier source
snapshots; current post-merge UI evidence and its run identifiers are in the
demo runbook. See Chapter 7 for CI provenance. Run repository setup scripts
from the project root, not from this report directory.

Some team records remain pending official evidence: proposal-panel actions,
meeting/progress minutes, approved schedule, coordinator name, and member-level
contribution/disclosure confirmations. The report leaves these unclaimed.
