# Who edits which file

Edit only your own files to avoid merge conflicts. For shared files, agree in the group chat first.
Base text: team review draft (ASENT_FYP1_Mid_Report_Team_Review), split so each module has its own files.

| Owner | Files |
|---|---|
| Maryam Fatima (CAVR) | chapters/04_abstract.tex, chapters/chapter1_introduction.tex, chapters/cavr/*, chapters/appendix_requirements.tex (Appendix B) |
| Syed Sheharyar Ali (SATRA-RV) | chapters/chapter2_research.tex, chapters/chapter5_design.tex, chapters/satra/*, chapters/appendix_test_cases.tex (C), chapters/appendix_diagrams.tex (E) |
| Muhammad Ali Sajjad (SABLE) | chapters/chapter3_iteration_plan.tex, the SABLE parts of chapter4/6/8 (currently inline in those files), chapters/appendix_repository.tex (D), chapters/appendix_meetings.tex (F) |
| Shared (all 3) | chapters/chapter4_requirements.tex, chapters/chapter6_iteration1.tex and chapters/chapter8_testing.tex (shared/SABLE text), chapters/chapter9_development_evidence.tex (Ch 8), chapters/chapter10_fyp2_plan.tex (Ch 9), chapters/conclusion.tex (Ch 10), front matter, main.tex, references/references.bib |

Template file names are off by one: chapter8_testing.tex = Chapter 7, chapter9_development_evidence.tex = Chapter 8, chapter10_fyp2_plan.tex = Chapter 9.

Build: `latexmk -pdf main.tex` inside report/ (pdflatex + BibTeX). CI builds the PDF on every push (Actions -> Report -> artifact "FYP1-mid-report"). The Tectonic wrapper in build_support/ is no longer needed but kept for reference.
