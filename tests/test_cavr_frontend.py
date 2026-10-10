"""Source checks on the CAVR dashboard page. Offline; nothing is rendered.

The repository has no JavaScript test runner, so these tests read the TypeScript sources as text.
They can only show that something is absent from, or present in, the source: that the page does
not hold the old fixture names or fixed result strings, and that it asks the API for what it shows.
`npm --prefix frontend run build` (the TypeScript compiler) is the check that the page compiles.
"""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PAGE = REPO / "frontend" / "src" / "components" / "CavrModule.tsx"
PARTS = sorted((REPO / "frontend" / "src" / "components" / "cavr").glob("*.ts*"))


def sources() -> dict:
    return {path.name: path.read_text(encoding="utf-8") for path in [PAGE, *PARTS]}


def found(pattern: str) -> list:
    """(file, matched text) for every match of `pattern` in the page and its parts."""
    return [(name, match.group(0)) for name, text in sources().items() for match in re.finditer(pattern, text)]


# --- issue 1: the chips are the API's scenarios ------------------------------------------------------------------

OLD_FIXTURE_NAMES = ("pdf-clean-extractor", "reportlab-legacy", "dormant-exfil", "invoice-utils", "requests-security",
                     "sub-telemetry-hook", "approved_benign", "trigger_dependent", "transitive_risk", "'typosquat'")


def test_the_page_and_its_parts_exist():
    assert PAGE.is_file() and len(PARTS) >= 10


def test_no_old_fixture_name_is_left_in_the_page():
    assert found("|".join(re.escape(name) for name in OLD_FIXTURE_NAMES)) == []


def test_the_page_names_no_package_of_its_own():
    """Which package a chip sends is decided by GET /api/cavr/scenarios, not by the page."""
    assert found(r"pypdf|left-pad|==\d") == []


def test_chips_are_loaded_from_the_api_and_run_through_the_scenario_endpoint():
    page = PAGE.read_text(encoding="utf-8")
    assert "fetch('/api/cavr/scenarios')" in page
    assert "/api/cavr/run?scenario=${encodeURIComponent(scenario.id)}" in page
    # One chip per entry of the list, labelled with the entry's own name.
    assert re.search(r"scenarios[^\n]*\.map\(\(scenario\)", page) and "{scenario.display_name}" in page
    # The page no longer builds a request from a package name of its own.
    assert "/api/cavr/intercept" not in page
