"""The CAVR dashboard page. Offline.

Two kinds of test, because the repository has no JavaScript test runner and no browser:

1. Source checks. They read the TypeScript sources as text and can only show that something is
   absent from, or present in, the source: no old fixture name, no fixed result string.
2. Render checks. `tests/test_cavr_data/render_cavr.mjs` bundles the real components with esbuild
   and renders them to HTML with react-dom/server. The test gives them real answers of the backend
   (an offline dashboard run from `test_cavr_api.Dashboard`) and checks what is printed. They need
   Node.js and `frontend/node_modules` (`npm --prefix frontend install`) and are skipped without.

What neither covers: clicks, the live event stream and the look of the page in a browser.
`npm --prefix frontend run build` (the TypeScript compiler) is the check that the page compiles.
"""
import html
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from backend.cavr import api
from backend.cavr.pipeline import STATUSES   # VERIFIED, REJECTED, BLOCK, UNRESOLVED: the order of the report
from test_cavr_api import Dashboard
from test_cavr_support import PYPDF_SHA256

REPO = Path(__file__).resolve().parents[1]
FRONTEND = REPO / "frontend"
PAGE = FRONTEND / "src" / "components" / "CavrModule.tsx"
PARTS = sorted((FRONTEND / "src" / "components" / "cavr").glob("*.ts*"))
RENDERER = REPO / "tests" / "test_cavr_data" / "render_cavr.mjs"
DASH = "—"


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
    # The page no longer builds a request from a package name of its own.
    assert found("/api/cavr/intercept") == []


# --- issue 2: no result string of the page's own ------------------------------------------------------------------

FIXED_RESULT_STRINGS = (
    "VERIFIED MATCH",                 # the proof drawer said this for every run
    "|| 1}",                          # "Counterfactual Container Runs (1)" for an empty list
    "timeTaken",                      # fixed stage timings: '12ms', '680ms', ...
    "Matches",                        # the cache dialog's Re-verify button, on a timer
    "13 PHASES", "13-phase",          # the pipeline has one path and six stages
    "Priority Score",                 # a worked example with an invented score
    "Typosquat / Homoglyph Detected", # computed in the browser, not by the backend
    "pristine baseline", "A clean environment was created",
    "LIVE FEED", "Honeytoken", "non-root (10001)", "256 MB", "0.5 cores",   # the sandbox panel: nothing is run
    "Trusted Packages", "Pre-verified",
)
# What four tabs printed where a value was missing, each a different wording.
OLD_PLACEHOLDERS = ("'pending'", "'not downloaded'", "'not read'", "'not built'", "'not inferred'", "'ANALYZING'",
                    "'EVALUATING'", "'none'", "'not asked'", "\"Pending.\"", "'n/a'")
PLACEHOLDER_FILES = ("OverviewTab.tsx", "AssuranceTab.tsx", "StageDetailPanel.tsx", "MetricsTab.tsx")


def test_no_fixed_result_string_is_left_in_the_page():
    assert found("|".join(re.escape(text) for text in FIXED_RESULT_STRINGS)) == []
    assert found(r"'\d+ ?ms'") == []          # no literal duration anywhere


def test_a_value_that_was_not_computed_is_printed_as_a_dash():
    types = (PAGE.parent / "cavr" / "types.ts").read_text(encoding="utf-8")
    assert "export const NOT_COMPUTED = '—';" in types and "export const shown" in types
    for name in PLACEHOLDER_FILES:
        # A CSS class name is not text on the page, so lines that only choose a class are left out.
        printed = [line for line in sources()[name].splitlines() if "className=" not in line]
        assert [text for text in OLD_PLACEHOLDERS if any(text in line for line in printed)] == [], name
    assert found("Awaiting execution|Evaluating\\.\\.\\.") == []
    # The dash is written in one place only; everything else uses the constant.
    assert [name for name, _ in found("—")] == ["types.ts"]


def test_the_timeline_is_the_stage_list_of_the_proof():
    page = PAGE.read_text(encoding="utf-8")
    assert "<Timeline stages={runState.proofData?.stages || null}" in page and found("timelineStepsData") == []


# --- render checks: the real components, given real answers of the backend ---------------------------------------

@pytest.fixture
def dashboard(tmp_path, monkeypatch):
    return Dashboard(tmp_path, monkeypatch)


def render(tmp_path, *views) -> list:
    """The text of each view, as a list of the pieces of text between its tags."""
    if shutil.which("node") is None or not (FRONTEND / "node_modules" / "esbuild").is_dir():
        pytest.skip("needs Node.js and frontend/node_modules (npm --prefix frontend install)")
    work = tmp_path / "render"
    work.mkdir(exist_ok=True)
    done = subprocess.run(["node", str(RENDERER), str(FRONTEND), str(work)], input=json.dumps({"views": list(views)}),
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    rendered = json.loads(done.stdout)["html"]
    assert len(rendered) == len(views)
    return [[html.unescape(piece).strip() for piece in re.split(r"<[^>]+>", markup) if piece.strip()] for markup in rendered]


def run_data(dashboard, scenario) -> dict:
    """One offline run of a chip: what the page gets from the stream and from the proof endpoint, as JSON."""
    run_id, _ = dashboard.run(scenario)
    return json.loads(json.dumps({"events": api.RUN_EVENTS[run_id], "proof": api.get_proof(run_id)}))


def shown(value) -> str:
    """What the page's `shown` prints for a JSON value."""
    if value is None or value == "":
        return DASH
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))      # JavaScript prints 12.0 as 12
    return str(value)


def after(pieces, label) -> str:
    """The piece of text that follows `label` (which must be there exactly once)."""
    assert pieces.count(label) == 1, (label, pieces)
    return pieces[pieces.index(label) + 1]


def test_the_page_before_any_run_shows_no_result(tmp_path):
    (page,) = render(tmp_path, {"view": "page"})
    text = " ".join(page)
    assert after(page, "INTERCEPTED TARGET") == DASH and "No run yet. Choose one of the requests." in page
    assert "Loading scenarios..." in page and "0 stored" in page
    assert not any(status in text for status in STATUSES) and "HASH_" not in text
    assert page.count("did not run") == 0 and page.count("0 values") == 6
    # Verdict, policy state, hash, fast gate, cache hit, escalated: every one a dash.
    assert after(page, "POLICY STATE:") == DASH and after(page, "Artifact SHA-256") == DASH and after(page, "Fast gate") == DASH
    assert "VERDICT: " + DASH in page and "Cache hit: " + DASH in page and "Escalation: " + DASH in page


def test_the_chips_are_the_scenarios_of_the_backend(tmp_path):
    listed = api.list_scenarios()
    (chips,) = render(tmp_path, {"view": "chips", "scenarios": listed})
    assert chips == ["Real requests (live pipeline):"] + [scenario["display_name"] for scenario in listed]
    (empty,) = render(tmp_path, {"view": "chips", "scenarios": None})
    assert empty == ["Real requests (live pipeline):", "Loading scenarios..."]


@pytest.mark.parametrize("scenario", [scenario["id"] for scenario in api.SCENARIOS])
def test_the_timeline_prints_what_each_stage_returned_and_a_dash_for_the_rest(dashboard, tmp_path, scenario):
    stages = run_data(dashboard, scenario)["proof"]["stages"]
    (timeline,) = render(tmp_path, {"view": "timeline", "stages": stages})
    for stage in stages:
        start = timeline.index(stage["title"])
        headline = stage["values"][0]
        assert timeline[start + 1] == (f"{headline['label']}: {shown(headline['value'])}" if stage["ran"] else "did not run")
        for item in stage["values"]:
            assert after(timeline[start:], item["label"]) == shown(item["value"]), (stage["id"], item)
    not_computed = sum(item["value"] is None for stage in stages for item in stage["values"])
    assert timeline.count(DASH) == not_computed and timeline.count("did not run") == sum(not stage["ran"] for stage in stages)
    assert not any(re.fullmatch(r"\d+ ?ms", piece) for piece in timeline)      # no time per stage


def test_the_proof_drawer_prints_the_hash_result_of_each_run(dashboard, tmp_path):
    runs = {scenario: run_data(dashboard, scenario)["proof"] for scenario in ("verified", "tampered_wheel", "network_off",
                                                                              "not_on_allowlist")}
    drawers = dict(zip(runs, render(tmp_path, *({"view": "proof", "proof": proof} for proof in runs.values()))))
    hashes = lambda pieces: (after(pieces, "Registry SHA-256:"), after(pieces, "SHA-256 of the downloaded file:"),
                             after(pieces, "Result:"), after(pieces, "Bytes equal the registry digest:"))
    assert hashes(drawers["verified"]) == (PYPDF_SHA256, PYPDF_SHA256, "HASH_MATCH", "true")
    arrived = runs["tampered_wheel"]["hash_comparison"]["actual_sha256"]
    assert arrived != PYPDF_SHA256 and hashes(drawers["tampered_wheel"]) == (PYPDF_SHA256, arrived, "HASH_MISMATCH", "false")
    # Nothing was hashed in these two runs: no "match" and no "mismatch" is printed for them.
    assert hashes(drawers["network_off"]) == (DASH, DASH, "REGISTRY_UNAVAILABLE", DASH)
    assert hashes(drawers["not_on_allowlist"]) == (DASH, DASH, DASH, DASH)
    for scenario, pieces in drawers.items():
        verdict = runs[scenario]["cavr_verdict"]
        assert after(pieces, "Status:") == verdict["status"] and after(pieces, "Reason:") == verdict["reason"]
        assert after(pieces, "fast_gate_ms:") == shown(verdict["fast_gate_ms"]) and "Counterfactual runs (0):" in pieces
        assert after(pieces, "Container command:") == api.NOT_RUN and "VERIFIED MATCH" not in " ".join(pieces)
    assert after(drawers["tampered_wheel"], "Demo condition:") == "tampered_wheel"
    assert after(drawers["verified"], "Demo condition:") == DASH


def test_the_overview_shows_the_verdict_and_dashes_for_what_was_not_computed(dashboard, tmp_path):
    blocked, verified = run_data(dashboard, "not_on_allowlist"), run_data(dashboard, "verified")
    block_view, verified_view = render(tmp_path, {"view": "overview", **blocked}, {"view": "overview", **verified})
    assert "VERDICT: BLOCK" in block_view and after(block_view, "POLICY STATE:") == "BLOCK"
    assert after(block_view, "Artifact SHA-256") == DASH                      # nothing was downloaded
    assert after(block_view, "Fast gate") == f"{shown(blocked['proof']['cavr_verdict']['fast_gate_ms'])} ms"
    assert "Cache hit: no" in block_view and "Escalation: " + DASH in block_view
    assert "VERDICT: ALLOW" in verified_view and after(verified_view, "POLICY STATE:") == "VERIFIED"
    assert after(verified_view, "Artifact SHA-256") == PYPDF_SHA256[:16] + "..."
    assert "HASH_MATCH against the registry digest" in verified_view


def test_the_requirements_tab_prints_what_a_stage_returned_and_no_pass_of_its_own(dashboard, tmp_path):
    blocked = run_data(dashboard, "not_on_allowlist")
    (table,) = render(tmp_path, {"view": "requirements", **blocked})
    returned = lambda requirement: table[table.index(requirement):][5]     # id, name, description, module, event, returned
    assert returned("FR-2") == "BLOCK (NOT_ON_ALLOWLIST)" and returned("FR-6") == "BLOCK (gate / NOT_ON_ALLOWLIST)"
    assert returned("FR-1") == "captured (" + blocked["proof"]["cavr_verdict"]["request"]["source"] + ")"
    assert [returned(requirement) for requirement in ("FR-3", "FR-4", "FR-5", "FR-7", "FR-8", "FR-9", "NFR-1", "NFR-2")] == [DASH] * 8
    assert returned("FR-10") == blocked["proof"]["certificate_id"]
    assert "PASS" not in table and "FAIL" not in table and "NOT RUN" not in table


# --- issue 3: fast_gate_ms per verdict and per cache lookup ---------------------------------------------------------

def table_rows(pieces, heading, columns, rows):
    """The cells of the table under `heading`, as `rows` lists of `columns` cells (the header row is left out)."""
    start = pieces.index(heading) + 1 + columns
    cells = pieces[start:start + rows * columns]
    return [cells[row * columns:(row + 1) * columns] for row in range(rows)]


def test_the_metrics_tab_lists_the_time_per_verdict_and_per_cache_lookup(dashboard, tmp_path):
    for scenario in ("verified", "verified_again", "known_vulnerable", "not_on_allowlist", "tampered_wheel"):
        dashboard.run(scenario)
    report = json.loads(json.dumps(api.get_metrics()))
    assert report["verdicts"] == 4                    # the tampered run was under a demo condition: not logged
    (tab,) = render(tmp_path, {"view": "metrics", "metrics": report})
    times = report["fast_gate_ms"]
    assert table_rows(tab, "fast_gate_ms by verdict", 4, 4) == [
        [status, shown(row["count"]), shown(row["p50"]), shown(row["p95"])] for status, row in times["by_status"].items()]
    assert [row[0] for row in table_rows(tab, "fast_gate_ms by verdict", 4, 4)] == list(STATUSES)
    assert table_rows(tab, "fast_gate_ms by verdict", 4, 4)[3] == ["UNRESOLVED", "0", DASH, DASH]     # none logged: no time
    assert table_rows(tab, "fast_gate_ms by cache lookup", 4, 3) == [
        [found, shown(row["count"]), shown(row["p50"]), shown(row["p95"])] for found, row in times["by_cache_lookup"].items()]
    pairs = times["by_status_and_cache_lookup"]
    assert table_rows(tab, "fast_gate_ms by verdict and cache lookup", 5, len(pairs)) == [
        [row["status"], row["cache_lookup"], shown(row["count"]), shown(row["p50"]), shown(row["p95"])] for row in pairs]
    assert ["VERIFIED", "HIT"] in [row[:2] for row in table_rows(tab, "fast_gate_ms by verdict and cache lookup", 5, len(pairs))]
    # Two hit rates, each with what it is a rate of. No single percentile over all verdicts.
    assert after(tab, "Cache hit rate, all verdicts") == "25.0%" and "1 of 4 verdicts" in tab
    assert after(tab, "Cache hit rate, lookups only") == "33.3%" and "1 of 3 verdicts that reached the cache lookup" in tab
    assert not [piece for piece in tab if "Fast gate p50" in piece or "Fast gate p95" in piece]
    recent = table_rows(tab, "Last verdicts (verdict log)", 7, 4)
    assert [(row[2], row[5]) for row in recent] == [("BLOCK", "NOT_REACHED"), ("REJECTED", "MISS"), ("VERIFIED", "HIT"),
                                                    ("VERIFIED", "MISS")]


def test_the_metrics_tab_with_an_empty_log_shows_dashes(dashboard, tmp_path):
    (tab,) = render(tmp_path, {"view": "metrics", "metrics": json.loads(json.dumps(api.get_metrics()))})
    assert table_rows(tab, "fast_gate_ms by verdict", 4, 4) == [[status, "0", DASH, DASH] for status in STATUSES]
    assert table_rows(tab, "fast_gate_ms by cache lookup", 4, 3) == [[found, "0", DASH, DASH] for found in ("HIT", "MISS", "NOT_REACHED")]
    assert after(tab, "Cache hit rate, all verdicts") == DASH and after(tab, "Cache hit rate, lookups only") == DASH
    assert tab.count("No verdict has been logged yet.") == 3      # the pairs table, the legend, the last verdicts
