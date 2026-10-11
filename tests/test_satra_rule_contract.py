"""Regression for the INCONCLUSIVE-on-every-run bug: seeded knowledge must satisfy the SATRA rule loader."""
import json
import re
from pathlib import Path
from backend.satra.seed_rules import RULES as LOADER_RULES

ROOT = Path(__file__).resolve().parents[1]


def test_seed_json_satisfies_loader_contract():
    rows = {r["id"]: r for r in json.loads((ROOT / "backend/threat_repo/seed/satra_rules.json").read_text())["records"]}
    for expected in LOADER_RULES:
        data = rows[expected["id"]]["data"] if "data" in rows[expected["id"]] else rows[expected["id"]]
        for key in ("pytest_template", "counterfactual_template", "expected_secure_behavior"):
            assert data.get(key) == expected.get(key), (expected["id"], key)


def test_seed_script_uses_loader_rule_source():
    text = (ROOT / "scripts/seed_threat_repository.py").read_text()
    assert re.search(r"from backend\.satra\.seed_rules import RULES", text)
    assert "from backend.satra.dictionary import RULES" not in text


def test_every_run_not_inconclusive_for_rules(scenario):
    from backend.threat_repo.satra_rules import dictionary
    run, ctx = scenario("safe")
    compiled, unsupported = dictionary(ctx.knowledge)
    assert not unsupported and len(compiled) == len(LOADER_RULES)
