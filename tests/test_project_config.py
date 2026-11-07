"""Step 1 of docs/dev-env-plan.md: the per-project `.asent/` configuration (schema + loader).

Every case builds a real `.asent/` directory in tmp_path and loads it with
`backend.project_config.load`. A config that is missing, unreadable, unsafe, an unreviewed starter
or inconsistent must come back `valid=False` with a named problem code: the gate turns that into
REVIEW (fail closed). Nothing here is mocked.
"""
import json
import os
from pathlib import Path

import pytest

from backend.project_config import load, tree_digest
from backend.project_config import schema as config_schema
from backend.cavr.capability_contract import capability_policy_problem

REPO = Path(__file__).resolve().parents[1]

CAVR_POLICY = {
    "project_task_description": "Invoice PDF text extraction",
    "allowed_scopes": ["FILE_READ:invoice_documents", "PROCESS_EXEC:none", "NETWORK_CONNECT:none"],
    "approved_requirements": ["pypdf>=5,<7"],
    "denied_packages": [{"name": "reqeusts", "reason": "typosquat of requests"}],
}
SATRA_CONTRACT = {
    "rule_id": "AUTHZ.IDOR.001",
    "route": "GET /invoices/{invoice_id}",
    "expected_status": 403,
    "authority_sources": ["SRS.md#FR-03"],
    "preconditions": ["authenticated normal user"],
    "scope": ["app/main.py", "app/security.py"],
    "counterfactual": {"operator": "RETURN_TRUE", "target": "app/security.py::can_access_invoice"},
}
SABLE_OBLIGATIONS = {"obligations": [{
    "id": "invoice-data-least-privilege", "principal": "aws_iam_role.app",
    "protected_asset": "aws_s3_bucket.invoice_data", "actions": ["s3:GetObject", "s3:PutObject"]}]}


def full_config():
    return {
        "schema_version": 1,
        "project": {"name": "example"},
        "modules": {
            "CAVR": {"enabled": True, "policy": "cavr/policy.json", "requirements_files": ["requirements.txt"]},
            "SATRA": {"enabled": True, "contract": "satra/contract.json", "trusted_tests": "satra/trusted_tests",
                      "source_dirs": ["app"], "project_security_tests": "tests/test_security.py"},
            "SABLE": {"enabled": True, "terraform_dirs": ["infra"], "obligations": "sable/obligations.json"},
        },
    }


def write(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data, indent=2))


def make(tmp_path, config=None, *, cavr=CAVR_POLICY, contract=SATRA_CONTRACT, obligations=SABLE_OBLIGATIONS):
    root = tmp_path / ".asent"
    write(root / "config.json", full_config() if config is None else config)
    if cavr is not None:
        write(root / "cavr/policy.json", cavr)
    if contract is not None:
        write(root / "satra/contract.json", contract)
        write(root / "satra/trusted_tests/test_authz.py", "def test_placeholder():\n    assert True\n")
    if obligations is not None:
        write(root / "sable/obligations.json", obligations)
    return root


def codes(result):
    return {problem.split(":", 1)[0] for problem in result.problems}


# --- valid configurations ---------------------------------------------------------------------------

def test_full_valid_config_loads(tmp_path):
    result = load(make(tmp_path))
    assert result.valid, result.problems
    assert result.problems == ()
    assert result.config.project.name == "example"
    assert result.module_state("CAVR") == "enabled"
    assert result.documents["cavr_policy"] == CAVR_POLICY
    assert result.documents["satra_contract"]["rule_id"] == "AUTHZ.IDOR.001"
    assert result.documents["sable_obligations"]["obligations"][0]["minimum_score"] == 6
    assert result.documents["satra_trusted_tests"] == ["test_authz.py"]
    assert len(result.digest) == 64


def test_disabled_module_with_reason_is_valid_and_its_files_are_not_required(tmp_path):
    config = full_config()
    config["modules"]["SABLE"] = {"enabled": False, "reason": "no cloud infrastructure in this service"}
    result = load(make(tmp_path, config, obligations=None))
    assert result.valid, result.problems
    assert result.module_state("SABLE") == "disabled"
    assert result.disabled_reason("SABLE") == "no cloud infrastructure in this service"
    assert "sable_obligations" not in result.documents


def test_absent_module_section_is_valid_at_load_time(tmp_path):
    # Whether the module applies depends on head's files; the gate (step 4) turns "applies but absent" into REVIEW.
    config = full_config()
    del config["modules"]["SATRA"]
    result = load(make(tmp_path, config, contract=None))
    assert result.valid, result.problems
    assert result.module_state("SATRA") == "absent"


def test_defaults_are_filled_in(tmp_path):
    config = {"schema_version": 1, "project": {"name": "x"}, "modules": {"CAVR": {"enabled": True}}}
    result = load(make(tmp_path, config))
    assert result.valid, result.problems
    cavr = result.config.modules.CAVR
    assert cavr.policy == "cavr/policy.json" and cavr.requirements_files == ["requirements.txt"] and cavr.verify == "all"


# --- missing / unreadable ---------------------------------------------------------------------------

def test_missing_directory(tmp_path):
    result = load(tmp_path / ".asent")
    assert not result.valid and codes(result) == {"ASENT_CONFIG_MISSING"}
    assert result.digest is None and tree_digest(tmp_path / ".asent") is None


def test_asent_is_a_file_not_a_directory(tmp_path):
    (tmp_path / ".asent").write_text("{}")
    assert codes(load(tmp_path / ".asent")) == {"ASENT_CONFIG_MISSING"}


def test_missing_config_json(tmp_path):
    root = make(tmp_path)
    (root / "config.json").unlink()
    result = load(root)
    assert not result.valid and "ASENT_CONFIG_MISSING" in codes(result)


@pytest.mark.parametrize("text", ["{not json", "", "null", "[]", '"text"', "\xff\xfe"])
def test_bad_json_or_not_an_object(tmp_path, text):
    root = make(tmp_path)
    (root / "config.json").write_bytes(text.encode("latin-1"))
    result = load(root)
    assert not result.valid and codes(result) & {"ASENT_CONFIG_JSON", "ASENT_CONFIG_SCHEMA"}


def test_duplicate_json_keys_are_rejected(tmp_path):
    # {"enabled": true, "enabled": false} would silently keep the last value.
    root = make(tmp_path)
    (root / "config.json").write_text('{"schema_version": 1, "schema_version": 1, "project": {"name": "x"}, "modules": {}}')
    assert "ASENT_CONFIG_JSON" in codes(load(root))


# --- schema -----------------------------------------------------------------------------------------

def test_unknown_top_level_key(tmp_path):
    config = full_config(); config["extra"] = True
    assert "ASENT_CONFIG_SCHEMA" in codes(load(make(tmp_path, config)))


def test_unknown_module_name(tmp_path):
    config = full_config(); config["modules"]["NEWMOD"] = {"enabled": True}
    assert "ASENT_CONFIG_SCHEMA" in codes(load(make(tmp_path, config)))


def test_cavr_mode_key_is_rejected_so_a_repository_cannot_pick_the_lockfile_analyzer(tmp_path):
    config = full_config(); config["modules"]["CAVR"]["mode"] = "lockfile"
    result = load(make(tmp_path, config))
    assert not result.valid and "ASENT_CONFIG_SCHEMA" in codes(result)
    assert any("mode" in problem for problem in result.problems)


@pytest.mark.parametrize("version", [0, 2, "1", None, True, 1.0])
def test_wrong_schema_version(tmp_path, version):
    config = full_config(); config["schema_version"] = version
    assert "ASENT_CONFIG_SCHEMA" in codes(load(make(tmp_path, config)))


def test_enabled_must_be_a_boolean(tmp_path):
    config = full_config(); config["modules"]["CAVR"]["enabled"] = "yes"
    assert "ASENT_CONFIG_SCHEMA" in codes(load(make(tmp_path, config)))


@pytest.mark.parametrize("reason", [None, "", "   "])
def test_disabled_without_reason(tmp_path, reason):
    config = full_config()
    config["modules"]["SABLE"] = {"enabled": False} if reason is None else {"enabled": False, "reason": reason}
    result = load(make(tmp_path, config))
    assert not result.valid and "ASENT_CONFIG_SCHEMA" in codes(result)
    assert any("reason" in problem for problem in result.problems)


@pytest.mark.parametrize("field,value", [
    ("policy", "../outside.json"), ("policy", "/etc/passwd"), ("policy", "C:\\policy.json"),
    ("policy", "cavr\\policy.json"), ("policy", ""), ("requirements_files", ["../requirements.txt"]),
    ("requirements_files", [".git/config"]), ("source_dirs", ["/abs"]), ("requirements_files", []),
])
def test_unsafe_or_empty_paths(tmp_path, field, value):
    config = full_config(); config["modules"]["CAVR"][field] = value
    result = load(make(tmp_path, config))
    assert not result.valid and "ASENT_CONFIG_SCHEMA" in codes(result)


def test_sable_terraform_dir_escaping_repo(tmp_path):
    config = full_config(); config["modules"]["SABLE"]["terraform_dirs"] = ["infra/../../x"]
    assert "ASENT_CONFIG_SCHEMA" in codes(load(make(tmp_path, config)))


# --- starter ----------------------------------------------------------------------------------------

def test_unreviewed_starter_is_invalid(tmp_path):
    config = full_config(); config["_starter"] = True
    result = load(make(tmp_path, config))
    assert not result.valid and codes(result) == {"ASENT_CONFIG_STARTER"}
    assert result.config is not None  # parsed, but not usable for a decision


def test_starter_false_is_accepted(tmp_path):
    config = full_config(); config["_starter"] = False
    assert load(make(tmp_path, config)).valid


# --- referenced files -------------------------------------------------------------------------------

def test_enabled_module_whose_file_is_missing(tmp_path):
    result = load(make(tmp_path, cavr=None))
    assert not result.valid and "ASENT_CONFIG_FILE_MISSING" in codes(result)
    assert any("cavr/policy.json" in problem for problem in result.problems)


def test_trusted_tests_directory_without_tests(tmp_path):
    root = make(tmp_path)
    (root / "satra/trusted_tests/test_authz.py").unlink()
    (root / "satra/trusted_tests/helper.py").write_text("x = 1\n")
    result = load(root)
    assert not result.valid and "ASENT_CONFIG_FILE_MISSING" in codes(result)


def test_configured_pytest_ini_missing(tmp_path):
    config = full_config(); config["modules"]["SATRA"]["pytest_ini"] = "satra/pytest.ini"
    assert "ASENT_CONFIG_FILE_MISSING" in codes(load(make(tmp_path, config)))


@pytest.mark.parametrize("policy,needle", [
    ({**CAVR_POLICY, "approved_requirements": "pypdf"}, "approved_requirements"),
    ({**CAVR_POLICY, "approved_requirements": ["pypdf[crypto]>=5"]}, "approved_requirements"),
    ({k: v for k, v in CAVR_POLICY.items() if k != "denied_packages"}, "denied_packages"),
    ({**CAVR_POLICY, "allowed_scopes": ["TELEPORT:anywhere"]}, "allowed_scopes"),
    ({**CAVR_POLICY, "allowed_scopes": ["FILE_READ:a", "FILE_READ:b"]}, "more than once"),
    ({k: v for k, v in CAVR_POLICY.items() if k != "project_task_description"}, "project_task_description"),
    ({**CAVR_POLICY, "project_task_description": "  "}, "project_task_description"),
])
def test_invalid_cavr_policy(tmp_path, policy, needle):
    result = load(make(tmp_path, cavr=policy))
    assert not result.valid and "ASENT_CONFIG_POLICY" in codes(result)
    assert any(needle in problem for problem in result.problems), result.problems


def test_invalid_cavr_policy_json(tmp_path):
    root = make(tmp_path)
    (root / "cavr/policy.json").write_text("{")
    assert "ASENT_CONFIG_POLICY" in codes(load(root))


@pytest.mark.parametrize("change", [
    {"counterfactual": {"operator": "DELETE_ALL", "target": "app/security.py::f"}},
    {"counterfactual": {"operator": "RETURN_TRUE", "target": "app/security.py"}},
    {"counterfactual": {"operator": "RETURN_TRUE", "target": "../x.py::f"}},
    {"authority_sources": []},
    {"scope": []},
    {"expected_status": "403"},
    {"unknown": 1},
])
def test_invalid_satra_contract(tmp_path, change):
    result = load(make(tmp_path, contract={**SATRA_CONTRACT, **change}))
    assert not result.valid and "ASENT_CONFIG_CONTRACT" in codes(result)


@pytest.mark.parametrize("obligations", [
    {"obligations": []},
    {"obligations": [{**SABLE_OBLIGATIONS["obligations"][0], "actions": []}]},
    {"obligations": [{k: v for k, v in SABLE_OBLIGATIONS["obligations"][0].items() if k != "principal"}]},
    {"obligations": [SABLE_OBLIGATIONS["obligations"][0], SABLE_OBLIGATIONS["obligations"][0]]},  # duplicate id
    {"obligations": [{**SABLE_OBLIGATIONS["obligations"][0], "margin": -1}]},
    [],
])
def test_invalid_sable_obligations(tmp_path, obligations):
    result = load(make(tmp_path, obligations=obligations))
    assert not result.valid and "ASENT_CONFIG_OBLIGATIONS" in codes(result)


def test_several_problems_are_all_reported(tmp_path):
    result = load(make(tmp_path, cavr=None, obligations={"obligations": []}))
    assert {"ASENT_CONFIG_FILE_MISSING", "ASENT_CONFIG_OBLIGATIONS"} <= codes(result)


# --- unsafe tree / budgets --------------------------------------------------------------------------

def test_symlinked_file_inside_asent(tmp_path):
    root = make(tmp_path)
    (tmp_path / "elsewhere.json").write_text(json.dumps(CAVR_POLICY))
    (root / "cavr/policy.json").unlink()
    os.symlink(tmp_path / "elsewhere.json", root / "cavr/policy.json")
    result = load(root)
    assert not result.valid and "ASENT_CONFIG_UNSAFE" in codes(result)


def test_symlinked_directory_inside_asent(tmp_path):
    root = make(tmp_path)
    (tmp_path / "outside").mkdir()
    os.symlink(tmp_path / "outside", root / "linked")
    assert "ASENT_CONFIG_UNSAFE" in codes(load(root))


def test_asent_itself_is_a_symlink(tmp_path):
    real = make(tmp_path / "real")
    os.symlink(real, tmp_path / ".asent")
    assert "ASENT_CONFIG_UNSAFE" in codes(load(tmp_path / ".asent"))


def test_too_many_files(tmp_path):
    root = make(tmp_path)
    for index in range(201):
        (root / f"note-{index}.txt").write_text("x")
    assert "ASENT_CONFIG_BUDGET" in codes(load(root))


def test_too_many_bytes(tmp_path):
    root = make(tmp_path)
    (root / "big.txt").write_bytes(b"x" * (1024 * 1024 + 1))
    assert "ASENT_CONFIG_BUDGET" in codes(load(root))


# --- digest -----------------------------------------------------------------------------------------

def test_digest_is_stable_and_changes_on_a_one_byte_edit(tmp_path):
    root = make(tmp_path)
    first, second = load(root).digest, load(root).digest
    assert first == second == tree_digest(root)
    readme = root / "README.md"
    readme.write_text("a")
    with_readme = load(root).digest
    readme.write_text("b")
    assert len({first, with_readme, load(root).digest}) == 3


def test_digest_is_independent_of_location(tmp_path):
    assert load(make(tmp_path / "one")).digest == load(make(tmp_path / "two")).digest


def test_digest_is_computed_for_an_invalid_config(tmp_path):
    # Needed to tell whether head changed .asent/ even when base's config is broken.
    config = full_config(); config["_starter"] = True
    result = load(make(tmp_path, config))
    assert not result.valid and result.digest == tree_digest(tmp_path / ".asent")


# --- capability helper reused by the loader -------------------------------------------------------

def test_capability_policy_problem_matches_contract_rules():
    assert capability_policy_problem(CAVR_POLICY) is None
    assert "allowed_scopes" in capability_policy_problem({**CAVR_POLICY, "allowed_scopes": "FILE_READ:x"})
    assert capability_policy_problem(None)


# --- documented schema ------------------------------------------------------------------------------

def test_committed_schemas_match_the_models():
    for name, generated in config_schema.export_schemas().items():
        committed = json.loads((REPO / "docs" / name).read_text())
        assert committed == generated, f"docs/{name} is out of date: run python -m backend.project_config --write docs"


def test_committed_schema_documents_starter_and_rejects_extras():
    committed = json.loads((REPO / "docs/asent-config.schema.json").read_text())
    assert "_starter" in committed["properties"] and committed["additionalProperties"] is False
