"""Step 2 of docs/dev-env-plan.md: `asent init` writes a starter `.asent/` that is refused until reviewed.

Each case is a real project directory in tmp_path. The starter must (1) load as invalid with only
ASENT_CONFIG_STARTER, so an unreviewed starter can never give ACCEPT, and (2) load as valid once a
person removes "_starter". SATRA and SABLE are written disabled with a reason, because their contract
and obligations cannot be inferred from the code; the gate then reports them as not assessed.
"""
import json
import os
from pathlib import Path

import pytest

from backend import cli
from backend.project_config import load
from backend.project_config.starter import init_project


def codes(result):
    return {problem.split(":", 1)[0] for problem in result.problems}


def reviewed(root: Path):
    """What a reviewer does last: remove the starter marker."""
    path = root / ".asent/config.json"
    config = json.loads(path.read_text())
    config.pop("_starter")
    path.write_text(json.dumps(config, indent=2))
    return load(root / ".asent")


def python_project(root: Path):
    (root / "app").mkdir(parents=True)
    (root / "app/main.py").write_text("import pypdf\n")
    (root / "tests").mkdir()
    (root / "tests/test_main.py").write_text("def test_x():\n    pass\n")
    (root / "requirements.txt").write_text(
        "# comment\npypdf==6.1.0\nfastapi==0.115.0 ; python_version >= '3.9'\nrequests>=2\n"
        "-r other.txt\ngit+https://example.invalid/pkg.git\nhttpx[http2]==0.27.0\n")
    return root


def test_empty_project(tmp_path):
    report = init_project(tmp_path)
    result = load(tmp_path / ".asent")
    assert codes(result) == {"ASENT_CONFIG_STARTER"}
    for module in ("CAVR", "SATRA", "SABLE"):
        assert result.module_state(module) == "disabled" and result.disabled_reason(module)
    assert report["detected"] == {"requirements_files": [], "python": False, "terraform_dirs": []}
    assert (tmp_path / ".asent/README.md").is_file()
    assert reviewed(tmp_path).valid


def test_python_project_copies_exact_pins_only(tmp_path):
    report = init_project(python_project(tmp_path))
    result = load(tmp_path / ".asent")
    assert codes(result) == {"ASENT_CONFIG_STARTER"}
    assert result.module_state("CAVR") == "enabled"
    assert result.config.modules.CAVR.requirements_files == ["requirements.txt"]
    policy = json.loads((tmp_path / ".asent/cavr/policy.json").read_text())
    # Only `name==version` lines become approved entries, without marker or extras (the gate refuses those).
    assert policy["approved_requirements"] == ["fastapi==0.115.0", "httpx==0.27.0", "pypdf==6.1.0"]
    assert policy["denied_packages"] == [] and policy["allowed_scopes"] == []
    assert sorted(report["not_copied"]) == sorted(["requests>=2", "-r other.txt", "git+https://example.invalid/pkg.git"])
    assert report["detected"]["python"] is True
    assert result.module_state("SATRA") == "disabled" and "contract" in result.disabled_reason("SATRA")
    assert reviewed(tmp_path).valid


def test_terraform_project(tmp_path):
    (tmp_path / "infra/modules/s3").mkdir(parents=True)
    (tmp_path / "infra/main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
    (tmp_path / "infra/modules/s3/main.tf").write_text("")
    (tmp_path / ".terraform/providers").mkdir(parents=True)
    (tmp_path / ".terraform/providers/x.tf").write_text("")
    report = init_project(tmp_path)
    assert report["detected"]["terraform_dirs"] == ["infra", "infra/modules/s3"]
    result = load(tmp_path / ".asent")
    assert result.module_state("SABLE") == "disabled" and "obligations" in result.disabled_reason("SABLE")
    assert result.config.modules.SABLE.terraform_dirs == ["infra", "infra/modules/s3"]
    assert reviewed(tmp_path).valid


def test_existing_asent_is_not_overwritten(tmp_path):
    (tmp_path / ".asent").mkdir()
    (tmp_path / ".asent/config.json").write_text("{\"mine\": true}")
    with pytest.raises(FileExistsError):
        init_project(tmp_path)
    assert (tmp_path / ".asent/config.json").read_text() == "{\"mine\": true}"


def test_force_replaces_existing_asent(tmp_path):
    (tmp_path / ".asent/old").mkdir(parents=True)
    (tmp_path / ".asent/old/file.txt").write_text("x")
    init_project(tmp_path, force=True)
    assert not (tmp_path / ".asent/old").exists()
    assert codes(load(tmp_path / ".asent")) == {"ASENT_CONFIG_STARTER"}


def test_symlinked_asent_is_refused_even_with_force(tmp_path):
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "elsewhere/keep.txt").write_text("keep")
    os.symlink(tmp_path / "elsewhere", tmp_path / ".asent")
    with pytest.raises(ValueError):
        init_project(tmp_path, force=True)
    assert (tmp_path / "elsewhere/keep.txt").read_text() == "keep"


def test_not_a_directory(tmp_path):
    with pytest.raises(ValueError):
        init_project(tmp_path / "missing")


def test_project_name_is_the_directory_name(tmp_path):
    project = tmp_path / "Invoice-Service"
    project.mkdir()
    init_project(project)
    assert load(project / ".asent").config.project.name == "Invoice-Service"


def test_cli_init_then_refuses_second_time(tmp_path, capsys):
    python_project(tmp_path)
    assert cli.main(["init", "--repository", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert ".asent/config.json" in out and "review" in out.lower()
    assert cli.main(["init", "--repository", str(tmp_path)]) == 2
    assert "already exists" in capsys.readouterr().err
    assert cli.main(["init", "--repository", str(tmp_path), "--force"]) == 0
