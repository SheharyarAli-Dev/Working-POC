"""vscode-asent/scripts/make_fixtures.py: neutral() on a GitHub runner.

The runner tests simulate the paths of an ubuntu-latest runner (user `runner`, home /home/runner,
checkout under /home/runner/work, $RUNNER_TEMP, $GITHUB_WORKSPACE) without being on one: the
environment is passed to neutral() and the checkout and temp folder are patched.
"""
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vscode-asent" / "scripts"))

import make_fixtures as mf  # noqa: E402

HOME = "/home/runner"
CHECKOUT = "/home/runner/work/Working-POC/Working-POC"
RUNNER_TEMP = "/home/runner/work/_temp"
WORK = Path("/tmp/asent-fixture-satra-block-ab12cd_3")


@pytest.fixture
def runner(monkeypatch):
    """The environment of a GitHub runner; the checkout and temp folder are patched to match."""
    monkeypatch.setattr(mf, "ROOT", Path(CHECKOUT))
    monkeypatch.setattr(tempfile, "tempdir", "/tmp")
    return {"HOME": HOME, "USER": "runner", "RUNNER_TEMP": RUNNER_TEMP, "GITHUB_WORKSPACE": CHECKOUT}


def test_runner_paths_become_placeholders_and_nothing_else_changes(runner):
    report = {
        "repository": f"{WORK}/repo",
        f"{WORK}/repo/app/security.py": "a key that is a path",
        "output": f"{WORK}/out/asent-report.json",
        "assets": f"{CHECKOUT}/backend/assets",
        "commands": f"{RUNNER_TEMP}/_runner_file_commands/set_env",
        "run_in_runner_temp": f"{RUNNER_TEMP}/asent-gate-q1w2e3r4/runtime",
        "workspace": "/tmp/asent-gate-k3j2h1x9/runtime/workspaces/w1",
        "pip_cache": f"{HOME}/.cache/pip",
        "sandbox_image": {"status": "READY", "reused": False, "packages": [],
                          "runner": {"image": "asent-satra-runner:local", "image_id": "sha256:" + "a" * 64,
                                     "python": "3.12.3"}},
        "exit_code": 1, "assessed": True, "evidence": None, "digest": "b" * 64,
    }
    assert mf.neutral(report, WORK, env=runner) == {
        "repository": "/workspace/project",
        "/workspace/project/app/security.py": "a key that is a path",
        "output": "/workspace/out/asent-report.json",
        "assets": "/opt/asent/backend/assets",
        "commands": "/tmp/runner-temp/_runner_file_commands/set_env",
        "run_in_runner_temp": "/tmp/runner-temp/asent-gate-run/runtime",
        "workspace": "/tmp/asent-gate-run/runtime/workspaces/w1",
        "pip_cache": "/home/user/.cache/pip",
        "sandbox_image": {"status": "READY", "reused": False, "packages": [],
                          "runner": {"image": "asent-satra-runner:local", "image_id": "sha256:" + "a" * 64,
                                     "python": "3.12.3"}},
        "exit_code": 1, "assessed": True, "evidence": None, "digest": "b" * 64,
    }


def test_the_user_name_as_a_word_is_not_a_machine_path(runner):
    # SATRA writes a "runner" key (sandbox_image.runner); on a runner the user name is also "runner".
    value = {"runner": "the SATRA runner image", "note": "runner"}
    assert mf.neutral(value, WORK, env=runner) == value


@pytest.mark.parametrize("leak", ["/srv/runner/cache", "/srv/runner", "C:\\Users\\runner\\AppData"])
def test_the_user_name_inside_a_path_is_still_refused(runner, leak):
    with pytest.raises(mf.ScenarioError, match="machine paths still present after neutral.*runner"):
        mf.neutral({"path": leak}, WORK, env=runner)


def test_the_check_reports_every_machine_path_it_finds(runner):
    table = mf.machine_paths(WORK, runner)
    for raw in (f"{WORK}/repo", str(WORK), CHECKOUT, RUNNER_TEMP, HOME):
        assert raw in mf.leftovers([f"see {raw}/x"], table, runner), raw
    assert mf.leftovers(["/workspace/project", "/opt/asent", "/tmp/runner-temp", "/home/user", "/tmp"],
                        table, runner) == []


def test_machine_paths_come_from_the_environment(runner):
    table = mf.machine_paths(WORK, runner)
    assert table[RUNNER_TEMP] == "/tmp/runner-temp"
    assert table[CHECKOUT] == "/opt/asent"      # GITHUB_WORKSPACE is the checkout: the first placeholder stays
    assert table[HOME] == "/home/user"
    other = mf.machine_paths(WORK, {**runner, "GITHUB_WORKSPACE": "/srv/checkout", "HOME": "/home/someone"})
    assert other["/srv/checkout"] == "/opt/asent" and other["/home/someone"] == "/home/user"
    assert HOME not in other


@pytest.mark.parametrize("value", ["", "/", "relative/tmp", None])
def test_unset_empty_root_or_relative_values_are_ignored(runner, value):
    env = {**runner, "RUNNER_TEMP": value, "GITHUB_WORKSPACE": value, "TMPDIR": value}
    env = {k: v for k, v in env.items() if v is not None}
    table = mf.machine_paths(WORK, env)
    assert not {"", "/", "relative/tmp"} & set(table)
    assert mf.neutral({"p": "/usr/lib/x", "r": "relative/tmp/y"}, WORK, env=env) == {"p": "/usr/lib/x", "r": "relative/tmp/y"}


def test_only_whole_path_segments_are_replaced(runner):
    value = {"a": f"{HOME}2/x", "b": f"{HOME}.old", "c": f"{HOME}:/usr/bin"}
    assert mf.neutral(value, WORK, env=runner) == {"a": f"{HOME}2/x", "b": f"{HOME}.old", "c": "/home/user:/usr/bin"}


def test_a_path_glued_to_other_text_is_still_replaced(runner):
    value = {"flags": f"-I{HOME}/include --root={CHECKOUT}", "glued": f"x{HOME}/y",
             "two": f"{CHECKOUT}/a:{RUNNER_TEMP}/b"}
    assert mf.neutral(value, WORK, env=runner) == {"flags": "-I/home/user/include --root=/opt/asent", "glued": "x/home/user/y",
                                                   "two": "/opt/asent/a:/tmp/runner-temp/b"}


def test_a_placeholder_does_not_hide_a_machine_path_it_starts(runner):
    table = mf.machine_paths(WORK, runner)
    assert mf.leftovers([f"{WORK}/repo/x"], table, runner) == [str(WORK), f"{WORK}/repo"]
    # ... but a placeholder that contains the user name or a machine path is not itself a leak
    as_user = {**runner, "USER": "user", "HOME": "/opt"}
    assert mf.leftovers(["/home/user/x", "/opt/asent/y"], mf.machine_paths(WORK, as_user), as_user) == []


def test_a_temp_folder_outside_tmp_is_replaced(runner, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", f"{HOME}/tmp")
    env = {**runner, "TMPDIR": f"{HOME}/tmp"}
    value = {"run": f"{HOME}/tmp/asent-gate-abcdefgh/x", "tmp": f"{HOME}/tmp/other"}
    assert mf.neutral(value, WORK, env=env) == {"run": "/tmp/asent-gate-run/x", "tmp": "/tmp/other"}


def test_the_resolved_form_of_a_symlinked_folder_is_replaced_too(runner, tmp_path):
    real = tmp_path / "real-home"
    real.mkdir()
    (tmp_path / "home").symlink_to(real)
    env = {**runner, "HOME": str(tmp_path / "home")}
    value = {"given": f"{tmp_path}/home/.cache", "resolved": f"{real.resolve()}/.cache"}
    assert mf.neutral(value, WORK, env=env) == {"given": "/home/user/.cache", "resolved": "/home/user/.cache"}


def test_without_user_variables_the_home_folder_name_is_checked(runner):
    env = {k: v for k, v in runner.items() if k != "USER"}
    with pytest.raises(mf.ScenarioError, match="runner"):
        mf.neutral({"p": "/srv/runner/cache"}, WORK, env=env)


def test_the_default_environment_is_the_process_environment(runner, monkeypatch):
    for name, value in runner.items():
        monkeypatch.setenv(name, value)
    assert mf.neutral({"p": f"{RUNNER_TEMP}/x", "runner": 1}, WORK) == {"p": "/tmp/runner-temp/x", "runner": 1}


def test_two_keys_that_become_one_placeholder_are_refused(runner):
    with pytest.raises(mf.ScenarioError, match="both become '/tmp/asent-gate-run'"):
        mf.neutral({"/tmp/asent-gate-aaaaaaaa": 1, "/tmp/asent-gate-bbbbbbbb": 2}, WORK, env=runner)


@pytest.mark.parametrize("value", [(f"{HOME}/x",), Path(HOME), {1, 2}])
def test_a_value_that_is_not_json_is_refused(runner, value):
    with pytest.raises(mf.ScenarioError, match="not a JSON value"):
        mf.neutral({"v": value}, WORK, env=runner)
