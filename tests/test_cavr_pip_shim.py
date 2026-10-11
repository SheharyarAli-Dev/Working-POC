"""The pip wrapper (plan step 12). Offline, with pip stubbed.

What is real here: the pipeline behind the wrapper (the pypdf 6.19.0 wheel, its recorded registry
response, the recorded OSV answer, tmp-built wheels served with digests of their real bytes).
What is stubbed: pip. `FakePip` records the command it is given and the text of the generated
requirements file, and installs nothing.
"""
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from backend.cavr import pip_shim
from backend.cavr.pip_shim import EXIT_INSTALL_FAILED, EXIT_USAGE, PIP_INSTALL_OPTIONS, install_plan, main, split_arguments
from backend.cavr.pypi_client import TransportError, registry_url
from test_cavr_support import PYPDF_SHA256, PYPDF_WHEEL, REPO, UNGUARDED, World, sha256_file, synthetic_advisory


class FakePip:
    """Stands in for `python -m pip`: remembers every call and what the requirements file held."""

    def __init__(self, returncode=0, error=None):
        self.calls, self.files, self.returncode, self.error = [], [], returncode, error

    def __call__(self, command):
        self.calls.append(list(command))
        self.files.append(Path(command[-1]).read_text(encoding="utf-8"))
        if self.error:
            raise self.error
        return self.returncode


class Shim:
    """A `World` whose policy is on disk where the wrapper looks for it, plus a stubbed pip."""

    def __init__(self, tmp_path):
        self.world = World(tmp_path)
        self.policy_path = self.world.project / "cavr-policy.json"
        self.save_policy()
        self.pip = FakePip()

    def save_policy(self):
        self.policy_path.write_text(json.dumps(self.world.policy))

    def run(self, *argv, **overrides):
        out = io.StringIO()
        args = {"pip_runner": self.pip, "out": out, "store": self.world.store, "transport": self.world.index,
                "quarantine_dir": self.world.tmp_path / "quarantine", "advisory_cache_dir": self.world.osv_dir,
                "live_advisories": False}
        args.update(overrides)
        code = main(["--cavr-project", str(self.world.project), *argv], **args)
        return code, out.getvalue()


@pytest.fixture
def shim(tmp_path, monkeypatch):
    monkeypatch.delenv("CAVR_POLICY", raising=False)
    return Shim(tmp_path)


def flip_one_byte_of_pypdf(world):
    response = world.index.add_pypdf()
    url = next(entry["url"] for entry in response["urls"] if entry["filename"].endswith(".whl"))
    data = bytearray(PYPDF_WHEEL.read_bytes())
    data[len(data) // 2] ^= 0x01
    world.index.routes[url] = bytes(data)


# --- the default: decide only ------------------------------------------------------------------------------

def test_default_prints_the_verdict_and_never_invokes_pip(shim):
    code, text = shim.run("install", "pypdf==6.19.0")
    assert code == 0 and shim.pip.calls == []
    assert "CAVR verdict: VERIFIED" in text and "ALL_CHECKS_PASSED" in text
    # The evidence is in the output: the real hash, the tree, the contract, OSV, the sinks and the metric fields.
    assert f"sha256 {PYPDF_SHA256}" in text and "HASH_MATCH" in text
    assert "NO_KNOWN_VULNERABILITY" in text and "CONTRACT_INFERRED" in text
    assert "pypdf/filters.py:774 subprocess.run GUARD_DISABLED" in text
    assert "cache_hit: False" in text and "escalated: False" in text and "fast_gate_ms:" in text
    assert "install: not requested; nothing was installed" in text


def test_second_default_run_is_a_cache_hit_and_still_installs_nothing(shim):
    assert shim.run("install", "pypdf==6.19.0")[0] == 0
    code, text = shim.run("install", "pypdf==6.19.0")
    assert code == 0 and "cache_hit: True" in text and shim.pip.calls == []


@pytest.mark.parametrize("argv, status, code", [
    (("install", "reqeusts==2.31.0"), "BLOCK", 3),
    (("install", "pypdf"), "BLOCK", 3),
    (("install", "-r", "missing.txt"), "UNRESOLVED", 2),
    (("list",), "UNRESOLVED", 2),
    (("--version",), "UNRESOLVED", 2),
    ((), "UNRESOLVED", 2),
])
def test_default_exit_code_is_non_zero_unless_verified(shim, argv, status, code):
    result, text = shim.run(*argv)
    assert result == code and f"CAVR verdict: {status}" in text
    assert shim.pip.calls == [] and shim.world.index.calls == []


# --- --install on VERIFIED ---------------------------------------------------------------------------------

@pytest.mark.parametrize("argv", [("install", "pypdf==6.19.0", "--install"), ("--install", "install", "pypdf==6.19.0"),
                                  ("install", "--install", "pypdf==6.19.0")])
def test_install_on_verified_invokes_pip_once_with_the_hash_pinned_file(shim, argv):
    code, text = shim.run(*argv)
    assert code == 0 and len(shim.pip.calls) == 1
    command = shim.pip.calls[0]
    assert command[:4] == [sys.executable, "-m", "pip", "install"]
    assert command[4:-2] == list(PIP_INSTALL_OPTIONS) and command[-2] == "-r"
    assert "--require-hashes" in command and "--no-deps" in command
    # The file lists exactly the verified file, by the SHA-256 the pipeline computed from its bytes.
    assert shim.pip.files == [f"pypdf==6.19.0 --hash=sha256:{PYPDF_SHA256}\n"]
    assert not Path(command[-1]).exists()  # the generated file is gone after pip returns
    assert "install: pip exited with 0" in text and f"pypdf==6.19.0 --hash=sha256:{PYPDF_SHA256}" in text


def test_install_lists_the_whole_verified_tree(shim):
    world = shim.world
    top = world.add("top", "1.0", {"top/__init__.py": "import helper\n\n\ndef run():\n    return helper.work()\n"}, requires=["helper>=2"])
    helper = world.add("helper", "2.0", {"helper/__init__.py": "def work():\n    return 1\n"})
    world.write("app/uses_top.py", "import top\n\ntop.run()\n")
    code, _ = shim.run("install", "top==1.0", "--install")
    assert code == 0
    assert shim.pip.files == [f"helper==2.0 --hash=sha256:{sha256_file(helper)}\ntop==1.0 --hash=sha256:{sha256_file(top)}\n"]


def test_two_requested_packages_are_one_pip_call(shim):
    world = shim.world
    demo = world.add("demo", "1.0", {"demo/__init__.py": "def run():\n    return 1\n"})
    world.write("app/uses_demo.py", "import demo\n\ndemo.run()\n")
    code, _ = shim.run("install", "pypdf==6.19.0", "demo==1.0", "--install")
    assert code == 0 and len(shim.pip.calls) == 1
    assert shim.pip.files[0].splitlines() == [f"demo==1.0 --hash=sha256:{sha256_file(demo)}", f"pypdf==6.19.0 --hash=sha256:{PYPDF_SHA256}"]


def test_the_users_own_pip_options_never_reach_pip(shim):
    code, _ = shim.run("install", "--upgrade", "--no-cache-dir", "--target", "somewhere", "pypdf==6.19.0", "--install")
    assert code == 0
    (command,) = shim.pip.calls
    assert not {"--upgrade", "--no-cache-dir", "--target", "somewhere", "pypdf==6.19.0"} & set(command)


def test_cavr_python_chooses_the_interpreter_that_runs_pip(shim):
    code, _ = shim.run("install", "pypdf==6.19.0", "--install", "--cavr-python", "/scratch/venv/bin/python")
    assert code == 0 and shim.pip.calls[0][:4] == ["/scratch/venv/bin/python", "-m", "pip", "install"]


def test_pip_failing_is_a_non_zero_exit(shim):
    shim.pip = FakePip(returncode=1)
    code, text = shim.run("install", "pypdf==6.19.0", "--install")
    assert code == EXIT_INSTALL_FAILED != 0 and "CAVR verdict: VERIFIED" in text and "install: pip exited with 1" in text


def test_pip_that_cannot_be_started_is_a_non_zero_exit(shim):
    shim.pip = FakePip(error=FileNotFoundError("no such interpreter"))
    code, text = shim.run("install", "pypdf==6.19.0", "--install")
    assert code == EXIT_INSTALL_FAILED and "pip could not be started" in text


# --- --install on anything else: pip is never invoked ------------------------------------------------------

def test_install_on_rejected_never_invokes_pip(shim):
    flip_one_byte_of_pypdf(shim.world)
    code, text = shim.run("install", "pypdf==6.19.0", "--install")
    assert code == 1 and shim.pip.calls == []
    assert "CAVR verdict: REJECTED" in text and "HASH_MISMATCH" in text and "install: refused" in text


def test_install_on_a_known_vulnerability_never_invokes_pip(shim):
    shim.world.advisories("pypdf", "6.19.0", [synthetic_advisory("SYNTH-1201", "pypdf")])
    code, text = shim.run("install", "pypdf==6.19.0", "--install")
    assert code == 1 and shim.pip.calls == [] and "SYNTH-1201" in text


def test_install_on_unresolved_never_invokes_pip(shim):
    shim.world.index.routes[registry_url("pypdf", "6.19.0")] = TransportError("ConnectError: network is unreachable")
    code, text = shim.run("install", "pypdf==6.19.0", "--install")
    assert code == 2 and shim.pip.calls == [] and "CAVR verdict: UNRESOLVED" in text and "install: refused" in text


def test_install_on_an_escalated_verdict_never_invokes_pip(shim):
    adapter = shim.world.project / "app" / "pdf_adapter.py"
    adapter.write_text(adapter.read_text() + UNGUARDED)
    code, text = shim.run("install", "pypdf==6.19.0", "--install")
    assert code == 2 and shim.pip.calls == []
    assert "escalated: True" in text and "deep analysis required (M2)" in text


@pytest.mark.parametrize("argv", [("install", "reqeusts==2.31.0", "--install"), ("install", "left-pad==1.0", "--install"),
                                  ("install", "pypdf>=6", "--install")])
def test_install_on_block_never_invokes_pip_and_downloads_nothing(shim, argv):
    code, text = shim.run(*argv)
    assert code == 3 and shim.pip.calls == [] and shim.world.index.calls == []
    assert "CAVR verdict: BLOCK" in text


def test_one_verified_and_one_rejected_installs_neither(shim):
    world = shim.world
    world.add("demo", "1.0", {"demo/__init__.py": "def run():\n    return 1\n"})
    world.write("app/uses_demo.py", "import demo\n\ndemo.run()\n")
    world.advisories("demo", "1.0", [synthetic_advisory("SYNTH-1202", "demo")])
    code, text = shim.run("install", "pypdf==6.19.0", "demo==1.0", "--install")
    assert code == 1 and shim.pip.calls == []
    assert "package pypdf==6.19.0: VERIFIED" in text and "package demo==1.0: REJECTED" in text


@pytest.mark.parametrize("argv", [
    ("install", "pypdf==6.19.0", "--install", "--index-url", "https://example.invalid/simple"),
    ("install", "pypdf==6.19.0", "--install", "--no-binary", ":all:"),
    ("install", "--install", "https://example.invalid/pypdf-6.19.0-py3-none-any.whl"),
    ("install", "--install", "-e", "."),
    ("download", "pypdf==6.19.0", "--install"),
    ("install", "pypdf==6.19.0", "--", "--install"),
])
def test_requests_the_capture_does_not_support_are_never_installed(shim, argv):
    code, _ = shim.run(*argv)
    assert code == 2 and shim.pip.calls == [] and shim.world.index.calls == []


# --- the policy ---------------------------------------------------------------------------------------------

def test_no_policy_file_is_unresolved_and_downloads_nothing(shim):
    shim.policy_path.unlink()
    code, text = shim.run("install", "pypdf==6.19.0", "--install")
    assert code == 2 and "POLICY_MISSING" in text
    assert shim.pip.calls == [] and shim.world.index.calls == []


def test_a_policy_that_is_not_json_is_unresolved(shim):
    shim.policy_path.write_text("{broken")
    code, text = shim.run("install", "pypdf==6.19.0", "--install")
    assert code == 2 and "POLICY_INVALID" in text and shim.pip.calls == []


def test_policy_option_and_environment_variable(shim, tmp_path, monkeypatch):
    elsewhere = tmp_path / "strict.json"
    elsewhere.write_text(json.dumps({"approved_requirements": [], "denied_packages": []}))
    assert shim.run("install", "pypdf==6.19.0")[0] == 0                                       # <project>/cavr-policy.json
    assert shim.run("install", "pypdf==6.19.0", "--cavr-policy", str(elsewhere))[0] == 3      # the option
    assert shim.run("install", "pypdf==6.19.0", f"--cavr-policy={elsewhere}")[0] == 3
    monkeypatch.setenv("CAVR_POLICY", str(elsewhere))
    assert shim.run("install", "pypdf==6.19.0")[0] == 3                                       # the environment variable
    assert shim.run("install", "pypdf==6.19.0", "--cavr-policy", str(shim.policy_path))[0] == 0  # the option wins
    monkeypatch.setenv("CAVR_POLICY", str(tmp_path / "nowhere.json"))
    assert shim.run("install", "pypdf==6.19.0")[0] == 2                                       # named but missing: no fallback


def test_project_defaults_to_the_current_directory(shim, monkeypatch):
    monkeypatch.chdir(shim.world.project)
    out = io.StringIO()
    code = main(["install", "pypdf==6.19.0"], pip_runner=shim.pip, out=out, store=shim.world.store, transport=shim.world.index,
                quarantine_dir=shim.world.tmp_path / "quarantine", advisory_cache_dir=shim.world.osv_dir, live_advisories=False)
    assert code == 0 and "CAVR verdict: VERIFIED" in out.getvalue()


# --- the wrapper's own options --------------------------------------------------------------------------------

def test_split_arguments():
    options, rest, problem = split_arguments(["--cavr-project=/p", "install", "--install", "a==1", "--cavr-json", "--cavr-policy", "x.json"])
    assert problem is None and rest == ["install", "a==1"]
    assert options == {"install": True, "json": True, "project": "/p", "policy": "x.json", "python": None}
    # After `--` everything belongs to pip.
    options, rest, problem = split_arguments(["install", "--", "--install", "--cavr-json"])
    assert (options["install"], options["json"], rest, problem) == (False, False, ["install", "--", "--install", "--cavr-json"], None)


@pytest.mark.parametrize("argv, word", [(["install", "a==1", "--cavr-unknown"], "--cavr-unknown"), (["--cavr-project"], "needs a value"),
                                        (["--cavr-json=yes", "install", "a==1"], "takes no value"),
                                        (["--cavr-policy=", "install", "a==1"], "needs a value"), (None, "list of strings"),
                                        (["install", 5], "list of strings")])
def test_bad_wrapper_options_are_a_usage_error(argv, word):
    assert word in split_arguments(argv)[2]


def test_a_usage_error_verifies_and_installs_nothing(shim):
    code, text = shim.run("install", "pypdf==6.19.0", "--install", "--cavr-unknown")
    assert code == EXIT_USAGE == 2 and "--cavr-unknown" in text
    assert shim.pip.calls == [] and shim.world.index.calls == [] and shim.world.store.get_verdict_log() == []


def test_json_output_is_the_whole_verdict_and_the_install_result(shim):
    code, text = shim.run("install", "pypdf==6.19.0", "--install", "--cavr-json")
    report = json.loads(text)
    assert code == 0 and set(report) == {"verdict", "install", "exit_code"} and report["exit_code"] == 0
    assert report["verdict"]["status"] == "VERIFIED" and report["verdict"]["packages"][0]["evidence"]["artifact"]["sha256"] == PYPDF_SHA256
    assert report["install"]["requested"] is True and report["install"]["performed"] is True and report["install"]["returncode"] == 0
    assert report["install"]["lines"] == [f"pypdf==6.19.0 --hash=sha256:{PYPDF_SHA256}"]


def test_credentials_in_a_request_are_not_printed_or_logged(shim):
    code, text = shim.run("install", "pypdf==6.19.0", "--index-url", "https://alice:hunter2@example.invalid/simple", "--cavr-json")
    assert code == 2 and "hunter2" not in text and "***@example.invalid" in text
    assert "hunter2" not in json.dumps(shim.world.store.get_verdict_log())


# --- the install plan refuses anything that is not a fully verified tree ------------------------------------------

def verified(shim):
    return shim.world.verify()


def test_install_plan_of_a_verified_verdict(shim):
    assert install_plan(verified(shim)) == ([f"pypdf==6.19.0 --hash=sha256:{PYPDF_SHA256}"], None)


def change(verdict, path, value):
    """Set one nested field of a copy of the verdict."""
    verdict = json.loads(json.dumps(verdict))
    target = verdict
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return verdict


NODE = ("packages", 0, "evidence", "tree", "nodes", 0)


@pytest.mark.parametrize("path, value, word", [
    (("status",), "UNRESOLVED", "not VERIFIED"),
    (("status",), "REJECTED", "not VERIFIED"),
    (("status",), "verified", "not VERIFIED"),
    (("packages", 0, "status"), "UNRESOLVED", "not VERIFIED"),
    (("packages",), [], "no verified package"),
    (("packages", 0, "evidence", "tree", "nodes"), [], "no verified package"),
    (("packages", 0, "evidence", "tree"), None, "evidence is incomplete"),
    (("packages", 0, "evidence", "tree", "rule"), "CHILD_NOT_PINNED", "tree was not built"),
    (NODE + ("sha256",), "7e5d", "not a SHA-256"),
    (NODE + ("sha256",), None, "not a SHA-256"),
    (NODE + ("sha256",), PYPDF_SHA256.upper(), "not a SHA-256"),
    (NODE + ("name",), "pypdf\n--index-url https://example.invalid/simple", "not a package name"),
    (NODE + ("name",), "pypdf --no-binary :all:", "not a package name"),
    (NODE + ("version",), "6.19.0 --hash=sha256:" + "0" * 64, "not a version"),
    (NODE + ("version",), "6.19.0\n", "not a version"),
    (NODE + ("version",), ">=6", "not a version"),
])
def test_install_plan_refuses_a_verdict_that_is_not_a_fully_verified_tree(shim, path, value, word):
    lines, problem = install_plan(change(verified(shim), path, value))
    assert lines is None and word in problem


def test_install_plan_refuses_two_files_for_one_package(shim):
    verdict = verified(shim)
    twice = change(verdict, ("packages",), verdict["packages"] * 2)
    assert install_plan(twice) == ([f"pypdf==6.19.0 --hash=sha256:{PYPDF_SHA256}"], None)  # the same file twice is one line
    other_hash = change(twice, ("packages", 1, "evidence", "tree", "nodes", 0, "sha256"), "0" * 64)
    assert "two different files" in install_plan(other_hash)[1]
    other_version = change(twice, ("packages", 1, "evidence", "tree", "nodes", 0, "version"), "6.18.0")
    assert "two different files" in install_plan(other_version)[1]


@pytest.mark.parametrize("verdict", [None, {}, [], "VERIFIED", {"status": "VERIFIED"}, {"status": "VERIFIED", "packages": None},
                                     {"status": "VERIFIED", "packages": [None]}])
def test_install_plan_of_something_that_is_not_a_verdict(verdict):
    lines, problem = install_plan(verdict)
    assert lines is None and problem


def test_a_verified_verdict_without_a_usable_plan_is_not_installed(shim, monkeypatch):
    """Defence in depth: if the pipeline ever said VERIFIED without the evidence, the wrapper still refuses."""
    real = pip_shim.verify_request
    monkeypatch.setattr(pip_shim, "verify_request",
                        lambda *args, **kwargs: change(real(*args, **kwargs), NODE + ("sha256",), "unknown"))
    code, text = shim.run("install", "pypdf==6.19.0", "--install")
    assert code == EXIT_INSTALL_FAILED and shim.pip.calls == [] and "install: refused" in text and "not a SHA-256" in text


def test_a_fault_in_the_pipeline_call_is_unresolved_not_a_traceback(shim, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(pip_shim, "verify_request", broken)
    code, text = shim.run("install", "pypdf==6.19.0", "--install")
    assert code == 2 and shim.pip.calls == [] and "CAVR verdict: UNRESOLVED" in text and "disk on fire" in text


# --- long advisory lists --------------------------------------------------------------------------------------------------

def test_a_long_advisory_list_is_one_short_line_and_whole_in_the_json(shim):
    many = [synthetic_advisory(f"SYNTH-{number:04d}", "pypdf") for number in range(1, 41)]
    shim.world.advisories("pypdf", "6.19.0", many)
    code, text = shim.run("install", "pypdf==6.19.0")
    assert code == 1 and "CAVR verdict: REJECTED" in text
    (line,) = [line for line in text.splitlines() if line.startswith("  advisories:")]
    assert line == ("  advisories: pypdf 6.19.0 KNOWN_VULNERABILITY: 40 advisories: SYNTH-0001, SYNTH-0002, SYNTH-0003 and 37 more "
                    "(every id: --cavr-json)")
    assert "SYNTH-0004" not in text and max(len(line) for line in text.splitlines()) < 200
    code, as_json = shim.run("install", "pypdf==6.19.0", "--cavr-json")
    affected = json.loads(as_json)["verdict"]["packages"][0]["evidence"]["advisories"][0]["affected"]
    assert code == 1 and [entry["id"] for entry in affected] == [advisory["id"] for advisory in many]


def test_a_short_advisory_list_is_printed_whole(shim):
    shim.world.advisories("pypdf", "6.19.0", [synthetic_advisory("SYNTH-0051", "pypdf"), synthetic_advisory("SYNTH-0052", "pypdf")])
    _, text = shim.run("install", "pypdf==6.19.0")
    assert "  advisories: pypdf 6.19.0 KNOWN_VULNERABILITY: 2 advisories: SYNTH-0051, SYNTH-0052\n" in text
    assert "more" not in text.split("advisories: pypdf")[1].splitlines()[0]
    _, clean = Shim(shim.world.tmp_path / "other").run("install", "pypdf==6.19.0")
    assert "  advisories: pypdf 6.19.0 NO_KNOWN_VULNERABILITY\n" in clean


# --- as a program ----------------------------------------------------------------------------------------------------

def test_module_runs_as_a_program_and_fails_closed(tmp_path):
    """`python -m backend.cavr.pip_shim` in a directory with no policy: UNRESOLVED before any network use."""
    env = {**os.environ, "ASENT_DATA": str(tmp_path / "data"), "PYTHONPATH": str(REPO)}
    env.pop("CAVR_POLICY", None)
    done = subprocess.run([sys.executable, "-m", "backend.cavr.pip_shim", "install", "pypdf==6.19.0", "--install"],
                          cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120)
    assert done.returncode == 2, done.stderr
    assert "CAVR verdict: UNRESOLVED" in done.stdout and "POLICY_MISSING" in done.stdout
    assert "install: refused" in done.stdout
