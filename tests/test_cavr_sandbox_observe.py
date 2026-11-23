"""PR 6 of docs/cavr-m2-plan.md: install the verified wheels and import their top-level modules in the sandbox.

Unit tests stage real wheels (`build_wheel`) from a quarantine directory in `tmp_path` and replace the sandbox run.
Docker tests (`requires_docker`, CAVR_DOCKER=1) install real wheels built in `tmp_path` in asent-cavr-sandbox; the
native one carries a CPython extension module (`_bisect`) copied out of the image itself.
"""
import hashlib
import os
import re
import subprocess
from pathlib import Path

import pytest

from backend.cavr import sandbox_exec, sandbox_observe
from tests.test_cavr_support import build_wheel, cavr_containers, requires_docker, sandbox_identity


def node_for(wheel, name, version):
    data = wheel.read_bytes()
    return {"name": name, "version": version, "filename": wheel.name, "path": str(wheel),
            "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


@pytest.fixture
def quarantine(tmp_path):
    q = tmp_path / "quarantine"
    q.mkdir()
    return q


def tree(quarantine, files=None, extra=()):
    """A verified tree: `demo` 1.0 (with `files`) and its dependency `helper` 2.0."""
    demo = build_wheel(quarantine, "demo", "1.0", files=files, requires=["helper==2.0"])
    helper = build_wheel(quarantine, "helper", "2.0")
    return [node_for(demo, "demo", "1.0"), node_for(helper, "helper", "2.0"), *extra]


@pytest.fixture
def captured(monkeypatch):
    """run_harness replaced: records the steps, mounts and tmpfs it was given and what /pkg held at that moment."""
    seen = {}

    def run(steps, mounts=(), tmpfs=(), **kwargs):
        (host, inside), = mounts
        seen.update(steps=steps, inside=inside, tmpfs=list(tmpfs), host=host,
                    files={entry.name: Path(entry.path).read_bytes() for entry in os.scandir(host)},
                    modes={e.name: os.stat(e.path).st_mode & 0o777 for e in os.scandir(host)},
                    dir_mode=os.stat(host).st_mode & 0o777)
        return sandbox_observe._result("DEEP_NOT_JUDGED", "fake", {"image_id": "sha256:" + "ab" * 32})
    monkeypatch.setattr(sandbox_observe, "run_harness", run)
    return seen


# --- staging on the host (unit) --------------------------------------------------------------------------------------------

def test_hash_file_holds_exactly_the_trees_sha256_values(quarantine, captured):
    nodes = tree(quarantine)
    got = sandbox_observe.observe(nodes, ["demo"], quarantine_dir=quarantine)
    assert got["status"] == "UNRESOLVED" and got["rule"] == "DEEP_NOT_JUDGED"
    lines = captured["files"]["hashes.txt"].decode().splitlines()
    assert lines == [f"demo==1.0 --hash=sha256:{nodes[0]['sha256']}", f"helper==2.0 --hash=sha256:{nodes[1]['sha256']}"]
    assert got["evidence"]["hash_file_sha256"] == hashlib.sha256(captured["files"]["hashes.txt"]).hexdigest()
    assert [w["sha256"] for w in got["evidence"]["wheels"]] == [n["sha256"] for n in nodes]


def test_staged_wheels_are_the_exact_quarantine_bytes_readable_by_the_sandbox_user(quarantine, captured):
    nodes = tree(quarantine)
    sandbox_observe.observe(nodes, ["demo"], quarantine_dir=quarantine)
    for node in nodes:
        assert captured["files"][node["filename"]] == open(node["path"], "rb").read()
        assert captured["modes"][node["filename"]] == 0o644
    assert set(captured["files"]) == {nodes[0]["filename"], nodes[1]["filename"], "hashes.txt"}
    assert captured["dir_mode"] == 0o755 and captured["inside"] == "/pkg"
    assert not os.path.exists(captured["host"])  # the staging directory is gone after the run


def test_a_wheel_whose_quarantine_bytes_changed_is_refused_before_mounting(quarantine, captured):
    nodes = tree(quarantine)
    with open(nodes[1]["path"], "ab") as handle:
        handle.write(b"tampered")
    got = sandbox_observe.observe(nodes, ["demo"], quarantine_dir=quarantine)
    assert got["status"] == "UNRESOLVED" and got["rule"] == "WHEEL_HASH_MISMATCH" and captured == {}
    assert nodes[1]["filename"] in got["reason"]


@pytest.mark.parametrize("change", [
    lambda n, q: n.update(filename="demo-1.0.tar.gz"),                     # an sdist is never installed
    lambda n, q: n.update(sha256=None),                                      # not verified
    lambda n, q: n.update(sha256="AB" * 32),                                 # not a lowercase hex digest
    lambda n, q: n.update(path=None),
    lambda n, q: n.update(path=str(q / "absent.whl"), filename="absent.whl"),
    lambda n, q: n.update(filename="../demo-1.0-py3-none-any.whl"),
    lambda n, q: n.update(name="demo; rm -rf /"),
    lambda n, q: n.update(version="1.0 --hash=sha256:x"),
])
def test_a_node_that_is_not_a_verified_wheel_is_refused(quarantine, captured, change):
    nodes = tree(quarantine)
    change(nodes[0], quarantine)
    got = sandbox_observe.observe(nodes, ["demo"], quarantine_dir=quarantine)
    assert got["rule"] == "WHEEL_NOT_VERIFIED" and captured == {}


def test_a_wheel_outside_the_quarantine_is_refused(quarantine, tmp_path, captured):
    elsewhere = build_wheel(tmp_path / "elsewhere", "demo", "1.0")
    got = sandbox_observe.observe([node_for(elsewhere, "demo", "1.0")], ["demo"], quarantine_dir=quarantine)
    assert got["rule"] == "WHEEL_NOT_VERIFIED" and "quarantine" in got["reason"] and captured == {}


def test_a_symlink_in_the_quarantine_is_refused(quarantine, tmp_path, captured):
    real = build_wheel(tmp_path / "elsewhere", "demo", "1.0")
    link = quarantine / real.name
    link.symlink_to(real)
    got = sandbox_observe.observe([node_for(link, "demo", "1.0")], ["demo"], quarantine_dir=quarantine)
    assert got["rule"] == "WHEEL_NOT_VERIFIED" and captured == {}


def test_a_name_twice_in_the_tree_is_refused(quarantine, captured):
    nodes = tree(quarantine)
    twin = dict(nodes[1], name="Helper")
    got = sandbox_observe.observe(nodes + [twin], ["demo"], quarantine_dir=quarantine)
    assert got["rule"] == "WHEEL_NOT_VERIFIED" and captured == {}


@pytest.mark.parametrize("nodes", [[], None, ["not a dict"]])
def test_no_wheel_is_refused(quarantine, captured, nodes):
    assert sandbox_observe.observe(nodes, ["demo"], quarantine_dir=quarantine)["rule"] == "WHEEL_NOT_VERIFIED"
    assert captured == {}


@pytest.mark.parametrize("modules", [[], None, ["demo.sub"], ["demo", "demo"], ["os; import x"], [""], "demo"])
def test_modules_that_are_not_top_level_names_are_refused(quarantine, captured, modules):
    got = sandbox_observe.observe(tree(quarantine), modules, quarantine_dir=quarantine)
    assert got["status"] == "UNRESOLVED" and got["rule"] == "MODULES_UNKNOWN" and captured == {}


def test_the_steps_install_offline_by_hash_then_import(quarantine, captured):
    sandbox_observe.observe(tree(quarantine), ["demo", "helper"], quarantine_dir=quarantine)
    install, imports = captured["steps"]
    assert install["name"] == "install" and imports["name"] == "imports"
    argv = install["argv"]
    assert argv[:4] == ["/usr/local/bin/python", "-I", "-m", "pip"]
    for flag in ("--no-index", "--no-deps", "--require-hashes", "--no-compile"):
        assert flag in argv
    assert argv[argv.index("--only-binary") + 1] == ":all:" and argv[argv.index("--target") + 1] == "/site/lib"
    assert argv[argv.index("-r") + 1] == "/pkg/hashes.txt" and argv[argv.index("--find-links") + 1] == "/pkg"
    assert imports["argv"][:4] == ["/usr/local/bin/python", "-I", "-S", "-c"] and imports["argv"][-2:] == ["demo", "helper"]
    assert "site.addsitedir('/site/lib')" in imports["argv"][4]
    assert install["env"] == {} and imports["env"] == {}


def test_only_the_install_target_is_executable(quarantine, captured):
    sandbox_observe.observe(tree(quarantine), ["demo"], quarantine_dir=quarantine)
    assert captured["tmpfs"] == ["/site:rw,exec,nosuid,nodev,size=128m,mode=1777"]
    assert "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777" in sandbox_exec.lockdown_flags()


def test_docker_hidden_is_unresolved_and_nothing_runs(quarantine, monkeypatch):
    monkeypatch.setattr(sandbox_observe, "IDENTITY", lambda: {"ok": False, "rule": "ENGINE_UNAVAILABLE",
                                                              "reason": "the docker engine cannot be reached"})
    ran = []
    monkeypatch.setattr(sandbox_observe, "RUN", lambda *a, **k: ran.append(a))
    got = sandbox_observe.observe(tree(quarantine), ["demo"], quarantine_dir=quarantine)
    assert got["status"] == "UNRESOLVED" and got["rule"] == "ENGINE_UNAVAILABLE" and ran == []


def test_a_fault_is_unresolved_internal_error(quarantine, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(sandbox_observe, "stage_wheels", boom)
    got = sandbox_observe.observe(tree(quarantine), ["demo"], quarantine_dir=quarantine)
    assert got["status"] == "UNRESOLVED" and got["rule"] == "INTERNAL_ERROR"


def test_a_module_no_staged_wheel_provides_is_refused(quarantine, captured):
    got = sandbox_observe.observe(tree(quarantine), ["os"], quarantine_dir=quarantine)
    assert got["rule"] == "MODULES_UNKNOWN" and "os" in got["reason"] and captured == {}


def test_top_level_names_come_from_the_wheel_archive(tmp_path):
    wheel = build_wheel(tmp_path, "multi", "1.0", files={"pkg_a/__init__.py": "", "pkg_a/sub/x.py": "", "single.py": "",
                                                         "fast.cpython-312-x86_64-linux-gnu.so": b"\x7fELF",
                                                         "startup.pth": "", "multi-1.0.data/scripts/tool": ""})
    assert sandbox_observe.top_level_names(wheel.read_bytes(), wheel.name) == ["fast", "pkg_a", "single"]


def test_an_unreadable_wheel_is_refused(quarantine, captured):
    bad = quarantine / "demo-1.0-py3-none-any.whl"
    bad.write_bytes(b"not a zip")
    node = {"name": "demo", "version": "1.0", "filename": bad.name, "path": str(bad),
            "sha256": hashlib.sha256(b"not a zip").hexdigest()}
    got = sandbox_observe.observe([node], ["demo"], quarantine_dir=quarantine)
    assert got["rule"] == "WHEEL_NOT_VERIFIED" and captured == {}


# --- Docker ---------------------------------------------------------------------------------------------------------------

def deep(quarantine, files, modules=("demo",), extra=()):
    got = sandbox_observe.observe(tree(quarantine, files, extra), list(modules), quarantine_dir=quarantine)
    assert cavr_containers() == []
    return got


def import_pids(got):
    return {pid for pid, p in got["evidence"]["processes"].items() if p["step"] == "imports"}


def lines_of(got, pids, needle):
    return [line for line in got["trace"].splitlines() if int(line.split()[0]) in pids and needle in line]


@requires_docker
def test_benign_wheel_installs_imports_and_gives_a_complete_trace(quarantine):
    got = deep(quarantine, {"demo/__init__.py": "import helper\nVALUE = helper.VALUE\n"}, modules=("demo",))
    assert got["rule"] == "DEEP_NOT_JUDGED", (got["reason"], got["output"]["text"])
    assert got["evidence"]["trace_check"] == "TRACE_COMPLETE"
    assert lines_of(got, import_pids(got), '"/site/lib/demo/__init__.py"')
    assert lines_of(got, import_pids(got), '"/site/lib/helper/__init__.py"')


@requires_docker
def test_import_that_connects_out_is_a_recorded_failed_connect(quarantine):
    code = ("import socket\ns = socket.socket()\ns.settimeout(2)\ntry:\n    s.connect(('198.51.100.24', 443))\n"
            "except OSError:\n    pass\n")
    got = deep(quarantine, {"demo/__init__.py": code})
    assert got["rule"] == "DEEP_NOT_JUDGED", got["reason"]
    connects = lines_of(got, import_pids(got), "connect(")
    assert any('sin_addr=inet_addr("198.51.100.24")' in line and "htons(443)" in line and "= -1 ENETUNREACH" in line
               for line in connects), connects


@requires_docker
def test_import_that_reads_aws_credentials_is_recorded(quarantine):
    code = ("import os\ntry:\n    open(os.path.expanduser('~/.aws/credentials')).read()\nexcept OSError:\n    pass\n")
    got = deep(quarantine, {"demo/__init__.py": code})
    assert got["rule"] == "DEEP_NOT_JUDGED", got["reason"]
    assert lines_of(got, import_pids(got), '"/tmp/home/.aws/credentials"')


@requires_docker
def test_a_pth_file_runs_at_start_up_and_is_recorded(quarantine):
    files = {"demo/__init__.py": "VALUE = 1\n", "demo-startup.pth": "import os; os.path.exists('/cavr-pth-ran')\n"}
    got = deep(quarantine, files)
    assert got["rule"] == "DEEP_NOT_JUDGED", got["reason"]
    assert lines_of(got, import_pids(got), '"/cavr-pth-ran"')


@requires_docker
def test_pip_inside_refuses_a_wheel_whose_hash_does_not_match(quarantine, tmp_path):
    nodes = tree(quarantine)
    stage = tmp_path / "stage"
    stage.mkdir()
    sandbox_observe.stage_wheels(nodes, quarantine, stage)
    (stage / "hashes.txt").write_text(f"demo==1.0 --hash=sha256:{'0' * 64}\nhelper==2.0 --hash=sha256:{nodes[1]['sha256']}\n")
    got = sandbox_observe.run_harness(sandbox_observe.install_steps(["demo"]), mounts=[(stage, "/pkg")],
                                      tmpfs=[sandbox_observe.SITE_TMPFS])
    assert cavr_containers() == []
    assert got["rule"] == "SANDBOX_EXIT_NONZERO" and "step:install:end:1" in got["trace"]
    assert "HASHES" in got["output"]["text"] or "hash" in got["output"]["text"].lower()


def native_extension():
    """(archive name, bytes) of the image's own `_bisect` extension module, and the wheel tag for this platform."""
    identity = sandbox_identity()
    code = ("import sysconfig, glob, sys; p = glob.glob('/usr/local/lib/python3.12/lib-dynload/_bisect.*.so')[0];"
            "print(p.rsplit('/', 1)[1]); print(sysconfig.get_platform().replace('-', '_').replace('.', '_'))")
    name = sandbox_exec.container_name(sandbox_exec.new_run_id(), 1)
    done = subprocess.run(sandbox_exec.docker_command(name, identity["image_id"], ["/usr/local/bin/python", "-I", "-S", "-c", code]),
                          capture_output=True, text=True, timeout=60)
    filename, platform = done.stdout.split()
    name = sandbox_exec.container_name(sandbox_exec.new_run_id(), 2)
    data = subprocess.run(sandbox_exec.docker_command(name, identity["image_id"], ["cat", f"/usr/local/lib/python3.12/lib-dynload/{filename}"]),
                          capture_output=True, timeout=60).stdout
    assert data[:4] == b"\x7fELF"
    return filename, data, f"cp312-cp312-{platform}"


@requires_docker
def test_a_wheel_with_a_native_so_imports_and_gives_a_complete_trace(quarantine):
    filename, data, tag = native_extension()
    wheel = build_wheel(quarantine, "nativedemo", "1.0", tag=tag, files={
        "nativedemo/__init__.py": "from nativedemo import _bisect\nVALUE = _bisect.bisect_left([1, 2, 3], 2)\nassert VALUE == 1\n",
        f"nativedemo/{filename}": data})
    got = sandbox_observe.observe([node_for(wheel, "nativedemo", "1.0")], ["nativedemo"], quarantine_dir=quarantine)
    assert cavr_containers() == []
    assert got["rule"] == "DEEP_NOT_JUDGED", (got["reason"], got["output"]["text"])
    mapped = [line for line in got["trace"].splitlines() if f'"/site/lib/nativedemo/{filename}"' in line and "openat(" in line]
    assert mapped and all(" = -1 " not in line for line in mapped)


@requires_docker
def test_the_same_native_wheel_cannot_load_from_the_noexec_tmp(quarantine, tmp_path):
    """Why /site is exec: installed into /tmp (noexec), the same extension module fails to load."""
    filename, data, tag = native_extension()
    wheel = build_wheel(quarantine, "nativedemo", "1.0", tag=tag, files={
        "nativedemo/__init__.py": "from nativedemo import _bisect\n", f"nativedemo/{filename}": data})
    stage = tmp_path / "stage"
    stage.mkdir()
    sandbox_observe.stage_wheels([node_for(wheel, "nativedemo", "1.0")], quarantine, stage)
    steps = [{**s, "argv": [a.replace("/site/lib", "/tmp/lib") for a in s["argv"]]}
             for s in sandbox_observe.install_steps(["nativedemo"])]
    got = sandbox_observe.run_harness(steps, mounts=[(stage, "/pkg")])
    assert cavr_containers() == []
    assert got["rule"] == "SANDBOX_EXIT_NONZERO" and "step:install:end:0" in got["trace"]
    assert re.search(r"step:imports:end:[1-9]", got["trace"])
    assert "failed to map segment" in got["output"]["text"] or "Operation not permitted" in got["output"]["text"]
