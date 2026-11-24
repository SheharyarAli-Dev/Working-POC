"""PR 3 of docs/cavr-m2-plan.md: CAVR's own sandbox image, its identity check and its lockdown flags.

Unit tests replace `sandbox_image.RUN` (no process starts). Docker tests (`requires_docker`) run only with
CAVR_DOCKER=1 and use the real `asent-cavr-sandbox:local`, built once per session if it is missing.
"""
import json
import subprocess
import time
from pathlib import Path

import pytest

from backend.cavr import sandbox_exec, sandbox_image, sandbox_observe
from tests.test_cavr_support import cavr_containers, requires_docker, sandbox_identity

REPO = Path(__file__).resolve().parents[1]
IMAGE_ID = "sha256:" + "ab" * 32
OTHER_ID = "sha256:" + "cd" * 32


def answer(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def inspect_output(image_id=IMAGE_ID, recipe=None):
    labels = {sandbox_image.RECIPE_LABEL: recipe or sandbox_image.sha256_file(sandbox_image.DOCKERFILE)}
    return f"{json.dumps(image_id)} {json.dumps(labels)}\n"


@pytest.fixture
def engine(monkeypatch):
    """A fake `docker`: set `.reply` (a CompletedProcess or an exception); calls are recorded."""
    class Engine:
        reply = answer(stdout=inspect_output())
        calls = []

    def run(cmd, **kwargs):
        Engine.calls.append(cmd)
        if isinstance(Engine.reply, BaseException):
            raise Engine.reply
        return Engine.reply
    Engine.calls = []
    monkeypatch.setattr(sandbox_image, "RUN", run)
    return Engine


@pytest.fixture
def record(tmp_path):
    path = tmp_path / "sandbox-image.json"
    path.write_text(json.dumps({"image": sandbox_image.IMAGE, "image_id": IMAGE_ID}))
    return path


# --- identity (unit) -----------------------------------------------------------------------------------------------------

def test_recorded_image_built_from_the_current_dockerfile_is_ok(engine, record):
    got = sandbox_image.image_identity(record=record)
    assert got["ok"] is True and got["rule"] == "IMAGE_OK" and got["image_id"] == IMAGE_ID
    assert got["recipe_sha256"] == sandbox_image.sha256_file(sandbox_image.DOCKERFILE)
    assert got["seccomp_sha256"] == sandbox_image.sha256_file(sandbox_image.SECCOMP_PROFILE)
    assert engine.calls == [["docker", "image", "inspect", "--format", "{{json .Id}} {{json .Config.Labels}}",
                             "asent-cavr-sandbox:local"]]


def test_missing_image_is_unresolved(engine, record):
    engine.reply = answer(1, stderr="Error response from daemon: No such image: asent-cavr-sandbox:local")
    got = sandbox_image.image_identity(record=record)
    assert got["ok"] is False and got["rule"] == "IMAGE_MISSING" and got["image_id"] is None


def test_image_id_mismatch_is_unresolved(engine, record):
    engine.reply = answer(stdout=inspect_output(OTHER_ID))
    got = sandbox_image.image_identity(record=record)
    assert got["ok"] is False and got["rule"] == "IMAGE_ID_MISMATCH"
    assert OTHER_ID in got["reason"] and IMAGE_ID in got["reason"]


def test_no_build_record_is_unresolved(engine, tmp_path):
    got = sandbox_image.image_identity(record=tmp_path / "absent.json")
    assert got["ok"] is False and got["rule"] == "IMAGE_NOT_RECORDED"


@pytest.mark.parametrize("text", ["not json", "[]", '{"image_id": 5}', "{}"])
def test_unreadable_build_record_is_unresolved(engine, tmp_path, text):
    path = tmp_path / "bad.json"
    path.write_text(text)
    assert sandbox_image.image_identity(record=path)["rule"] == "IMAGE_NOT_RECORDED"


def test_stale_recipe_label_is_unresolved(engine, record):
    engine.reply = answer(stdout=inspect_output(recipe="0" * 64))
    got = sandbox_image.image_identity(record=record)
    assert got["ok"] is False and got["rule"] == "IMAGE_STALE"


def test_image_without_labels_is_stale(engine, record):
    engine.reply = answer(stdout=f"{json.dumps(IMAGE_ID)} null\n")
    assert sandbox_image.image_identity(record=record)["rule"] == "IMAGE_STALE"


@pytest.mark.parametrize("reply", [FileNotFoundError("docker"), subprocess.TimeoutExpired("docker", 15),
                                   PermissionError("denied"),
                                   answer(1, stderr="Cannot connect to the Docker daemon at unix:///nonexistent")])
def test_no_engine_is_unresolved(engine, record, reply):
    engine.reply = reply
    got = sandbox_image.image_identity(record=record)
    assert got["ok"] is False and got["rule"] == "ENGINE_UNAVAILABLE"


@pytest.mark.parametrize("reply", [answer(2, stderr="something odd"), answer(stdout="garbage"),
                                   answer(stdout='"md5:x" {}'), RuntimeError("boom")])
def test_inspect_error_is_unresolved(engine, record, reply):
    engine.reply = reply
    got = sandbox_image.image_identity(record=record)
    assert got["ok"] is False and got["rule"] == "ENGINE_ERROR"


def test_missing_seccomp_profile_is_unresolved(engine, record, monkeypatch, tmp_path):
    monkeypatch.setattr(sandbox_image, "SECCOMP_PROFILE", tmp_path / "absent.json")
    got = sandbox_image.image_identity(record=record)
    assert got["ok"] is False and got["rule"] == "SECCOMP_MISSING" and engine.calls == []


def test_build_records_the_built_image_id(engine, tmp_path):
    replies = iter([answer(), answer(stdout=inspect_output())])
    sandbox_image.RUN = lambda cmd, **kw: (engine.calls.append(cmd), next(replies))[1]
    path = tmp_path / "rec" / "sandbox-image.json"
    got = sandbox_image.build(record=path, emit=lambda line: None)
    assert got["ok"] is True and got["image_id"] == IMAGE_ID
    recipe = sandbox_image.sha256_file(sandbox_image.DOCKERFILE)
    assert engine.calls[0][:5] == ["docker", "build", "--label", f"{sandbox_image.RECIPE_LABEL}={recipe}", "-t"]
    saved = json.loads(path.read_text())
    assert saved["image_id"] == IMAGE_ID and saved["recipe_sha256"] == recipe and saved["base"].startswith("python:3.12-slim@sha256:")


def test_failed_build_writes_no_record(engine, tmp_path):
    engine.reply = answer(1)
    path = tmp_path / "sandbox-image.json"
    got = sandbox_image.build(record=path, emit=lambda line: None)
    assert got["ok"] is False and got["rule"] == "BUILD_FAILED" and not path.exists()


def test_build_without_engine_is_not_ok(engine, tmp_path):
    engine.reply = FileNotFoundError("docker")
    assert sandbox_image.build(record=tmp_path / "r.json", emit=lambda line: None)["rule"] == "ENGINE_UNAVAILABLE"


# --- image recipe and profile (unit) --------------------------------------------------------------------------------------

def test_dockerfile_base_is_pinned_by_digest():
    base = sandbox_image.base_image()
    assert base == "python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"
    text = sandbox_image.DOCKERFILE.read_text()
    assert text.count("\nFROM ") == 1 and "strace" in text and "libfaketime" in text and "useradd -u 10001" in text


def test_image_is_cavr_own_not_satra():
    assert sandbox_image.IMAGE == "asent-cavr-sandbox:local" != "asent-sandbox:local"
    assert sandbox_image.DOCKERFILE == REPO / "docker/cavr-sandbox/Dockerfile"


def _names(profile):
    return [name for entry in profile["syscalls"] for name in entry["names"]]


def test_shared_profile_lacks_what_strace_and_runc_need():
    shared = set(_names(json.loads(sandbox_image.SHARED_SECCOMP_PROFILE.read_text())))
    needed = {"ptrace", "wait4", "execve", "clone", "fstatfs", "statx", "setreuid", "setregid", "setgroups"}
    assert needed - shared == needed


def test_cavr_profile_is_the_shared_profile_plus_listed_additions():
    shared = json.loads(sandbox_image.SHARED_SECCOMP_PROFILE.read_text())
    cavr = json.loads(sandbox_image.SECCOMP_PROFILE.read_text())
    assert cavr["defaultAction"] == shared["defaultAction"] == "SCMP_ACT_ERRNO"
    assert cavr["architectures"] == shared["architectures"]
    assert cavr["syscalls"][0]["names"] == shared["syscalls"][0]["names"]
    added = cavr["syscalls"][1:]
    assert all(entry["comment"].startswith("CAVR addition: ") for entry in added)
    names = _names({"syscalls": added})
    # 46 until PR 7, which added chdir and fchdir (packages that change directory are traced, not refused).
    assert len(names) == len(set(names)) == 48 and not set(names) & set(shared["syscalls"][0]["names"])
    assert {"chdir", "fchdir"} <= set(names)
    # clone only without CLONE_UNTRACED and namespace flags; clone3 answers ENOSYS (glibc falls back to clone).
    by_name = {name: entry for entry in added for name in entry["names"]}
    assert by_name["clone"]["names"] == ["clone"] and by_name["clone"]["action"] == "SCMP_ACT_ALLOW"
    assert by_name["clone"]["args"] == [{"index": 0, "value": 0x7E820000, "valueTwo": 0, "op": "SCMP_CMP_MASKED_EQ"}]
    assert 0x7E820000 & 0x00800000 and 0x7E820000 & 0x7E020000 == 0x7E020000  # CLONE_UNTRACED + Docker's namespace mask
    assert by_name["clone3"] == {**by_name["clone3"], "names": ["clone3"], "action": "SCMP_ACT_ERRNO", "errnoRet": 38}
    unconditional = [entry for entry in added if entry["action"] == "SCMP_ACT_ALLOW" and "args" not in entry]
    assert not {"clone", "clone3"} & set(_names({"syscalls": unconditional}))
    # Never added: kernel modules, mounts, namespaces, keyrings, BPF, reboot, the clock.
    assert not set(names) & {"mount", "umount2", "unshare", "setns", "init_module", "finit_module", "bpf", "keyctl",
                             "add_key", "reboot", "settimeofday", "clock_settime", "pivot_root", "chroot", "ptrace_attach"}


# --- docker run flags (unit) ---------------------------------------------------------------------------------------------

def test_lockdown_flags_are_the_planned_set():
    flags = sandbox_exec.lockdown_flags()
    assert flags == ["--network", "none", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
                     "--cap-drop", "ALL", "--cap-add", "SYS_PTRACE", "--cap-add", "SETUID", "--cap-add", "SETGID",
                     "--cap-add", "DAC_READ_SEARCH",
                     "--security-opt", "no-new-privileges", "--security-opt", f"seccomp={sandbox_image.SECCOMP_PROFILE}",
                     "--pids-limit", "64", "--memory", "256m", "--memory-swap", "256m", "--cpus", "1",
                     "--ulimit", "nofile=256:256", "--ulimit", "fsize=67108864:67108864", "--ulimit", "core=0:0",
                     "--log-driver", "none", "--hostname", "cavr-sandbox"]


def test_docker_command_runs_the_image_by_id_with_read_only_mounts(tmp_path):
    cmd = sandbox_exec.docker_command("cavr-0123456789ab-1", IMAGE_ID, ["true"], mounts=[(tmp_path, "/pkg")],
                                      env={"HOME": "/tmp"})
    assert cmd[:5] == ["docker", "run", "--rm", "--name", "cavr-0123456789ab-1"]
    assert cmd[-2:] == [IMAGE_ID, "true"]
    assert f"type=bind,src={tmp_path},dst=/pkg,readonly" in cmd and "--env" in cmd and "HOME=/tmp" in cmd
    assert not {"--user", "-u", "--privileged", "-v", "--volume", "-i", "-t", "--pid", "--ipc", "--userns"} & set(cmd)
    assert "docker.sock" not in " ".join(cmd)


@pytest.mark.parametrize("name, image, mounts, env", [
    ("box-1", IMAGE_ID, [], {}),                                      # not cavr-<hex>-<n>
    ("cavr-0123456789ab-1", "asent-cavr-sandbox:local", [], {}),      # a tag, not the checked ID
    ("cavr-0123456789ab-1", IMAGE_ID, [("/a,readonly=false", "/pkg")], {}),
    ("cavr-0123456789ab-1", IMAGE_ID, [("/a", "relative")], {}),
    ("cavr-0123456789ab-1", IMAGE_ID, [], {"lower": "x"}),
    ("cavr-0123456789ab-1", IMAGE_ID, [], {"A": "x\0y"}),
])
def test_docker_command_refuses_what_it_cannot_pass_safely(name, image, mounts, env):
    with pytest.raises(ValueError):
        sandbox_exec.docker_command(name, image, ["true"], mounts=mounts, env=env)


# --- Docker -------------------------------------------------------------------------------------------------------------

def _run(identity, command, name="cavr-000000000003-1", timeout=60):
    cmd = sandbox_exec.docker_command(name, identity["image_id"], command)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


@requires_docker
def test_real_image_identity_is_its_inspected_id():
    identity = sandbox_identity()
    done = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", sandbox_image.IMAGE],
                          capture_output=True, text=True, timeout=30)
    assert identity["ok"] and identity["image_id"] == done.stdout.strip()


@requires_docker
def test_image_has_strace_and_libfaketime():
    done = _run(sandbox_identity(), ["sh", "-c", "strace -V | head -1; ls /usr/lib/*/faketime/libfaketime.so.1; id -u cavr"])
    assert done.returncode == 0, done.stderr
    lines = done.stdout.split()
    assert "strace" in done.stdout and any(line.endswith("/faketime/libfaketime.so.1") for line in lines)
    assert lines[-1] == "10001"
    assert cavr_containers() == []


SETUID_SCAN = r'''
import os, stat
found = []
for top, dirs, files in os.walk("/"):
    if top in ("/proc", "/sys", "/dev"):
        dirs[:] = []
        continue
    for name in dirs + files:
        path = os.path.join(top, name)
        try:
            info = os.lstat(path)
        except OSError as exc:
            found.append(f"UNREADABLE {path} {exc}")
            continue
        if stat.S_ISREG(info.st_mode) and info.st_mode & (stat.S_ISUID | stat.S_ISGID):
            found.append(f"SETID {path}")
        if not stat.S_ISLNK(info.st_mode):
            try:
                os.getxattr(path, "security.capability", follow_symlinks=False)
                found.append(f"FILECAP {path}")
            except OSError:
                pass
print("\n".join(found) or "NONE")
'''


@requires_docker
def test_no_file_in_the_image_has_setuid_setgid_or_file_capabilities():
    """strace holds DAC_READ_SEARCH (PR 7); nothing a package process can exec may gain a privilege (Q5)."""
    done = _run(sandbox_identity(), ["/usr/local/bin/python", "-I", "-S", "-c", SETUID_SCAN])
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "NONE", done.stdout[:2000]


@requires_docker
def test_a_package_process_holds_no_capability():
    """`strace -u cavr` drops to UID 10001: every capability set is empty, so DAC_READ_SEARCH stays with strace."""
    done = _run(sandbox_identity(), ["strace", "-f", "-q", "-e", "trace=none", "-u", "cavr", "--", "/bin/sh", "-c",
                                     "grep -E '^Cap(Inh|Prm|Eff|Amb)' /proc/self/status; cat /etc/shadow 2>&1 || true"])
    assert done.returncode == 0, done.stderr
    sets = dict(line.split(":\t") for line in done.stdout.splitlines() if line.startswith("Cap"))
    assert sets == {"CapInh": "0000000000000000", "CapPrm": "0000000000000000", "CapEff": "0000000000000000",
                    "CapAmb": "0000000000000000"}
    assert "Permission denied" in done.stdout


@requires_docker
def test_the_image_pip_is_the_pinned_version():
    """sandbox_observe.PIP_CODE replaces pip's User-Agent builder; it is written for this pip (PR 7)."""
    identity = sandbox_identity()
    done = _run(identity, ["/usr/local/bin/python", "-I", "-m", "pip", "--version"])
    assert done.returncode == 0 and done.stdout.split()[:2] == ["pip", sandbox_observe.PIP_VERSION], done.stdout
    labels = json.loads(subprocess.run(["docker", "image", "inspect", "--format", "{{json .Config.Labels}}",
                                        identity["image_id"]], capture_output=True, text=True, timeout=30).stdout)
    assert labels["org.asent.cavr.pip-version"] == sandbox_observe.PIP_VERSION
    assert f'ARG PIP_VERSION={sandbox_observe.PIP_VERSION}' in sandbox_image.DOCKERFILE.read_text()


@requires_docker
def test_python_and_strace_start_under_the_cavr_profile():
    done = _run(sandbox_identity(), ["strace", "-f", "-q", "-u", "cavr", "--", "/usr/local/bin/python", "-I", "-S", "-c",
                                     "import os; print(os.getuid(), os.geteuid())"])
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "10001 10001"
    assert done.stderr.rstrip().endswith("+++ exited with 0 +++")


@requires_docker
def test_the_shared_profile_is_not_used_and_would_not_start_python():
    """The shared profile is SATRA's; CAVR never passes it. On this engine it cannot start a container at all."""
    assert "asent-seccomp.json" not in " ".join(sandbox_exec.lockdown_flags())
    identity = sandbox_identity()
    cmd = sandbox_exec.docker_command("cavr-000000000003-2", identity["image_id"], ["/usr/local/bin/python", "-c", "1"],
                                      seccomp=sandbox_image.SHARED_SECCOMP_PROFILE)
    assert subprocess.run(cmd, capture_output=True, text=True, timeout=60).returncode != 0
    assert cavr_containers() == []


@requires_docker
def test_running_container_has_every_lockdown_flag(tmp_path):
    identity = sandbox_identity()
    name = "cavr-000000000003-3"
    (tmp_path / "f").write_text("x")
    cmd = sandbox_exec.docker_command(name, identity["image_id"], ["sleep", "30"], mounts=[(tmp_path, "/pkg")],
                                      env={"HOME": "/tmp"})
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        info = None
        for _ in range(100):
            done = subprocess.run(["docker", "inspect", name], capture_output=True, text=True, timeout=30)
            if done.returncode == 0 and json.loads(done.stdout)[0]["State"]["Running"]:
                info = json.loads(done.stdout)[0]
                break
            time.sleep(0.1)
        assert info is not None, "container did not start"
        host = info["HostConfig"]
        assert host["ReadonlyRootfs"] is True and host["NetworkMode"] == "none"
        assert host["CapDrop"] == ["ALL"]
        assert sorted(c.removeprefix("CAP_") for c in host["CapAdd"]) == ["DAC_READ_SEARCH", "SETGID", "SETUID", "SYS_PTRACE"]
        assert "no-new-privileges" in host["SecurityOpt"]
        seccomp = [opt for opt in host["SecurityOpt"] if opt.startswith("seccomp=")]
        assert len(seccomp) == 1
        assert json.loads(seccomp[0].removeprefix("seccomp=")) == json.loads(sandbox_image.SECCOMP_PROFILE.read_text())
        assert host["PidsLimit"] == 64 and host["Memory"] == host["MemorySwap"] == 256 * 1024 * 1024
        assert host["NanoCpus"] == 1_000_000_000 and host["Privileged"] is False
        assert {u["Name"]: (u["Soft"], u["Hard"]) for u in host["Ulimits"]} == {
            "nofile": (256, 256), "fsize": (67108864, 67108864), "core": (0, 0)}
        assert host["Tmpfs"] == {"/tmp": "rw,noexec,nosuid,nodev,size=64m,mode=1777"}
        assert host["LogConfig"]["Type"] == "none" and host["AutoRemove"] is True
        assert info["Config"]["User"] == ""  # strace is the container's root process (Q5); packages run as 10001
        assert all(m["RW"] is False for m in info["Mounts"]) and len(info["Mounts"]) == 1
        assert not any("docker.sock" in m["Source"] for m in info["Mounts"])
        assert info["Image"] == identity["image_id"]
    finally:
        subprocess.run(["docker", "kill", name], capture_output=True, timeout=30)
        proc.wait(timeout=30)
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30)
    assert cavr_containers() == []


@requires_docker
def test_container_has_only_loopback():
    done = _run(sandbox_identity(), ["/usr/local/bin/python", "-I", "-S", "-c",
                                     "import os; print(' '.join(sorted(os.listdir('/sys/class/net'))))"])
    assert done.returncode == 0, done.stderr
    assert done.stdout.split() == ["lo"]
