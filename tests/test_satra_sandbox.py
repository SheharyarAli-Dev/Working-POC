import json
import subprocess
import pytest
import shutil
import sys
import tempfile
from pathlib import Path
from backend.config import ASSETS, ROOT
from backend.satra import pytest_runner


@pytest.fixture(scope="module")
def docker_available():
    return shutil.which("docker") is not None


def test_sandbox_network_isolated(docker_available):
    if not docker_available:
        pytest.skip("Docker not available")
    # Verify container has network lockdown: curl/ping/socket fails
    cmd = [
        "docker", "run", "--rm",
        "--network", "none",
        "asent-sandbox:local",
        "python", "-c", "import socket; s = socket.socket(); s.settimeout(1.0);\ntry:\n    s.connect(('1.1.1.1', 80))\n    print('CONNECTED')\nexcept OSError:\n    print('BLOCKED')"
    ]
    res = subprocess.run(cmd, text=True, capture_output=True, timeout=10)
    assert res.returncode == 0
    assert "BLOCKED" in res.stdout


def test_sandbox_readonly_root(docker_available):
    if not docker_available:
        pytest.skip("Docker not available")
    # Verify root filesystem is read-only
    cmd = [
        "docker", "run", "--rm",
        "--read-only",
        "asent-sandbox:local",
        "python", "-c", "try:\n    open('/etc/test.txt', 'w').write('x')\n    print('WRITTEN')\nexcept OSError:\n    print('READONLY')"
    ]
    res = subprocess.run(cmd, text=True, capture_output=True, timeout=10)
    assert res.returncode == 0
    assert "READONLY" in res.stdout


def test_sandbox_tmpfs_isolated(docker_available):
    if not docker_available:
        pytest.skip("Docker not available")
    # Verify writable tmpfs exists and enforces size limit
    cmd = [
        "docker", "run", "--rm",
        "--tmpfs", "/tmp:rw,nosuid,size=64m",
        "asent-sandbox:local",
        "python", "-c", "with open('/tmp/test.txt', 'w') as f: f.write('hello')\nwith open('/tmp/test.txt') as f: print(f.read())"
    ]
    res = subprocess.run(cmd, text=True, capture_output=True, timeout=10)
    assert res.returncode == 0
    assert "hello" in res.stdout


def test_sandbox_execution_timeout(docker_available):
    if not docker_available:
        pytest.skip("Docker not available")
    # Verify execution timeout kill works cleanly
    cmd = [
        "docker", "run", "--rm",
        "asent-sandbox:local",
        "python", "-c", "import time; time.sleep(10)"
    ]
    with pytest.raises(subprocess.TimeoutExpired):
        subprocess.run(cmd, text=True, capture_output=True, timeout=2)


def test_runner_entry_permits_loopback_socket():
    """Host fallback audit hook in runner_entry.py must permit loopback connections (needed for socketpair on Windows)."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / 'pytest.ini').write_text('[pytest]\n')
        (p / 'test_loop.py').write_text('''
import socket, pytest

def test_loopback_permitted():
    s = socket.socket()
    try:
        s.connect(('127.0.0.1', 65432))
    except (ConnectionRefusedError, OSError) as e:
        assert 'Network unavailable' not in str(e)
''')
        res = subprocess.run([sys.executable, '-I', str(ROOT / 'backend/satra/runner_entry.py'), str(p), '-q', str(p / 'test_loop.py')], capture_output=True, text=True)
        assert res.returncode == 0
        assert '1 passed' in res.stdout


def test_runner_entry_blocks_external_socket():
    """Host fallback audit hook in runner_entry.py must forbid non-loopback network connections."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / 'pytest.ini').write_text('[pytest]\n')
        (p / 'test_ext.py').write_text('''
import socket, pytest

def test_external_blocked():
    s = socket.socket()
    with pytest.raises(PermissionError, match='Network unavailable'):
        s.connect(('8.8.8.8', 53))
''')
        res = subprocess.run([sys.executable, '-I', str(ROOT / 'backend/satra/runner_entry.py'), str(p), '-q', str(p / 'test_ext.py')], capture_output=True, text=True)
        assert res.returncode == 0
        assert '1 passed' in res.stdout


def test_runner_entry_blocks_subprocess():
    """Host fallback audit hook in runner_entry.py must forbid child process creation."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / 'pytest.ini').write_text('[pytest]\n')
        (p / 'test_sub.py').write_text('''
import subprocess, pytest

def test_subproc_blocked():
    with pytest.raises(PermissionError, match='Child process forbidden'):
        subprocess.Popen(['echo', 'hi'])
''')
        res = subprocess.run([sys.executable, '-I', str(ROOT / 'backend/satra/runner_entry.py'), str(p), '-q', str(p / 'test_sub.py')], capture_output=True, text=True)
        assert res.returncode == 0
        assert '1 passed' in res.stdout


def test_runner_entry_blocks_forbidden_local_services():
    """Host fallback audit hook must forbid access to sensitive local service ports (e.g. Ollama 11434, Docker 2375)."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / 'pytest.ini').write_text('[pytest]\n')
        (p / 'test_local_svc.py').write_text('''
import socket, pytest

def test_forbidden_local_port():
    s = socket.socket()
    with pytest.raises(PermissionError, match='forbidden in built-in test mode'):
        s.connect(('127.0.0.1', 11434))

def test_privileged_local_port():
    s = socket.socket()
    with pytest.raises(PermissionError, match='forbidden in built-in test mode'):
        s.connect(('127.0.0.1', 80))
''')
        res = subprocess.run([sys.executable, '-I', str(ROOT / 'backend/satra/runner_entry.py'), str(p), '-q', str(p / 'test_local_svc.py')], capture_output=True, text=True)
        assert res.returncode == 0
        assert '2 passed' in res.stdout


# --- [owner review: SATRA] Seccomp profile and Docker argument tests --------------------------

def test_seccomp_profile_validation_success():
    """Default SATRA seccomp profile exists, is readable, contains required schema keys, and enforces strict rules."""
    path, err = pytest_runner.validate_seccomp_profile(pytest_runner.SECCOMP_PROFILE)
    assert err is None
    assert path == pytest_runner.SECCOMP_PROFILE
    assert path.is_file()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data.get("defaultAction") == "SCMP_ACT_ERRNO"
    assert "architectures" in data and len(data["architectures"]) > 0
    assert "syscalls" in data
    assert isinstance(data["syscalls"], list) and len(data["syscalls"]) > 0

    all_allowed = set()
    for entry in data["syscalls"]:
        if entry.get("action") == "SCMP_ACT_ALLOW":
            all_allowed.update(entry.get("names", []))
        if "clone3" in entry.get("names", []):
            assert entry.get("action") == "SCMP_ACT_ERRNO"
            assert entry.get("errnoRet") == 38
        if "clone" in entry.get("names", []):
            assert "args" in entry and len(entry["args"]) > 0
            assert entry["args"][0]["op"] == "SCMP_CMP_MASKED_EQ"

    # Strict security properties: no ptrace, no privilege changes
    forbidden = {"ptrace", "setuid", "setgroups", "setreuid", "setregid"}
    found_forbidden = all_allowed.intersection(forbidden)
    assert not found_forbidden, f"Profile contains forbidden syscalls: {found_forbidden}"


def test_seccomp_profile_validation_missing_file(tmp_path):
    """Validation fails closed when profile path does not exist."""
    missing = tmp_path / "missing-seccomp.json"
    path, err = pytest_runner.validate_seccomp_profile(missing)
    assert path is None
    assert "not found" in err


def test_seccomp_profile_validation_invalid_json(tmp_path):
    """Validation fails closed when profile file is not valid JSON."""
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("not json content {")
    path, err = pytest_runner.validate_seccomp_profile(bad_json)
    assert path is None
    assert "invalid seccomp profile JSON" in err


def test_seccomp_profile_validation_missing_keys(tmp_path):
    """Validation fails closed when profile lacks required schema fields."""
    missing_keys = tmp_path / "no_keys.json"
    missing_keys.write_text('{"foo": "bar"}')
    path, err = pytest_runner.validate_seccomp_profile(missing_keys)
    assert path is None
    assert "missing defaultAction or syscalls" in err


def test_seccomp_docker_args_when_disabled(monkeypatch):
    """When seccomp is not requested, no seccomp arguments are returned."""
    monkeypatch.delenv("SATRA_SECCOMP", raising=False)
    monkeypatch.delenv("ASENT_SECCOMP_PROFILE", raising=False)
    args, err = pytest_runner.get_seccomp_docker_args(None)
    assert args == [] and err is None
    args, err = pytest_runner.get_seccomp_docker_args(False)
    assert args == [] and err is None


def test_seccomp_docker_args_explicit_profile(tmp_path):
    """Passing a valid profile path returns the appropriate --security-opt seccomp argument."""
    valid_profile = tmp_path / "custom-seccomp.json"
    valid_profile.write_text('{"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []}')
    args, err = pytest_runner.get_seccomp_docker_args(valid_profile)
    assert err is None
    assert args == ["--security-opt", f"seccomp={valid_profile.resolve()}"]


def test_seccomp_docker_args_default_when_true():
    """Passing seccomp=True returns argument referencing the shared asent-seccomp.json."""
    args, err = pytest_runner.get_seccomp_docker_args(True)
    assert err is None
    assert args == ["--security-opt", f"seccomp={pytest_runner.SECCOMP_PROFILE}"]


def test_seccomp_docker_args_env_var(monkeypatch):
    """Setting SATRA_SECCOMP=1 activates seccomp with default profile."""
    monkeypatch.setenv("SATRA_SECCOMP", "1")
    args, err = pytest_runner.get_seccomp_docker_args(None)
    assert err is None
    assert args == ["--security-opt", f"seccomp={pytest_runner.SECCOMP_PROFILE}"]


def test_seccomp_docker_args_fails_closed_on_missing_profile(tmp_path):
    """Missing required profile returns error and empty args (fail-closed)."""
    args, err = pytest_runner.get_seccomp_docker_args(tmp_path / "nonexistent.json")
    assert args == []
    assert "not found" in err


def test_run_pytest_fails_closed_on_missing_seccomp_profile(tmp_path, monkeypatch):
    """run_pytest refuses execution and returns available=False when seccomp profile is missing."""
    monkeypatch.setattr(pytest_runner, "availability", lambda: {"docker": {"available": True}, "podman": {"available": False}})
    (tmp_path / "p").mkdir()
    (tmp_path / "p" / "pytest.ini").write_text("[pytest]\n")
    missing = tmp_path / "missing-seccomp.json"
    result = pytest_runner.run_pytest(tmp_path / "p", tmp_path / "out", external=True, seccomp=missing)
    assert result["available"] is False
    assert result["exit_code"] is None
    assert "Seccomp security check failed" in result["reason"]
    assert "not found" in result["reason"]


def test_run_pytest_fails_closed_on_invalid_seccomp_profile(tmp_path, monkeypatch):
    """run_pytest refuses execution when seccomp profile contains invalid JSON."""
    monkeypatch.setattr(pytest_runner, "availability", lambda: {"docker": {"available": True}, "podman": {"available": False}})
    (tmp_path / "p").mkdir()
    (tmp_path / "p" / "pytest.ini").write_text("[pytest]\n")
    bad = tmp_path / "bad.json"
    bad.write_text("corrupted content")
    result = pytest_runner.run_pytest(tmp_path / "p", tmp_path / "out", external=True, seccomp=bad)
    assert result["available"] is False
    assert result["exit_code"] is None
    assert "Seccomp security check failed" in result["reason"]


def test_run_pytest_generates_seccomp_docker_arguments(tmp_path, monkeypatch):
    """run_pytest includes --security-opt seccomp=... alongside all existing isolation flags."""
    captured_cmd = []

    def mock_run(cmd, *args, **kwargs):
        captured_cmd.extend(cmd)
        results_xml = Path(cmd[cmd.index("--junitxml=/results/results.xml")].split("=", 1)[1] if "--junitxml=/results/results.xml" in cmd else cmd[[i for i, part in enumerate(cmd) if part.startswith("--junitxml=")][0]].split("=", 1)[1])
        # Find results volume mapping: -v <host_results>:/results:rw
        for i, part in enumerate(cmd):
            if part == "-v" and cmd[i + 1].endswith(":/results:rw"):
                host_results = Path(cmd[i + 1].split(":")[0])
                (host_results / "results.xml").write_text('<testsuites><testsuite name="p" tests="1"><testcase classname="t" name="test_one"/></testsuite></testsuites>')
                break
        return subprocess.CompletedProcess(cmd, 0, "1 passed", "")

    monkeypatch.setattr(pytest_runner, "availability", lambda: {"docker": {"available": True}, "podman": {"available": False}})
    monkeypatch.setattr(pytest_runner.subprocess, "run", mock_run)

    (tmp_path / "p").mkdir()
    (tmp_path / "p" / "pytest.ini").write_text("[pytest]\n")
    (tmp_path / "p" / "tests").mkdir()
    (tmp_path / "p" / "tests" / "test_dummy.py").write_text("def test_dummy(): pass\n")

    result = pytest_runner.run_pytest(tmp_path / "p", tmp_path / "out", external=True, targets=["tests"], seccomp=True)
    assert result["available"] is True
    cmd = captured_cmd
    # Check that seccomp profile is passed
    assert "--security-opt" in cmd
    sec_opts = [cmd[i + 1] for i, part in enumerate(cmd) if part == "--security-opt"]
    assert "no-new-privileges" in sec_opts
    assert f"seccomp={pytest_runner.SECCOMP_PROFILE}" in sec_opts
    # Check that all other isolation flags are preserved
    assert "--network" in cmd and cmd[cmd.index("--network") + 1] == "none"
    assert "--read-only" in cmd
    assert "--cap-drop" in cmd and cmd[cmd.index("--cap-drop") + 1] == "ALL"
    assert "--memory" in cmd and cmd[cmd.index("--memory") + 1] == "512m"
    assert "--cpus" in cmd and cmd[cmd.index("--cpus") + 1] == "1"
    assert "--pids-limit" in cmd and cmd[cmd.index("--pids-limit") + 1] == "64"
    assert "--tmpfs" in cmd and cmd[cmd.index("--tmpfs") + 1] == "/tmp:rw,nosuid,size=64m"
    assert "seccomp" in result["isolation"]


def test_real_docker_seccomp_profile_starts_and_runs_python(docker_available):
    """Real Docker daemon executes Python cleanly under SATRA's seccomp profile with all isolation flags."""
    if not docker_available:
        pytest.skip("Docker not available")
    cmd = [
        "docker", "run", "--rm",
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--security-opt", f"seccomp={pytest_runner.SECCOMP_PROFILE}",
        "--memory", "512m",
        "--cpus", "1",
        "--pids-limit", "64",
        "--tmpfs", "/tmp:rw,nosuid,size=64m",
        "asent-satra-runner:local",
        "python", "-c", "print('seccomp-container-ok')"
    ]
    res = subprocess.run(cmd, text=True, capture_output=True, timeout=20)
    assert res.returncode == 0, res.stderr
    assert "seccomp-container-ok" in res.stdout


def test_real_docker_seccomp_trusted_run_passes(docker_available, tmp_path):
    """Real Docker run of the InvoiceHub trusted test suite passes completely with seccomp enabled."""
    if not docker_available:
        pytest.skip("Docker not available")
    ih = ROOT / "demo_project/InvoiceHub"
    trusted_data = {"fixtures/invoice.pdf": (ih / "fixtures/invoice.pdf").read_bytes()}
    res = pytest_runner.run_pytest(
        ih,
        tmp_path / "out",
        selected="all",
        trusted=True,
        trusted_tests_dir=ih / ".asent/satra/trusted_tests",
        pytest_ini=ih / "pytest.ini",
        image="asent-sandbox:local",
        trusted_data=trusted_data,
        seccomp=True
    )
    assert res["available"] is True, res.get("reason")
    assert res["exit_code"] == 0, f"stdout: {res.get('stdout')}\nstderr: {res.get('stderr')}"
    assert res["isolation"] == "container with network none and seccomp"
    assert len(res["tests"]) == 10
    assert all(t["status"] == "PASS" for t in res["tests"])


def test_real_docker_legacy_shared_profile_fails_at_runc_init(docker_available):
    """Documents and verifies that legacy asent-seccomp.json fails at runc init on modern engines."""
    if not docker_available:
        pytest.skip("Docker not available")
    cmd = [
        "docker", "run", "--rm",
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--security-opt", f"seccomp={pytest_runner.SHARED_SECCOMP_PROFILE}",
        "--memory", "512m",
        "--cpus", "1",
        "--pids-limit", "64",
        "--tmpfs", "/tmp:rw,nosuid,size=64m",
        "asent-satra-runner:local",
        "python", "-c", "print('fail')"
    ]
    res = subprocess.run(cmd, text=True, capture_output=True, timeout=20)
    assert res.returncode != 0
    assert "fstatfs" in res.stderr or "operation not permitted" in res.stderr
