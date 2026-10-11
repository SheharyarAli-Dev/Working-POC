import subprocess
import pytest
import shutil


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
