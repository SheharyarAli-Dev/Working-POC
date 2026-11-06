import subprocess
import pytest
import shutil
import sys
import tempfile
from pathlib import Path
from backend.config import ROOT


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

