"""The host fallback of the CAVR lab runs only hash-pinned inert sources (backend/cavr/sandbox.py).

Without Docker/Podman, `run_counterfactual` refuses any source whose LF-normalised SHA-256 is not in
scenarios/laboratory_hashes.json `cavr_sources`. SATRA's host fallback reads `python_sources` from the same file
for the vendored copy. These tests keep the pins in step with the shipped sources, and run the real fallback with
the engines hidden, so a changed lab source fails on every machine, with or without Docker.
"""
import hashlib
import json
import re
import tempfile

import pytest

from backend.config import ASSETS, ROOT
from backend.cavr import sandbox

LAB_DIR = ROOT / 'scenarios' / 'cavr_controlled'
# The file `sandbox.run_counterfactual` reads.
PINS = json.loads((ASSETS / 'scenarios' / 'laboratory_hashes.json').read_text())
PDF = ROOT / 'demo_project' / 'InvoiceHub' / 'fixtures' / 'invoice.pdf'
REFUSAL = 'Untrusted package requires Docker/Podman; host fallback only accepts hash-pinned inert sources'
# Any of these in a run of the safe adapter means it is not inert.
FORBIDDEN = {'PROCESS_CREATE', 'NETWORK_CONNECT', 'FILE_WRITE', 'SECRET_ACCESS'}
# The one write allowed, once per run: the interpreter caching the imported adapter's bytecode inside the disposable
# workspace (the harness runs with `-I`, which ignores PYTHONDONTWRITEBYTECODE). The old, approved adapter shows the
# same write.
BYTECODE_CACHE = re.compile(re.escape(tempfile.gettempdir()) + r'[\\/]asent-cavr-[^\\/]+[\\/]__pycache__[\\/]'
                            r'package\.cpython-\d+\.pyc(\.\d+)?')


def lf_digest(path):
    return hashlib.sha256(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest()


@pytest.fixture
def no_engine(monkeypatch):
    """The real `availability()`, with docker, podman and strace reported unavailable."""
    real = sandbox.availability

    def hidden():
        caps = real()
        for name in ('docker', 'podman', 'strace'):
            caps[name] = {**caps[name], 'available': False, 'reason': 'hidden by test'}
        return caps
    monkeypatch.setattr(sandbox, 'availability', hidden)


def test_every_cavr_lab_source_is_pinned_for_the_host_fallback():
    sources = sorted(LAB_DIR.glob('invoice_pdf_*.py'))
    assert [p.name for p in sources] == ['invoice_pdf_lab.py', 'invoice_pdf_safe.py']
    digests = {p.name: lf_digest(p) for p in sources}
    assert sorted(PINS['cavr_sources']) == sorted(digests.values()), digests
    missing = {name: d for name, d in digests.items() if d not in PINS['python_sources']}
    assert not missing, f'not pinned for SATRA host runs: {missing}'


def test_pinned_lab_sources_run_on_the_host_without_docker(no_engine, tmp_path):
    events = []
    result = sandbox.run_counterfactual(LAB_DIR / 'invoice_pdf_safe.py', PDF, tmp_path, lambda k, d: events.append((k, d)))
    assert result['available'], result
    assert result['backend'] == 'PINNED_INERT_LAB_PYTHON_AUDIT'
    assert result['execution_modes'] == {'containerized': False, 'kernel_strace_observation': False,
                                         'python_audit_only_fallback': True}
    normal, counterfactual = result['runs']
    assert normal['facts']['functional_text'] and normal['facts']['functional_text'] == counterfactual['facts']['functional_text']
    assert not normal['facts']['canary_received'] and not counterfactual['facts']['canary_received']
    for run in result['runs']:
        flagged = [event for event in run['events'] if event['type'] in FORBIDDEN]
        cache_writes = [event for event in flagged if event['type'] == 'FILE_WRITE'
                        and BYTECODE_CACHE.fullmatch(event['resource'])]
        assert len(cache_writes) <= 1 and flagged == cache_writes, (run['mode'], flagged)
    assert not [k for k, _ in events if k == 'cavr.runtime_event']


def test_an_unpinned_source_is_still_refused_without_docker(no_engine, tmp_path):
    changed = tmp_path / 'invoice_pdf_safe.py'
    changed.write_bytes((LAB_DIR / 'invoice_pdf_safe.py').read_bytes() + b'# one added line\n')
    assert lf_digest(changed) not in PINS['cavr_sources']
    result = sandbox.run_counterfactual(changed, PDF, tmp_path / 'out', lambda k, d: None)
    assert result == {'available': False, 'reason': REFUSAL, 'runs': []}
