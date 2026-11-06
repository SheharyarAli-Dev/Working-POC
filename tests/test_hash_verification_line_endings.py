import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from backend.cavr import sandbox
from backend.satra import pytest_runner


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_cavr_pinned_python_source_accepts_windows_crlf_checkout(monkeypatch, tmp_path):
    from backend.config import ROOT

    source = ROOT / 'scenarios/cavr_controlled/invoice_pdf_lab.py'
    crlf_source = tmp_path / 'invoice_pdf_lab.py'
    crlf_source.write_bytes(source.read_bytes().replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
    assert _sha(crlf_source.read_bytes()) not in json.loads(
        (ROOT / 'scenarios/laboratory_hashes.json').read_text()
    )['cavr_sources']
    assert sandbox._lf_digest(crlf_source.read_bytes()) in json.loads(
        (ROOT / 'scenarios/laboratory_hashes.json').read_text()
    )['cavr_sources']

    monkeypatch.setattr(sandbox, 'availability', lambda: {
        'docker': {'available': False}, 'podman': {'available': False},
        'strace': {'available': False, 'reason': 'not installed'},
    })
    monkeypatch.setattr(sandbox.subprocess, 'run', lambda *a, **k: SimpleNamespace(
        returncode=0, stdout='{"audit_events": []}\n', stderr=''
    ))
    result = sandbox.run_counterfactual(
        crlf_source, ROOT / 'demo_project/InvoiceHub/fixtures/invoice.pdf',
        tmp_path / 'out', lambda *a: None,
    )
    assert result['available'] is True
    assert result['execution_mode'] == 'PINNED_INERT_LAB_PYTHON_AUDIT'


def test_satra_pinned_python_source_normalizes_but_other_assets_stay_byte_exact(monkeypatch, tmp_path):
    reference_root = tmp_path / 'reference'
    candidate_root = tmp_path / 'candidate'
    (reference_root / 'demo_project/InvoiceHub/fixtures').mkdir(parents=True)
    (reference_root / 'scenarios').mkdir()
    (candidate_root / 'fixtures').mkdir(parents=True)
    source = b'from app import main\n'
    (candidate_root / 'test_app.py').write_bytes(source.replace(b'\n', b'\r\n'))
    (reference_root / 'demo_project/InvoiceHub/pytest.ini').write_bytes(b'[pytest]\n')
    pdf = b'%PDF-1.4\nfixture-bytes\n'
    (reference_root / 'demo_project/InvoiceHub/fixtures/invoice.pdf').write_bytes(pdf)
    (candidate_root / 'pytest.ini').write_bytes(b'[pytest]\n')
    (candidate_root / 'fixtures/invoice.pdf').write_bytes(pdf)
    (reference_root / 'scenarios/laboratory_hashes.json').write_text(json.dumps({
        'python_sources': [_sha(source)],
    }))
    monkeypatch.setattr(pytest_runner, 'ROOT', reference_root)

    assert pytest_runner.permitted_builtin(candidate_root)
    (candidate_root / 'test_app.py').write_bytes(b'changed source\r\n')
    assert not pytest_runner.permitted_builtin(candidate_root)
    (candidate_root / 'test_app.py').write_bytes(source.replace(b'\n', b'\r\n'))
    (candidate_root / 'pytest.ini').write_bytes(b'[pytest]\r\n')
    assert not pytest_runner.permitted_builtin(candidate_root)
    (candidate_root / 'pytest.ini').write_bytes(b'[pytest]\n')
    (candidate_root / 'fixtures/invoice.pdf').write_bytes(pdf.replace(b'\n', b'\r\n'))
    assert not pytest_runner.permitted_builtin(candidate_root)
