import hashlib
import json
from pathlib import Path

from backend.satra import pytest_runner


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
    monkeypatch.setattr(pytest_runner, 'ASSETS', reference_root)  # permitted_builtin reads its references from config.ASSETS

    assert pytest_runner.permitted_builtin(candidate_root)
    (candidate_root / 'test_app.py').write_bytes(b'changed source\r\n')
    assert not pytest_runner.permitted_builtin(candidate_root)
    (candidate_root / 'test_app.py').write_bytes(source.replace(b'\n', b'\r\n'))
    (candidate_root / 'pytest.ini').write_bytes(b'[pytest]\r\n')
    assert not pytest_runner.permitted_builtin(candidate_root)
    (candidate_root / 'pytest.ini').write_bytes(b'[pytest]\n')
    (candidate_root / 'fixtures/invoice.pdf').write_bytes(pdf.replace(b'\n', b'\r\n'))
    assert not pytest_runner.permitted_builtin(candidate_root)
