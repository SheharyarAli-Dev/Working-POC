import json
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.config import ROOT
from backend.orchestrator.service import Service
from backend.orchestrator.context_service import ContextService
import backend.integrations.osv_adapter as osv_adapter

# The scenarios verify pypdf 6.19.0 against advisory evidence committed in advisories/ (captured from
# PyPI on a fixed date). The adapter correctly refuses evidence older than advisory_max_age_days (30),
# so on the real clock these scenarios turn UNRESOLVED once the capture ages. Tests that need the
# committed evidence to be "current" evaluate it at a fixed moment: one day after its own retrieved_at.
# The evidence itself and the max-age rule are untouched.
ADVISORY_EVIDENCE_AGE=timedelta(days=1)

def advisory_clock_time():
    stamps=[datetime.fromisoformat(json.loads(p.read_text())['retrieved_at']) for p in sorted((ROOT/'advisories').glob('*.json'))]
    assert stamps,'no committed advisory evidence in advisories/'
    return max(stamps)+ADVISORY_EVIDENCE_AGE

def frozen_datetime(moment):
    class FrozenDatetime(datetime):
        @classmethod
        def now(cls,tz=None):return moment.astimezone(tz) if tz else moment.replace(tzinfo=None)
    return FrozenDatetime

@contextmanager
def fixed_advisory_clock(moment=None):
    """Freeze the clock seen by the OSV/registry advisory adapter only, for the duration of the block."""
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(osv_adapter,'datetime',frozen_datetime(moment or advisory_clock_time()))
        yield

@pytest.fixture
def advisory_clock():
    with fixed_advisory_clock():yield

@pytest.fixture
def service(tmp_path):return Service(tmp_path/'runtime')

@pytest.fixture
def scenario(service):
    def create(name='safe'):
        run=service.create(name)
        return run,ContextService(run.candidate_workspace,run.baseline_workspace,service.threats.snapshot())
    return create

@pytest.fixture(scope='session')
def integration_runs(tmp_path_factory):
    # Session-scoped: freeze only while the runs are built. Tests that re-analyse request `advisory_clock`.
    # The committed evidence artifact reports/scenario-validation.json is protected: snapshot it and
    # prove at teardown that this session did not touch it.
    artifact=Path(__file__).resolve().parents[1]/'reports'/'scenario-validation.json'
    artifact_before=artifact.read_bytes() if artifact.is_file() else None
    svc=Service(tmp_path_factory.mktemp('integration')/'runtime');runs={}
    with fixed_advisory_clock():
        for name in ('safe','satra_weak','satra_bypass','cross_module'):
            run=svc.create(name);svc.analyze(run.run_id,auto_repair=name=='cross_module');runs[name]=svc.store.run(run.run_id)
    yield svc,runs
    report={'note':'Actual executions from pytest; historical validation only, never dashboard seed data.','runs':{name:svc.report(run.run_id) for name,run in runs.items()}}
    # Write the executed-run report to the pytest session temp directory: ordinary
    # test execution must not rewrite the committed evidence artifact.
    out=tmp_path_factory.mktemp('scenario_validation')/'scenario-validation.json'
    out.write_text(json.dumps(report,indent=2))
    artifact_after=artifact.read_bytes() if artifact.is_file() else None
    assert artifact_after==artifact_before,(
        'tests/conftest.py::integration_runs rewrote the committed evidence artifact '
        'reports/scenario-validation.json; test execution must write only to the pytest temp directory')
