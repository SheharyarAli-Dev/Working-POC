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

# The OSV adapter's committed evidence in advisories/ (captured on a fixed date) is refused once it is older than
# advisory_max_age_days (30). Tests of that adapter evaluate it at a fixed moment: one day after its own
# retrieved_at. The evidence itself and the max-age rule are untouched. (Since PR 1 of docs/cavr-m2-plan.md the
# scenarios no longer read it: their PyPI packages go through `verify_request`, see `_offline_demo_runs`.)
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

# Orchestrator demo / scenario runs judge PyPI packages with `verify_request` (PR 1 of docs/cavr-m2-plan.md). No test
# may reach the real PyPI or OSV through them, so for the whole session `analyzer.DEMO_SETTINGS` serves the recorded
# answers (real pypdf 6.21.4 and 6.19.0 wheels, registry JSON and OSV answers of 2026-11-22). Only the demo's settings
# are replaced: `gate_adapter.SETTINGS` keeps its live default, which the gate tests replace themselves.
@pytest.fixture(scope='session',autouse=True)
def _offline_demo_runs(tmp_path_factory):
    from backend.cavr import analyzer
    from test_cavr_support import recorded_demo_settings
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(analyzer,'DEMO_SETTINGS',recorded_demo_settings(tmp_path_factory.mktemp('demo-settings')))
        yield

# pypdf 6.19.0 is a REJECTED demo case (OSV listed 18 advisories on 2026-11-22). The 0-advisory answer recorded on
# 2026-10-10 is a historical snapshot, and no test may show 6.19.0 VERIFIED, with that snapshot or with any other
# "no advisories" answer. Every package verdict of the pipeline passes through `pipeline._package_verdict`; this
# records each VERIFIED pypdf 6.19.0 and fails the test that produced it (session-time runs fail the first test).
VERIFIED_6_19_0=[]

@pytest.fixture(scope='session',autouse=True)
def _record_verified_6_19_0():
    from packaging.utils import canonicalize_version
    from backend.cavr import pipeline
    original=pipeline._package_verdict
    def recording(decision,status,*args,**kwargs):
        if status=='VERIFIED' and str(decision.get('package','')).lower()=='pypdf' and canonicalize_version(str(decision.get('version')))=='6.19':
            VERIFIED_6_19_0.append(dict(decision))
        return original(decision,status,*args,**kwargs)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(pipeline,'_package_verdict',recording);yield

@pytest.fixture(autouse=True)
def _no_verified_6_19_0():
    yield
    seen=list(VERIFIED_6_19_0);VERIFIED_6_19_0.clear()
    assert not seen,f'pypdf 6.19.0 came out VERIFIED in this test (it is a REJECTED demo case): {seen}'

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
        for name in ('safe','satra_weak','satra_bypass'):
            run=svc.create(name);svc.analyze(run.run_id);runs[name]=svc.store.run(run.run_id)
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
