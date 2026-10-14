import sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.orchestrator.service import Service
from backend.orchestrator.context_service import ContextService

@pytest.fixture(scope='session',autouse=True)
def cavr_recorded_world(tmp_path_factory):
    # The orchestrator's CAVR analyzer asks PyPI and OSV. Tests are offline: PyPI is the real pypdf
    # 6.19.0 wheel with its recorded registry response, OSV is the recorded answer for that release.
    from backend.cavr import analyzer
    from test_cavr_support import FakeIndex,RECORDED_6_19_0,write_osv_cache
    index=FakeIndex();index.add_pypdf()
    osv=tmp_path_factory.mktemp('cavr-osv');write_osv_cache(osv,'pypdf','6.19.0',RECORDED_6_19_0)
    saved=analyzer.TRANSPORT,analyzer.LIVE_ADVISORIES,analyzer.ADVISORY_CACHE_DIR
    analyzer.TRANSPORT,analyzer.LIVE_ADVISORIES,analyzer.ADVISORY_CACHE_DIR=index,False,osv
    yield
    analyzer.TRANSPORT,analyzer.LIVE_ADVISORIES,analyzer.ADVISORY_CACHE_DIR=saved

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
    svc=Service(tmp_path_factory.mktemp('integration')/'runtime');runs={}
    for name in ('safe','satra_weak','satra_bypass','cross_module'):
        run=svc.create(name);svc.analyze(run.run_id,auto_repair=name=='cross_module');runs[name]=svc.store.run(run.run_id)
    yield svc,runs
    import json
    report={'note':'Actual executions from pytest; historical validation only, never dashboard seed data.','runs':{name:svc.report(run.run_id) for name,run in runs.items()}}
    (Path(__file__).resolve().parents[1]/'reports/scenario-validation.json').write_text(json.dumps(report,indent=2))
