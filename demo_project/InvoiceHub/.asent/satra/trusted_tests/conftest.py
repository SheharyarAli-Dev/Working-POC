from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from app.main import create_app

@pytest.fixture(scope="module")
def case(tmp_path_factory):
    tmp_path=tmp_path_factory.mktemp("invoice")
    client=TestClient(create_app(tmp_path,seed=True))
    def login(name):
        r=client.post('/auth/login',json={'username':name,'password':'demo-password'})
        assert r.status_code==200
        return {'Authorization':'Bearer '+r.json()['access_token']}
    alice,bob,admin=login('alice'),login('bob'),login('admin')
    pdf=(Path(__file__).resolve().parents[1]/'fixtures'/'invoice.pdf').read_bytes()
    r=client.post('/invoices',headers=alice,files={'file':('invoice.pdf',pdf,'application/pdf')})
    assert r.status_code==201,r.text
    return client,alice,bob,admin,r.json()['id']
