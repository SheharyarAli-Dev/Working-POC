def test_owner_can_read(case):
    c,a,b,admin,i=case
    response=c.get(f'/invoices/{i}',headers=a)
    assert response.status_code==200
    assert 'Invoice' in response.json()['text']

def test_admin_view(case):
    c,a,b,admin,i=case
    assert c.get(f'/invoices/{i}',headers=admin).status_code==200

def test_registration_login(case):
    c,*_=case
    body={'username':'charlie','password':'strong-password'}
    assert c.post('/auth/register',json=body).status_code==201
    assert c.post('/auth/login',json=body).status_code==200


import sqlite3
import time
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import create_app


def test_archive_boundary_and_ownership(tmp_path):
    with TestClient(create_app(tmp_path,seed=True)) as c:
        def token(name):return {'Authorization':'Bearer '+c.post('/auth/login',json={'username':name,'password':'demo-password'}).json()['access_token']}
        alice,bob,admin=token('alice'),token('bob'),token('admin')
        pdf=(Path(__file__).resolve().parents[1]/'fixtures/invoice.pdf').read_bytes()
        old=c.post('/invoices',headers=alice,files={'file':('old.pdf',pdf)}).json()['id']
        recent=c.post('/invoices',headers=alice,files={'file':('new.pdf',pdf)}).json()['id']
        with sqlite3.connect(tmp_path/'invoicehub.sqlite3') as db:
            db.execute('UPDATE invoices SET created=? WHERE id=?',(time.time()-91*86400,old))
        assert c.post('/admin/archive',headers=alice).status_code==403
        assert c.post('/admin/archive').status_code==401
        assert c.post('/admin/archive',headers=admin).json()['archived']==1
        assert c.get(f'/invoices/{old}',headers=alice).json()['archived']==1
        assert c.get(f'/invoices/{recent}',headers=alice).json()['archived']==0
        assert c.get(f'/invoices/{old}',headers=bob).status_code==403
        assert c.post('/admin/archive',headers=admin).json()['archived']==0
        assert len(list((tmp_path/'s3-local/invoice-archive').glob('*.pdf')))==1
        assert c.delete(f'/invoices/{old}',headers=alice).status_code==200
        assert list((tmp_path/'s3-local/invoice-archive').glob('*.pdf'))==[]
