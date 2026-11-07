def test_nonowner_denied(case):
    c,a,b,admin,i=case
    before=c.get('/invoices',headers=a).json()
    response=c.get(f'/invoices/{i}',headers=b)
    assert response.status_code==403
    assert c.get('/invoices',headers=a).json()==before

def test_unauthenticated_denied(case):
    c,a,b,admin,i=case
    assert c.get(f'/invoices/{i}').status_code==401

def test_normal_user_not_admin(case):
    c,a,b,admin,i=case
    assert c.get('/admin/invoices',headers=a).status_code==403

def test_nonowner_cannot_delete(case):
    c,a,b,admin,i=case
    assert c.delete(f'/invoices/{i}',headers=b).status_code==403
    assert c.get(f'/invoices/{i}',headers=a).status_code==200

def test_reject_non_pdf(case):
    c,a,b,admin,i=case
    assert c.post('/invoices',headers=a,files={'file':('../bad.txt',b'not PDF')}).status_code==415

def test_sql_login_payload(case):
    c,*_=case
    assert c.post('/auth/login',json={'username':"admin' OR 1=1 --",'password':'demo-password'}).status_code in (401,422)
