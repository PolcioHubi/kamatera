def test_public_validations(client):
    r1 = client.post('/api/validate-email', json={'email': 'test@example.com'})
    assert r1.status_code == 200
    assert r1.get_json().get('valid') is True

    r2 = client.post('/api/validate-date', json={'date': '20.08.2025'})
    assert r2.status_code == 200
    assert r2.get_json().get('valid') is True

    r3 = client.post('/api/validate-pesel', json={'pesel': '44051401458'})
    assert r3.status_code == 200
    assert r3.get_json().get('valid') is True

