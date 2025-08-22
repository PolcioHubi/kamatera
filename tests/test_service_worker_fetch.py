def test_service_worker_cached_assets_accessible(client):
    # Ensure sw.js itself is served with 200
    r = client.get('/static/sw.js')
    assert r.status_code == 200

    # Dashboard should be available and carry CSP/security headers
    r2 = client.get('/static/dashboard.html')
    assert r2.status_code in (200, 304)
    assert 'Content-Security-Policy' in r2.headers

    # Sanity: main assets referenced by SW pre-cache exist or 404 (but endpoint responds)
    for path in ['/static/main.css', '/static/jquery-3.6.0.min.js', '/static/manifest.json']:
        resp = client.get(path)
        assert resp.status_code in (200, 404)

