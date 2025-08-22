def test_api_health_is_ok_json(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.is_json
    body = r.get_json()
    assert isinstance(body, dict)
    assert body.get("status") == "ok"


def test_metrics_text_plain_and_has_counters(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert r.headers.get("Content-Type", "").startswith("text/plain")
    text = r.get_data(as_text=True)
    assert "app_requests_total" in text


def test_security_headers_on_ok_and_404(client):
    ok = client.get("/api/health")
    notfound = client.get("/never-exists")
    for r in (ok, notfound):
        assert "Content-Security-Policy" in r.headers
        assert r.headers.get("X-Frame-Options") == "DENY"
        assert r.headers.get("X-Content-Type-Options") == "nosniff"
        assert r.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

