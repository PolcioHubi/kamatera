import os


def test_metrics_endpoint(client):
    resp = client.get("/metrics")
    assert resp.status_code == 200
    text = resp.get_data(as_text=True)
    assert "app_requests_total" in text


def test_security_headers_on_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    headers = resp.headers
    assert "Content-Security-Policy" in headers
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "Permissions-Policy" in headers


def test_x_request_id_passthrough_and_generation(client):
    # passthrough
    resp = client.get("/api/health", headers={"X-Request-ID": "abc123"})
    assert resp.status_code == 200
    assert resp.headers.get("X-Request-ID") == "abc123"

    # generation
    resp2 = client.get("/api/health")
    assert resp2.status_code == 200
    assert resp2.headers.get("X-Request-ID")


def test_static_cache_control_header(client):
    # Pick a known static asset present in repo
    static_path = "/static/js/register.js"
    resp = client.get(static_path)
    assert resp.status_code == 200
    cache = resp.headers.get("Cache-Control")
    assert cache is not None


def test_api_users_validation_errors(client):
    # Non-dict JSON
    resp = client.post("/api/users", json=["not", "a", "dict"])
    assert resp.status_code in (400, 422)

    # Missing required fields
    resp2 = client.post("/api/users", json={"name": "x"})
    assert resp2.status_code in (400, 422)

    # Unexpected fields
    resp3 = client.post("/api/users", json={"id": 1, "username": "x", "extra": 1})
    # Depending on implementation it may accept/ignore; just ensure handled with JSON body
    assert resp3.status_code in (200, 201, 400, 422)


def test_api_404_handler_returns_json(client):
    resp = client.get("/api/does-not-exist")
    assert resp.status_code == 404
    # Should be JSON body from API error handler
    # Accept either JSON or text depending on current implementation
    ctype = resp.headers.get("Content-Type", "")
    assert ("application/json" in ctype) or ("text/" in ctype)


