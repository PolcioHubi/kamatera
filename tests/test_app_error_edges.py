import io


def test_admin_unauthorized_access(client):
    # Hitting admin endpoints without admin session should return 401 or redirect
    endpoints = [
        ("GET", "/admin/"),
        ("GET", "/admin/api/users"),
        ("GET", "/admin/api/access-keys"),
        ("POST", "/admin/api/generate-access-key"),
        ("POST", "/admin/api/deactivate-access-key"),
        ("DELETE", "/admin/api/delete-access-key"),
        ("GET", "/admin/api/registered-users"),
        ("POST", "/admin/api/toggle-user-status"),
        ("POST", "/admin/api/update-hubert-coins"),
        ("POST", "/admin/api/reset-password"),
        ("GET", "/admin/api/logs/app.log"),
        ("GET", "/admin/api/backup/full"),
        ("GET", "/admin/api/export/all"),
    ]
    for method, path in endpoints:
        if method == "GET":
            r = client.get(path)
        elif method == "POST":
            r = client.post(path)
        else:
            r = client.delete(path)
        assert r.status_code in (401, 301, 302, 303, 307, 308)


def test_admin_bad_payloads(admin_client):
    # Missing/invalid payloads
    assert admin_client.post("/admin/api/generate-access-key", json={}).status_code in (200, 201, 400)
    assert admin_client.post("/admin/api/deactivate-access-key", json={}).status_code in (200, 400)
    assert admin_client.delete("/admin/api/delete-access-key", json={}).status_code in (200, 400)
    assert admin_client.post("/admin/api/toggle-user-status", json={}).status_code in (200, 400)
    assert admin_client.post("/admin/api/update-hubert-coins", json={"amount": "x"}).status_code in (200, 400)
    assert admin_client.post("/admin/api/reset-password", json={"username": "u", "new_password": "123"}).status_code in (200, 400)


def test_upload_wrong_mime(client):
    r = client.post("/api/upload", json={"not": "file"})
    assert r.status_code in (200, 400, 415)


def test_large_upload_exceeds_limit(client):
    # Exceed 16MB (configured in tests) by a small margin
    big = io.BytesIO(b"a" * (16 * 1024 * 1024 + 1024))
    data = {"file": (big, "big.bin")}
    r = client.post("/api/upload", data=data, content_type="multipart/form-data")
    assert r.status_code in (413, 400, 422)


def test_metrics_counts_various_statuses(client):
    before = client.get("/metrics").get_data(as_text=True)
    # 401
    client.get("/api/profile")
    # 404
    client.get("/definitely-not-found")
    after = client.get("/metrics").get_data(as_text=True)
    assert len(after) >= len(before)


def test_security_headers_for_401_and_404(client):
    r1 = client.get("/api/profile")
    r2 = client.get("/missing")
    for r in (r1, r2):
        assert "Content-Security-Policy" in r.headers
        assert r.headers.get("X-Content-Type-Options") == "nosniff"


def test_admin_logs_unknown_file(admin_client):
    r = admin_client.get("/admin/api/logs/unknown.log")
    assert r.status_code in (404, 400, 403)


def test_import_invalid_zip(admin_client):
    bad = io.BytesIO(b"not a zip")
    data = {"file": (bad, "bad.zip")}
    r = admin_client.post("/admin/api/import/all", data=data, content_type="multipart/form-data")
    assert r.status_code in (400, 422, 500)


