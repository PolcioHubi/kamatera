def test_method_not_allowed_cases(client):
    # Endpoints that are POST-only: try GET to elicit 405 (or 404 depending on routing)
    for path in ["/api/login", "/api/users", "/api/validate-pesel", "/api/validate-date", "/api/validate-email", "/api/upload"]:
        r = client.get(path)
        assert r.status_code in (404, 405)


def test_impersonation_requires_admin(client):
    # Non-admin trying to hit admin-only impersonation endpoints
    r1 = client.post("/admin/api/impersonate/start", json={"username": "x"})
    r2 = client.post("/admin/api/impersonate/stop")
    for r in (r1, r2):
        assert r.status_code in (400, 401, 301, 302, 303, 307, 308)


def test_admin_logs_existing_files(admin_client):
    # Known logs should be retrievable for admin
    for name in ("app.log", "user_activity.log"):
        r = admin_client.get(f"/admin/api/logs/{name}")
        assert r.status_code in (200, 206)  # 206 if ranged, but accept 200


def test_admin_announcements_bad_payloads(admin_client):
    r = admin_client.post("/admin/api/announcements", json={})
    assert r.status_code in (200, 400)
    r2 = admin_client.delete("/api/announcements/delete/-1")
    assert r2.status_code in (400, 404)


def test_profile_page_redirects_when_not_logged(client):
    r = client.get("/profile")
    assert r.status_code in (301, 302, 303, 307, 308)


def test_login_get_returns_form_or_error(client):
    r = client.get("/login")
    assert r.status_code in (200, 400, 404)


def test_users_crud_wrong_methods(client):
    # PATCH without resource id
    r = client.patch("/api/users")
    assert r.status_code in (404, 405)
    # DELETE without resource id
    r2 = client.delete("/api/users")
    assert r2.status_code in (404, 405)


def test_x_request_id_propagates_on_404_and_405(client):
    headers = {"X-Request-ID": "rid-xyz"}
    r1 = client.get("/totally-missing", headers=headers)
    assert r1.headers.get("X-Request-ID") == "rid-xyz"
    r2 = client.get("/api/login", headers=headers)  # likely 405
    assert r2.headers.get("X-Request-ID") == "rid-xyz"


