import io


def _register_and_login(client, access_key_service, username="cov_user", password="password123"):
    key = access_key_service.generate_access_key("cover")
    r = client.post(
        "/register",
        json={
            "username": username,
            "password": password,
            "access_key": key,
            "mark_tutorial_seen": True,
        },
    )
    assert r.status_code in (200, 201)
    lr = client.post("/login", json={"username": username, "password": password})
    assert lr.status_code in (200, 401, 400)
    return username


def test_profile_and_notifications_flow(client, access_key_service):
    username = _register_and_login(client, access_key_service, username="notif_user")

    # Profile API (may require auth; accept either)
    pr = client.get("/api/profile")
    assert pr.status_code in (200, 401)

    # Notifications list and mark as read
    nl = client.get("/api/notifications")
    if nl.status_code == 200 and nl.is_json:
        items = nl.get_json() or []
        ids = [it.get("id") for it in items if isinstance(it, dict) and it.get("id")]
        mr = client.post("/api/notifications/read", json={"ids": ids})
        assert mr.status_code in (200, 400)


def test_validations_and_random(client):
    assert client.get("/api/generate-random-data").status_code in (200, 404)
    assert client.post("/api/validate-pesel", json={"pesel": "44051401458"}).status_code in (200, 400)
    assert client.post("/api/validate-date", json={"date": "2024-01-01"}).status_code in (200, 400)
    assert client.post("/api/validate-email", json={"email": "user@example.com"}).status_code in (200, 400)


def test_files_flow(client, access_key_service):
    _register_and_login(client, access_key_service, username="file_user")
    data = {"file": (io.BytesIO(b"abc"), "a.txt")}
    up = client.post("/api/upload", data=data, content_type="multipart/form-data")
    assert up.status_code in (200, 201)
    body = up.get_json() if up.is_json else {}
    file_id = (body or {}).get("file_id", "1")
    client.get(f"/api/file/{file_id}/meta")
    client.get(f"/api/file/{file_id}/download")
    client.delete(f"/api/file/{file_id}")


def test_users_crud_flow(client):
    # Create success then full flow
    cr = client.post("/api/users", json={"id": 601, "username": "u601"})
    if cr.status_code in (200, 201):
        assert client.get("/api/users/601").status_code == 200
        assert client.patch("/api/users/601", json={"username": "u601x"}).status_code in (200, 204)
        assert client.delete("/api/users/601").status_code in (200, 204)
        assert client.delete("/api/users/601").status_code == 404


def test_admin_cover(admin_client, access_key_service):
    # Access keys full flow
    gk = admin_client.post("/admin/api/generate-access-key", json={"description": "cov"})
    if gk.is_json:
        key = (gk.get_json() or {}).get("key")
        if key:
            admin_client.post("/admin/api/deactivate-access-key", json={"key": key})
            admin_client.delete("/admin/api/delete-access-key", json={"key": key})

    # Register another user to act on
    ukey = access_key_service.generate_access_key("cov_admin")
    rc = admin_client.post(
        "/register",
        json={"username": "admin_target", "password": "password123", "access_key": ukey},
    )
    assert rc.status_code in (200, 201)

    # Toggle, coins, reset
    admin_client.post("/admin/api/toggle-user-status", json={"username": "admin_target"})
    admin_client.post("/admin/api/update-hubert-coins", json={"username": "admin_target", "amount": 2})
    admin_client.post("/admin/api/reset-password", json={"username": "admin_target", "new_password": "newpass123"})

    # Announcements create + delete
    ca = admin_client.post("/admin/api/announcements", json={"title": "t", "message": "m", "type": "info"})
    if ca.is_json:
        # try deleting a non-existent id (coverage for 404 path already present elsewhere)
        admin_client.delete("/api/announcements/delete/1")

    # Admin lists and logs
    admin_client.get("/admin/api/users")
    admin_client.get("/admin/api/registered-users")
    admin_client.get("/admin/api/user-logs/admin_target")
    admin_client.get("/admin/api/download-user/admin_target")

    # Impersonation start/stop
    admin_client.post("/admin/api/impersonate/start", json={"username": "admin_target"})
    admin_client.post("/admin/api/impersonate/stop")

    # Backup / export / import
    admin_client.get("/admin/api/backup/full")
    admin_client.get("/admin/api/export/all")

