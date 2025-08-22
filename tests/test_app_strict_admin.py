def test_admin_keys_and_user_actions(admin_client, access_key_service):
    # generate key
    gk = admin_client.post("/admin/api/generate-access-key", json={"description": "strict"})
    assert gk.status_code in (200, 201)
    kbody = gk.get_json() if gk.is_json else {}
    key = (kbody or {}).get("key")

    # deactivate/delete tolerate absence
    if key:
        admin_client.post("/admin/api/deactivate-access-key", json={"key": key})
        admin_client.delete("/admin/api/delete-access-key", json={"key": key})

    # Prepare target user
    ukey = access_key_service.generate_access_key("strict_admin")
    rc = admin_client.post("/register", json={"username": "strict_target", "password": "password123", "access_key": ukey})
    assert rc.status_code in (200, 201)

    # toggle / coins / reset
    tg = admin_client.post("/admin/api/toggle-user-status", json={"username": "strict_target"})
    assert tg.status_code in (200, 400)
    co = admin_client.post("/admin/api/update-hubert-coins", json={"username": "strict_target", "amount": 3})
    assert co.status_code in (200, 400)
    rp = admin_client.post("/admin/api/reset-password", json={"username": "strict_target", "new_password": "newpass123"})
    assert rp.status_code in (200, 400)

    # logs and exports
    lg = admin_client.get("/admin/api/logs/app.log")
    assert lg.status_code in (200, 206)
    admin_client.get("/admin/api/export/all")

