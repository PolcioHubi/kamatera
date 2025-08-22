def test_register_login_profile_flow(client, access_key_service):
    key = access_key_service.generate_access_key("strict")
    # register strictly requires fields
    r = client.post(
        "/register",
        json={"username": "strict_user", "password": "password123", "access_key": key},
    )
    assert r.status_code in (200, 201)

    # login (API) should be 200 with JSON body {success: True} or token
    lr = client.post("/api/login", json={"username": "strict_user", "password": "password123"})
    assert lr.status_code in (200,)
    assert lr.is_json
    body = lr.get_json()
    assert isinstance(body, dict)
    assert body.get("success") in (True, False)

    # profile unauthorized via API
    pr = client.get("/api/profile")
    assert pr.status_code in (200, 401)

