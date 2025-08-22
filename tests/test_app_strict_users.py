def test_users_crud_strict(client):
    # create (contract: name, email, age)
    cr = client.post(
        "/api/users",
        json={"name": "User 701", "email": "u701@example.com", "age": 25},
    )
    assert cr.status_code in (200, 201)
    new_id = (cr.get_json() or {}).get("id", 701)
    # get
    ge = client.get(f"/api/users/{new_id}")
    assert ge.status_code == 200
    assert ge.is_json
    # patch (contract: name/email/age)
    pa = client.patch(f"/api/users/{new_id}", json={"name": "User 701X"})
    assert pa.status_code in (200, 204)
    # delete
    de = client.delete(f"/api/users/{new_id}")
    assert de.status_code in (200, 204)
    # now not found
    nf = client.get(f"/api/users/{new_id}")
    assert nf.status_code == 404

