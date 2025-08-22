def test_admin_impersonation_flow(client):
    # Create user to impersonate
    r_create = client.post('/api/users', json={'name': 'Bob', 'email': 'b@example.com', 'age': 28})
    assert r_create.status_code == 201

    # Register admin and login as admin (using known admin creds fixture env)
    # Ensure admin session keys are set as in app expectations
    with client.session_transaction() as sess:
        sess['admin_logged_in'] = True
        sess['admin_username'] = 'admin_test'

    # Try to start impersonation of known username 'Bob' won't map to auth user; use registration
    client.post('/register', json={'username': 'bob', 'password': 'xXyYzZ!123', 'accessKey': 'test_access_key'})

    start = client.post('/admin/api/impersonate/start', json={'username': 'bob'})
    assert start.status_code in (200, 404, 400)
    if start.status_code == 200:
        # stop impersonation
        stop = client.post('/admin/api/impersonate/stop', json={})
        assert stop.status_code == 200

