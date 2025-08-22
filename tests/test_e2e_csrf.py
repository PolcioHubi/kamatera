def test_form_post_requires_csrf(csrf_enabled_client):
    # Try posting to a CSRF-protected endpoint (e.g., /admin/api/announcements)
    resp = csrf_enabled_client.post('/admin/api/announcements', json={'title': 't', 'message': 'm', 'type': 'info'})
    # Expect 400 with specific message configured in app for missing CSRF token
    assert resp.status_code in (400, 403)
    assert b"The CSRF token is missing." in resp.data

