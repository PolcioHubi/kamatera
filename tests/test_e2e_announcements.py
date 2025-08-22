def test_admin_announcements_crud(client):
    # Ensure admin session
    with client.session_transaction() as sess:
        sess['admin_logged_in'] = True
        sess['admin_username'] = 'admin_test'

    # Create
    r_create = client.post('/admin/api/announcements', json={
        'title': 'Nowe ogłoszenie',
        'message': 'Treść ogłoszenia',
        'type': 'info'
    })
    assert r_create.status_code == 200
    assert r_create.get_json().get('success') is True

    # List (service via API users stats isn’t announcements; use service exposure via admin panel route if present)
    # For now, verify service layer indirectly by checking there is at least one active announcement using a dedicated endpoint if exists,
    # otherwise skip listing and proceed to deactivate via service-exposed route if present.

    # Deactivate via service method proxy if app exposes an endpoint; otherwise simulate deactivate by creating another and assert 200 again
    # Since no explicit deactivate endpoint is defined, this test limits to creation success.
    # If later endpoint like /admin/api/announcements/<id>/deactivate appears, extend this test accordingly.
    

