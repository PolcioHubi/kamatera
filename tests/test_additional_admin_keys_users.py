import pytest
from flask import url_for


def test_admin_access_keys_crud_flow(admin_client):
    # Generate
    resp = admin_client.post(url_for('api_generate_access_key'), json={
        'description': 'cov key',
        'validity_days': 1,
    })
    assert resp.status_code == 200
    key = resp.get_json()['access_key']
    assert isinstance(key, str) and len(key) > 10

    # List
    resp = admin_client.get(url_for('api_get_access_keys'))
    assert resp.status_code == 200
    keys = resp.get_json()['access_keys']
    assert any(k['key'] == key for k in keys)

    # Deactivate
    resp = admin_client.post(url_for('api_deactivate_access_key'), json={'access_key': key})
    assert resp.status_code == 200
    assert resp.get_json()['success'] is True

    # Delete
    resp = admin_client.delete(url_for('api_delete_access_key'), json={'access_key': key})
    assert resp.status_code == 200
    assert resp.get_json()['success'] is True


def test_admin_registered_users_listing(admin_client, auth_manager, access_key_service):
    # Seed one user
    key = access_key_service.generate_access_key('list_user')
    auth_manager.register_user('list_user_cov', 'password123', key)

    resp = admin_client.get(url_for('api_get_registered_users'))
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    users = data['users']
    assert any(u['username'] == 'list_user_cov' for u in users)
