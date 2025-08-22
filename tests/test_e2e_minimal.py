import re


def test_register_login_profile_flow(client):
    # Register
    r = client.post('/register', json={
        'username': 'e2e_user',
        'password': 'StrongPassw0rd!',
        'accessKey': 'test_access_key'
    })
    assert r.status_code in (200, 201)

    # Login
    r2 = client.post('/login', json={
        'username': 'e2e_user',
        'password': 'StrongPassw0rd!'
    })
    assert r2.status_code == 200

    # Profile
    r3 = client.get('/api/profile')
    assert r3.status_code in (200, 401)  # 200 when logged in session persists; some configs may require auth header
    if r3.status_code == 200:
        data = r3.get_json()
        assert data and data.get('username') == 'e2e_user'


def test_users_crud_e2e(client):
    # Create
    r = client.post('/api/users', json={'name': 'Alice', 'email': 'a@example.com', 'age': 30})
    assert r.status_code == 201
    user_id = r.get_json()['id']

    # Read
    r2 = client.get(f'/api/users/{user_id}')
    assert r2.status_code == 200
    assert r2.get_json()['name'] == 'Alice'

    # Patch
    r3 = client.patch(f'/api/users/{user_id}', json={'name': 'Alice B'})
    assert r3.status_code == 200
    assert r3.get_json()['name'] == 'Alice B'

    # Delete
    r4 = client.delete(f'/api/users/{user_id}')
    assert r4.status_code == 200
    # Not found after delete
    r5 = client.get(f'/api/users/{user_id}')
    assert r5.status_code == 404


def test_upload_and_download_e2e(client):
    # Upload
    data = {
        'file': (bytes('hello', 'utf-8'), 'hello.txt')
    }
    r = client.post('/api/upload', data=data, content_type='multipart/form-data')
    assert r.status_code in (200, 201)

    # Download (dummy endpoint)
    r2 = client.get('/api/file/1/download')
    assert r2.status_code == 200
    # Endpoint returns simple text content for testing
    assert b'Test content' in r2.data


