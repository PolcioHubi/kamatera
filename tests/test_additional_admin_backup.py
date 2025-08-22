import io
import os
import zipfile
from pathlib import Path

import pytest
from flask import url_for


def test_admin_api_users_ok(admin_client):
    resp = admin_client.get(url_for('api_get_users'))
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert "users_data" in data and "stats" in data


def test_admin_create_announcement_ok(admin_client):
    payload = {
        "title": "Nowe ogłoszenie",
        "message": "Treść",
        "type": "info",
    }
    resp = admin_client.post(url_for('api_create_announcement'), json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True


def test_admin_update_hubert_coins_ok(admin_client, auth_manager, access_key_service):
    key = access_key_service.generate_access_key("coins_key")
    username = "coins_user"
    auth_manager.register_user(username, "password123", key)

    resp = admin_client.post(url_for('api_update_hubert_coins'), json={
        "username": username,
        "amount": 3,
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True

    # Verify via user info
    info = auth_manager.get_user_info(username)
    assert info is not None and info["hubert_coins"] >= 3


def test_admin_reset_password_ok(admin_client, auth_manager, access_key_service):
    key = access_key_service.generate_access_key("reset_key")
    username = "reset_user"
    old_password = "password123"
    new_password = "newpass1234"
    auth_manager.register_user(username, old_password, key)

    resp = admin_client.post(url_for('api_reset_user_password'), json={
        "username": username,
        "new_password": new_password,
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True

    ok, _, _ = auth_manager.authenticate_user(username, new_password)
    assert ok is True


def test_admin_export_all_data_ok(admin_client):
    resp = admin_client.get(url_for('export_all_data'))
    assert resp.status_code == 200
    # Content type may vary; ensure a file is returned
    disp = resp.headers.get('Content-Disposition', '')
    assert 'attachment' in disp and '.zip' in disp


def test_admin_import_all_data_ok(admin_client, app):
    # Build an in-memory zip with required structure
    mem_zip = io.BytesIO()
    with zipfile.ZipFile(mem_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('user_data/dummy.txt', 'x')
        zf.writestr('auth_data/dummy.db', 'y')
    mem_zip.seek(0)

    data = {
        'backupFile': (mem_zip, 'backup.zip')
    }
    resp = admin_client.post(url_for('import_all_data'), data=data, content_type='multipart/form-data')

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["success"] is True

    # Verify directories exist after import
    assert Path('user_data').exists()
    assert Path('auth_data').exists()

    # Some import paths in app may dispose the engine; ensure tables exist for subsequent tests
    from models import db
    with app.app_context():
        db.create_all()


def test_serve_user_file_forbidden(logged_in_client, registered_user, auth_manager, access_key_service):
    # Create another user and a file under their directory
    other_username = "file_owner"
    auth_manager.register_user(other_username, "pass12345", access_key_service.generate_access_key("fk"))

    base = Path('user_data') / other_username / 'files'
    base.mkdir(parents=True, exist_ok=True)
    (base / 'test.txt').write_text('secret')

    # Logged in as registered_user, try to access other user's file
    resp = logged_in_client.get(f"/user_files/{other_username}/test.txt")
    assert resp.status_code == 403


def test_notifications_flow(logged_in_client, registered_user):
    # Get notifications
    resp = logged_in_client.get(url_for('get_notifications'))
    assert resp.status_code == 200
    notes = resp.get_json()
    assert isinstance(notes, list) and len(notes) >= 1

    note_id = notes[0]["id"]
    resp2 = logged_in_client.post(url_for('mark_notification_as_read'), json={"id": note_id})
    assert resp2.status_code == 200
    data = resp2.get_json()
    assert data["success"] is True


def test_log_rotation_truncates_when_over_limit(client, monkeypatch):
    # Force log maintenance to run and truncate logs
    monkeypatch.setenv('APP_ENV_MODE', 'development')
    import app as app_module
    app_module.MAX_LOG_DIR_SIZE_MB = 0

    logs_dir = Path('logs')
    logs_dir.mkdir(exist_ok=True)
    app_log = logs_dir / 'app.log'
    activity_log = logs_dir / 'user_activity.log'
    app_log.write_text('x' * 10_000)
    activity_log.write_text('x' * 10_000)

    # Ensure the time gate passes by removing last_check file
    last_check = logs_dir / '.last_log_check'
    if last_check.exists():
        last_check.unlink()

    # Trigger before_request by hitting any route
    resp = client.get(url_for('health_check'))
    assert resp.status_code == 200

    # Files should be significantly reduced in size (may not be exactly 0 if loggers append)
    assert app_log.exists() and app_log.stat().st_size < 10_000
    assert activity_log.exists() and activity_log.stat().st_size < 10_000
