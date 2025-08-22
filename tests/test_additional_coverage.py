import os
import json
import shutil
from pathlib import Path

import pytest
from flask import url_for

# Note: Using fixtures from tests/conftest.py: app, client, auth_manager, access_key_service


def test_health_endpoint(client):
    resp = client.get(url_for('health_check'))
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['status'] == 'ok'
    assert 'timestamp' in data


def test_forgot_password_flow(client, auth_manager, access_key_service):
    key = access_key_service.generate_access_key("coverage_key")
    username = "cov_user_fp"
    password = "password123"
    ok, _, _ = auth_manager.register_user(username, password, key)
    assert ok

    resp = client.post(url_for('forgot_password'), json={"username": username})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    # In demo app the token is returned in body
    assert isinstance(data.get("token"), str) and len(data["token"]) > 0


def test_reset_password_with_token(client, auth_manager, access_key_service):
    key = access_key_service.generate_access_key("coverage_key_reset")
    username = "cov_user_rpt"
    password = "password123"
    new_password = "newpassword456"
    ok, _, _ = auth_manager.register_user(username, password, key)
    assert ok

    token = auth_manager.generate_password_reset_token(username)
    assert token is not None

    resp = client.post(url_for('reset_password'), json={
        "token": token,
        "new_password": new_password,
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True

    # Verify user can authenticate with the new password
    ok, _, user = auth_manager.authenticate_user(username, new_password)
    assert ok is True and user is not None


def test_recover_password_with_recovery_token(client, auth_manager, access_key_service):
    key = access_key_service.generate_access_key("coverage_key_recover")
    username = "cov_user_recov"
    password = "password123"
    ok, _, recovery_token = auth_manager.register_user(username, password, key)
    assert ok and recovery_token is not None

    resp = client.post(url_for('recover_password'), json={
        "username": username,
        "recovery_token": recovery_token,
        "new_password": "pw7891011",
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True


@pytest.mark.parametrize("payload, expected_status", [
    ({"user_name": "ab"}, 200),  # minimal valid
    ({"user_name": "a"}, 200),   # API returns 200 with error JSON (covered path)
])
def test_set_user_endpoint_creates_dirs(client, payload, expected_status):
    resp = client.post(url_for('set_user'), json=payload)
    assert resp.status_code == expected_status

    user_name = payload["user_name"]
    base = Path("user_data") / user_name
    files_dir = base / "files"
    logs_dir = base / "logs"

    # Only assert directories for valid name length >= 2
    if len(user_name) >= 2:
        assert files_dir.exists() and files_dir.is_dir()
        assert logs_dir.exists() and logs_dir.is_dir()
        # cleanup
        shutil.rmtree(base, ignore_errors=True)


def test_filter_sensitive_data_redaction():
    # Import private function from app for coverage
    from app import _filter_sensitive_data

    raw = {
        "username": "u",
        "password": "secret",
        "nested": {"access_key": "ak"},
        "token": "t",
        "csrf_token": "c",
    }
    filtered = _filter_sensitive_data(raw)
    assert filtered["password"] == "[REDACTED]"
    assert filtered["nested"]["access_key"] == "[REDACTED]"
    assert filtered["token"] == "[REDACTED]"
    assert filtered["csrf_token"] == "[REDACTED]"


def test_admin_login_failure(client, monkeypatch):
    # Set known env for admin creds, then try wrong password
    monkeypatch.setenv("ADMIN_USERNAME", "admin_cov")
    monkeypatch.setenv("ADMIN_PASSWORD", "pass_cov")

    resp = client.post(url_for('admin_login'), json={
        "username": "admin_cov",
        "password": "wrong"
    })
    assert resp.status_code == 401
    data = resp.get_json()
    assert data["success"] is False


def test_static_js_serving(client):
    # File exists under static/js/register.js
    resp = client.get("/static/js/register.js")
    assert resp.status_code == 200
    assert b"function" in resp.data or b"const" in resp.data


def test_generate_random_data_endpoint(client):
    resp = client.get(url_for('api_generate_random_data'))
    assert resp.status_code == 200
    data = resp.get_json()
    # Basic fields presence (subset)
    assert "imie" in data and "nazwisko" in data


def test_check_password_exception_path(auth_manager):
    # Trigger ValueError inside bcrypt by passing an empty hashed string,
    # which is caught in the implementation and returns False.
    result = auth_manager._check_password(hashed_password="", password="abc")
    assert result is False
