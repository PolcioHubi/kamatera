import types
import sys
import pytest

from models import db, User


def test_register_user_import_flask_exception_triggers_nonprod_path(auth_manager, monkeypatch):
    # Prepare: ensure no user exists with this name
    username = "user_import_exc"
    User.query.filter_by(username=username).delete()
    db.session.commit()

    # Monkeypatch sys.modules['flask'] to a dummy without current_app to cause ImportError
    dummy = types.ModuleType("flask")
    if "flask" in sys.modules:
        original_flask = sys.modules["flask"]
    else:
        original_flask = None
    sys.modules["flask"] = dummy

    try:
        ok, msg, rec_token = auth_manager.register_user(
            username=username,
            password="password123",
            access_key="test_access_key",
            mark_tutorial_seen=True,
        )
        assert ok is True
        assert isinstance(rec_token, str) and len(rec_token) > 0
        # Verify access_key_used recorded with username suffix in non-prod shared-key mode
        user = User.query.filter_by(username=username).first()
        assert user is not None
        assert user.access_key_used.startswith("test_access_key:")
    finally:
        # Restore original flask module
        if original_flask is not None:
            sys.modules["flask"] = original_flask
        else:
            del sys.modules["flask"]


def test_toggle_user_status_nonexistent_returns_false(auth_manager):
    assert auth_manager.toggle_user_status("does_not_exist") is False


def test_update_hubert_coins_nonexistent_user(auth_manager):
    ok, msg = auth_manager.update_hubert_coins("ghost_user", 1)
    assert ok is False and "nie został znaleziony" in msg.lower()


def test_generate_password_reset_token_nonexistent_user(auth_manager):
    assert auth_manager.generate_password_reset_token("nope") is None


def test_reset_user_password_with_token_length_check(auth_manager, access_key_service):
    # Create a user and generate token
    key = access_key_service.generate_access_key("for_token_test")
    ok, _, _ = auth_manager.register_user("token_user", "password123", key)
    assert ok is True
    token = auth_manager.generate_password_reset_token("token_user")
    assert token is not None

    # Too short password should trigger length branch
    ok, msg = auth_manager.reset_user_password_with_token(token, "123")
    assert ok is False and "6 do 100" in msg


def test_reset_password_with_recovery_token_length_and_not_found(auth_manager, access_key_service):
    # Register user and fetch recovery_token by reading user row
    key = access_key_service.generate_access_key("for_recovery")
    ok, _, _ = auth_manager.register_user("recovery_user", "password123", key)
    assert ok is True
    user = User.query.filter_by(username="recovery_user").first()
    assert user is not None and user.recovery_token

    # Length too short branch
    ok, msg = auth_manager.reset_password_with_recovery_token("recovery_user", user.recovery_token, "123")
    assert ok is False and "6 do 100" in msg

    # Not found branch (wrong token)
    ok, msg = auth_manager.reset_password_with_recovery_token("recovery_user", "WRONGTOKEN", "password123")
    assert ok is False and ("nieprawidłowa" in msg.lower() or "invalid" in msg.lower())


