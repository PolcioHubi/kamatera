import datetime
from sqlalchemy.exc import IntegrityError
from models import db, User
from user_auth import AuthUser
import sys
import types


def _ensure_user(username: str, password: str = "password123"):
    user = User.query.filter_by(username=username).first()
    if not user:
        user = User(username=username, password=password, is_active=True, has_seen_tutorial=True)
        db.session.add(user)
        db.session.commit()
    return user


def test_authuser_get_id(app):
    _ensure_user("id_user")
    auth_user = db.session.get(AuthUser, "id_user")
    assert auth_user is not None
    assert auth_user.get_id() == "id_user"


def test_hash_and_check_password(auth_manager):
    hashed = auth_manager._hash_password("secret123")
    assert auth_manager._check_password(hashed, "secret123") is True
    assert auth_manager._check_password(hashed, "bad") is False
    # invalid hash triggers ValueError branch
    assert auth_manager._check_password("not-a-valid-hash", "secret123") is False


def test_validate_referral_code(auth_manager):
    _ensure_user("ref_ok")
    assert auth_manager.validate_referral_code("ref_ok") is True
    assert auth_manager.validate_referral_code("ref_missing") is False


def test_register_user_invalid_access_key(auth_manager, monkeypatch):
    monkeypatch.setattr(auth_manager.access_key_service, "validate_access_key", lambda k: (False, "bad"))
    ok, msg, token = auth_manager.register_user("ua1", "password123", "X")
    assert ok is False and token is None


def test_register_user_import_flask_exception_path(auth_manager):
    # Temporarily replace flask module to break `from flask import current_app`
    dummy = types.ModuleType("flask")
    original = sys.modules.get("flask")
    sys.modules["flask"] = dummy
    try:
        ok, msg, token = auth_manager.register_user("ua_import", "password123", "test_access_key")
        assert ok is True and token is not None
    finally:
        if original is not None:
            sys.modules["flask"] = original
        else:
            del sys.modules["flask"]


def test_register_user_username_password_bounds(auth_manager):
    # too short username
    ok, msg, _ = auth_manager.register_user("ab", "password123", "test_access_key")
    assert ok is False and "co najmniej 3" in msg
    # too long username
    ok, msg, _ = auth_manager.register_user("x" * 51, "password123", "test_access_key")
    assert ok is False and "maksymalnie 50" in msg
    # too short password
    ok, msg, _ = auth_manager.register_user("u_short_pwd", "123", "test_access_key")
    assert ok is False and "co najmniej 6" in msg
    # too long password
    ok, msg, _ = auth_manager.register_user("u_long_pwd", "x" * 101, "test_access_key")
    assert ok is False and "maksymalnie 100" in msg


def test_register_user_exists(auth_manager, access_key_service):
    key = access_key_service.generate_access_key("exists")
    ok, _, _ = auth_manager.register_user("exists_user", "password123", key)
    assert ok is True
    # attempt again with same username
    key2 = access_key_service.generate_access_key("exists2")
    ok2, msg, _ = auth_manager.register_user("exists_user", "password123", key2)
    assert ok2 is False and "już istnieje" in msg


def test_register_user_referral_bonus(auth_manager, access_key_service):
    _ensure_user("referrer")
    key = access_key_service.generate_access_key("ref_bonus")
    ok, msg, _ = auth_manager.register_user("new_with_ref", "password123", key, referral_code="referrer")
    assert ok is True
    ref = User.query.filter_by(username="referrer").first()
    assert ref.hubert_coins >= 1


def test_register_user_integrity_error_branch(auth_manager, access_key_service, monkeypatch):
    key = access_key_service.generate_access_key("int")
    # Monkeypatch commit to raise IntegrityError once
    calls = {"n": 0}
    real_commit = db.session.commit
    def fail_once():
        if calls["n"] == 0:
            calls["n"] += 1
            raise IntegrityError("dup", None, None)
        return real_commit()
    monkeypatch.setattr(db.session, "commit", fail_once)
    ok, msg, token = auth_manager.register_user("int_user", "password123", key)
    assert ok is False and token is None


def test_register_user_generic_exception_branch(auth_manager, access_key_service, monkeypatch):
    key = access_key_service.generate_access_key("gen")
    def add_raises(*a, **k):
        raise Exception("boom")
    monkeypatch.setattr(db.session, "add", add_raises)
    ok, msg, token = auth_manager.register_user("gen_user", "password123", key)
    assert ok is False and token is None


def test_authenticate_user_paths(auth_manager, access_key_service):
    # not found
    ok, msg, user = auth_manager.authenticate_user("no_user", "x")
    assert ok is False and user is None
    # inactive
    key = access_key_service.generate_access_key("inactive")
    ok, _, _ = auth_manager.register_user("inactive_user", "password123", key)
    u = User.query.filter_by(username="inactive_user").first()
    u.is_active = False
    db.session.commit()
    ok2, msg2, user2 = auth_manager.authenticate_user("inactive_user", "password123")
    assert ok2 is False and user2 is None
    # success and wrong password
    key2 = access_key_service.generate_access_key("ok")
    ok3, _, _ = auth_manager.register_user("auth_ok", "password123", key2)
    assert ok3 is True
    ok4, msg4, user4 = auth_manager.authenticate_user("auth_ok", "password123")
    assert ok4 is True and user4 is not None
    ok5, msg5, user5 = auth_manager.authenticate_user("auth_ok", "BAD")
    assert ok5 is False and user5 is None


def test_get_user_helpers_and_toggle_delete(auth_manager, access_key_service):
    key = access_key_service.generate_access_key("helpers")
    ok, _, _ = auth_manager.register_user("helper_user", "password123", key)
    assert ok is True
    # get_user_by_id
    assert auth_manager.get_user_by_id("helper_user") is not None
    # get_all_users returns list
    assert isinstance(auth_manager.get_all_users(), list)
    # toggle true branch
    assert auth_manager.toggle_user_status("helper_user") is True
    # delete true branch
    assert auth_manager.delete_user("helper_user") is True
    # delete false branch
    assert auth_manager.delete_user("helper_user") is False
    # toggle false branch on non-existent user
    assert auth_manager.toggle_user_status("no_such_user") is False


def test_update_hubert_coins_paths(auth_manager, access_key_service):
    key = access_key_service.generate_access_key("coins")
    ok, _, _ = auth_manager.register_user("coins_user", "password123", key)
    assert ok is True
    ok1, _ = auth_manager.update_hubert_coins("coins_user", 2)
    assert ok1 is True
    ok2, msg2 = auth_manager.update_hubert_coins("coins_user", -999)
    assert ok2 is False and "Niewystarczająca" in msg2
    # user not found branch
    ok3, msg3 = auth_manager.update_hubert_coins("ghost_user", 1)
    assert ok3 is False


def test_reset_user_password_paths(auth_manager, access_key_service):
    key = access_key_service.generate_access_key("reset1")
    ok, _, _ = auth_manager.register_user("reset_user", "password123", key)
    assert ok is True
    # length invalid
    ok_len, _ = auth_manager.reset_user_password("reset_user", "123")
    assert ok_len is False
    # user not found
    ok_nf, _ = auth_manager.reset_user_password("no_reset_user", "password123")
    assert ok_nf is False
    # success
    ok_ok, _ = auth_manager.reset_user_password("reset_user", "new_password")
    assert ok_ok is True


def test_password_reset_token_and_reset_with_token(auth_manager, access_key_service):
    key = access_key_service.generate_access_key("ptok")
    ok, _, _ = auth_manager.register_user("prt_user", "password123", key)
    assert ok is True
    token = auth_manager.generate_password_reset_token("prt_user")
    assert token is not None
    # expired branch
    u = User.query.filter_by(username="prt_user").first()
    u.password_reset_expires = datetime.datetime.now() - datetime.timedelta(hours=1)
    db.session.commit()
    ok_exp, msg_exp = auth_manager.reset_user_password_with_token(token, "password123")
    assert ok_exp is False
    # length invalid
    token2 = auth_manager.generate_password_reset_token("prt_user")
    ok_len, msg_len = auth_manager.reset_user_password_with_token(token2, "123")
    assert ok_len is False
    # success
    ok_ok, msg_ok = auth_manager.reset_user_password_with_token(token2, "another_pass")
    assert ok_ok is True
    # invalid token branch
    ok_inv, msg_inv = auth_manager.reset_user_password_with_token("NON_EXISTENT_TOKEN", "password123")
    assert ok_inv is False


def test_generate_password_reset_token_nonexistent_user_branch(auth_manager):
    # ensure branch where user is not found returns None
    assert auth_manager.generate_password_reset_token("definitely_missing_user") is None


def test_reset_password_with_recovery_token_success(auth_manager, access_key_service):
    key = access_key_service.generate_access_key("reco")
    ok, _, _ = auth_manager.register_user("reco_user", "password123", key)
    assert ok is True
    user = User.query.filter_by(username="reco_user").first()
    ok_ok, msg = auth_manager.reset_password_with_recovery_token("reco_user", user.recovery_token, "newpass123")
    assert ok_ok is True


def test_reset_password_with_recovery_token_invalid_length_and_not_found(auth_manager, access_key_service):
    key = access_key_service.generate_access_key("reco2")
    ok, _, _ = auth_manager.register_user("reco_user2", "password123", key)
    assert ok is True
    user = User.query.filter_by(username="reco_user2").first()
    # length invalid
    ok_len, _ = auth_manager.reset_password_with_recovery_token("reco_user2", user.recovery_token, "123")
    assert ok_len is False
    # user/token not found branch
    ok_nf, _ = auth_manager.reset_password_with_recovery_token("reco_user2", "WRONG", "password123")
    assert ok_nf is False


def test_get_user_info_paths(auth_manager, access_key_service):
    # None path
    assert auth_manager.get_user_info("nope") is None
    key = access_key_service.generate_access_key("info")
    ok, _, _ = auth_manager.register_user("info_user", "password123", key)
    assert ok is True
    info = auth_manager.get_user_info("info_user")
    assert isinstance(info, dict) and info.get("username") == "info_user"


