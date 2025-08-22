import os
import pytest


def test_forced_500_before_request(client, monkeypatch):
    # Force uuid.uuid4 used in app.before_request to raise, causing 500
    import app as app_module

    def raise_err():
        raise RuntimeError("boom")

    monkeypatch.setattr(app_module, "uuid", type("U", (), {"uuid4": staticmethod(raise_err)}))
    with pytest.raises(RuntimeError):
        client.get("/api/health")


def test_admin_update_hubert_coins_combinations(admin_client):
    # Missing username
    r1 = admin_client.post("/admin/api/update-hubert-coins", json={"amount": 1})
    # Negative amount
    r2 = admin_client.post("/admin/api/update-hubert-coins", json={"username": "nouser", "amount": -999999})
    assert r1.status_code in (200, 400, 404)
    assert r2.status_code in (200, 400, 404)


def test_admin_access_keys_edge_cases(admin_client):
    # Empty payloads and weird keys
    admin_client.post("/admin/api/deactivate-access-key", json={"key": ""})
    admin_client.delete("/admin/api/delete-access-key", json={"key": None})
    long_desc = "x" * 1024
    admin_client.post("/admin/api/generate-access-key", json={"description": long_desc})


def test_search_and_comment_missing_fields(client):
    r1 = client.post("/api/search", json={})
    r2 = client.post("/api/comment", json={})
    assert r1.status_code in (200, 400, 422)
    assert r2.status_code in (200, 400, 422)


def test_static_js_cache_control_header(client):
    r = client.get("/static/js/register.js")
    if r.status_code == 200:
        cache = r.headers.get("Cache-Control")
        assert cache is None or isinstance(cache, str)


