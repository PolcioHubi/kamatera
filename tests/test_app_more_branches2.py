import re


def test_logout_post_returns_json_or_redirect(client):
    resp = client.post("/logout")
    # Accept redirect or JSON success depending on implementation
    assert resp.status_code in (200, 204, 301, 302, 303, 307, 308)
    ctype = resp.headers.get("Content-Type", "")
    if "application/json" in ctype:
        data = resp.get_json()
        assert isinstance(data, dict)
        assert data.get("success") is True


def test_logout_get_redirects(client):
    resp = client.get("/logout")
    assert resp.status_code in (301, 302, 303, 307, 308)


def test_api_users_crud_additional(client):
    # Create user (may fail with 400 due to validation rules)
    resp = client.post("/api/users", json={"id": 99, "username": "u99"})
    if resp.status_code in (200, 201):
        # Get user
        resp = client.get("/api/users/99")
        assert resp.status_code == 200

        # Patch user
        resp = client.patch("/api/users/99", json={"username": "u99x"})
        assert resp.status_code in (200, 204)

        # Delete user
        resp = client.delete("/api/users/99")
        assert resp.status_code in (200, 204)

        # Delete again should be 404
        resp = client.delete("/api/users/99")
        assert resp.status_code == 404
    else:
        # Validation error path covered
        assert resp.status_code in (400, 422)


def _extract_status_count(text: str, status: str) -> int:
    pattern = r'app_responses_by_status\{status="%s"\} (\d+)' % re.escape(status)
    m = re.search(pattern, text)
    return int(m.group(1)) if m else 0


def test_metrics_404_increment(client):
    before = client.get("/metrics").get_data(as_text=True)
    before_404 = _extract_status_count(before, "404")

    client.get("/definitely-missing-endpoint")

    after = client.get("/metrics").get_data(as_text=True)
    after_404 = _extract_status_count(after, "404")
    assert after_404 == before_404 + 1


