import os
import re


def _parse_csp_header(csp_value: str) -> dict:
    directives = {}
    for part in csp_value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        directive = tokens[0]
        sources = tokens[1:]
        directives[directive] = sources
    return directives


def test_csp_dev_allows_google_fonts_and_blob_data(client):
    resp = client.get("/static/dashboard.html")
    assert resp.status_code in (200, 304)

    csp = resp.headers.get("Content-Security-Policy")
    assert csp, "CSP header missing"
    d = _parse_csp_header(csp)

    # img-src allows data: and blob:
    assert "img-src" in d
    assert "data:" in d["img-src"]
    assert "blob:" in d["img-src"]

    # style and font from Google
    assert "style-src" in d and "https://fonts.googleapis.com" in d["style-src"]
    assert "style-src-elem" in d and "https://fonts.googleapis.com" in d["style-src-elem"]
    assert "font-src" in d and "https://fonts.gstatic.com" in d["font-src"]

    # connect-src allows fonts endpoints for SW/font CSS fetch
    assert "connect-src" in d
    assert "https://fonts.googleapis.com" in d["connect-src"]
    assert "https://fonts.gstatic.com" in d["connect-src"]

    # other security headers
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    permissions = resp.headers.get("Permissions-Policy", "")
    assert "geolocation=()" in permissions
    assert "camera=()" in permissions
    assert "microphone=()" in permissions


def test_csp_prod_allows_google_fonts_when_env_set(client, monkeypatch):
    # Simulate production for this single request
    monkeypatch.setenv("FLASK_ENV", "production")
    resp = client.get("/static/dashboard.html")
    assert resp.status_code in (200, 304)

    csp = resp.headers.get("Content-Security-Policy")
    assert csp, "CSP header missing"
    d = _parse_csp_header(csp)

    # In prod we also allow Google Fonts per app configuration
    assert "style-src" in d and "https://fonts.googleapis.com" in d["style-src"]
    assert "style-src-elem" in d and "https://fonts.googleapis.com" in d["style-src-elem"]
    assert "font-src" in d and "https://fonts.gstatic.com" in d["font-src"]
    assert "connect-src" in d
    assert "https://fonts.googleapis.com" in d["connect-src"]
    assert "https://fonts.gstatic.com" in d["connect-src"]


