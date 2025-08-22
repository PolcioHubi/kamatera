def test_google_fonts_links_present_in_static_pages(client):
    for page in ['/static/dashboard.html', '/static/documents.html', '/static/services.html', '/static/more.html', '/static/qr.html']:
        resp = client.get(page)
        assert resp.status_code in (200, 304)
        text = resp.get_data(as_text=True)
        assert 'https://fonts.googleapis.com' in text
        assert 'https://fonts.gstatic.com' in text or 'preconnect' in text

