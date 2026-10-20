import pytest


class TestPublicRoutes:

    def test_health_endpoint(self, client):
        resp = client.get('/api/health')
        assert resp.status_code == 200
        assert b'PassMetric API' in resp.data

    def test_csrf_token_endpoint(self, client):
        resp = client.get('/api/csrf-token')
        assert resp.status_code == 200
        assert 'csrf_token' in resp.get_json()

    def test_config_endpoint(self, client):
        resp = client.get('/api/config')
        assert resp.status_code == 200
        assert 'hcaptcha_sitekey' in resp.get_json()

    def test_unknown_api_path_returns_json(self, client):
        resp = client.get('/api/does-not-exist')
        assert resp.status_code == 404
        assert resp.is_json


class TestSecurityHeaders:

    def test_xss_and_framing_headers(self, client):
        resp = client.get('/api/health')
        assert resp.headers.get('X-Content-Type-Options') == 'nosniff'
        assert resp.headers.get('X-Frame-Options') == 'DENY'
        assert resp.headers.get('X-XSS-Protection') == '0'

    def test_csp_header_present(self, client):
        resp = client.get('/api/health')
        csp = resp.headers.get('Content-Security-Policy', '')
        assert "default-src 'self'" in csp
        assert "object-src 'none'" in csp
        assert "script-src 'self' 'unsafe-inline'" not in csp

    def test_api_responses_are_no_store(self, client):
        # /api/* responses must not be cached (sensitive data goes through here)
        resp = client.get('/api/health')
        assert 'no-store' in resp.headers.get('Cache-Control', '')


class TestUnauthenticatedAccess:

    def test_protected_route_returns_401_json(self, client):
        # without a session it should return JSON 401
        resp = client.get('/api/auth/me')
        assert resp.status_code == 401
        assert resp.is_json

    def test_dashboard_redirects_to_index(self, client):
        resp = client.get('/dashboard', follow_redirects=False)
        assert resp.status_code in (301, 302)


def test_configured_captcha_fails_closed_on_network_error(client, monkeypatch):
    import app as app_module

    monkeypatch.setattr(app_module, 'HCAPTCHA_SECRET', 'configured-secret')

    def fail_request(*args, **kwargs):
        raise OSError('network unavailable')

    monkeypatch.setattr(app_module.http_requests, 'post', fail_request)
    with app_module.app.test_request_context('/api/auth/login'):
        assert app_module.verify_captcha('token') is False
