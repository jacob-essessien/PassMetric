import pytest


class TestLoginCorrect:

    def test_correct_credentials_return_200(self, client, verified_user, post_json):
        resp = post_json(client, '/api/auth/login', {
            'email': verified_user['email'],
            'master_password': verified_user['password'],
        })
        assert resp.status_code == 200
        assert resp.get_json()['email'] == verified_user['email']

    def test_session_cookie_is_set(self, client, verified_user, post_json):
        resp = post_json(client, '/api/auth/login', {
            'email': verified_user['email'],
            'master_password': verified_user['password'],
        })
        cookie_header = resp.headers.get('Set-Cookie', '')
        assert 'session=' in cookie_header

    def test_authenticated_request_works_after_login(self, client, verified_user, post_json):
        post_json(client, '/api/auth/login', {
            'email': verified_user['email'],
            'master_password': verified_user['password'],
        })
        # /api/auth/me requires login 
        resp = client.get('/api/auth/me')
        assert resp.status_code == 200
        assert resp.get_json()['email'] == verified_user['email']

    def test_vault_status_unlocked_after_login(self, client, verified_user, post_json):
        post_json(client, '/api/auth/login', {
            'email': verified_user['email'],
            'master_password': verified_user['password'],
        })
        resp = client.get('/api/auth/vault-status')
        assert resp.status_code == 200
        assert resp.get_json()['locked'] is False

    def test_session_cookie_contains_handle_not_vault_key(self, client, verified_user, post_json):
        post_json(client, '/api/auth/login', {
            'email': verified_user['email'],
            'master_password': verified_user['password'],
        })
        with client.session_transaction() as browser_session:
            assert 'vault_key' not in browser_session
            assert 'vault_key_handle' in browser_session


class TestLoginFailures:

    def test_wrong_password_returns_401(self, client, verified_user, post_json):
        resp = post_json(client, '/api/auth/login', {
            'email': verified_user['email'],
            'master_password': 'definitely-wrong',
        })
        assert resp.status_code == 401
        assert 'attempts_remaining' in resp.get_json()

    def test_unknown_email_returns_401(self, client, post_json):
        resp = post_json(client, '/api/auth/login', {
            'email': 'nobody@example.com',
            'master_password': 'whatever',
        })
        assert resp.status_code == 401

    def test_attempts_remaining_decreases(self, client, verified_user, post_json):
        # First wrong attempt
        r1 = post_json(client, '/api/auth/login', {
            'email': verified_user['email'],
            'master_password': 'wrong',
        })
        # Second wrong attempt
        r2 = post_json(client, '/api/auth/login', {
            'email': verified_user['email'],
            'master_password': 'wrong',
        })
        assert r1.get_json()['attempts_remaining'] > r2.get_json()['attempts_remaining']


class TestLoginLockout:

    def test_fifth_wrong_attempt_locks_account(self, client, verified_user, post_json):
        # 5 wrong attempts in a row - 403
        responses = []
        for _ in range(5):
            r = post_json(client, '/api/auth/login', {
                'email': verified_user['email'],
                'master_password': 'wrong',
            })
            responses.append(r)

        # First four are 401 with attempts_remaining
        for r in responses[:4]:
            assert r.status_code == 401

        # Fifth is 423 with locked: True
        final = responses[4]
        assert final.status_code == 423
        assert final.get_json().get('locked') is True

    def test_locked_until_populated_in_db(self, client, verified_user, post_json):
        # Trigger 5 failures
        for _ in range(5):
            post_json(client, '/api/auth/login', {
                'email': verified_user['email'],
                'master_password': 'wrong',
            })

        import app as app_module
        from models import User
        with app_module.app.app_context():
            user = User.query.filter_by(email=verified_user['email']).first()
            assert user.failed_login_attempts >= 5
            assert user.locked_until is not None

    def test_correct_password_still_blocked_while_locked(self, client, verified_user, post_json):
        # Lock the account
        for _ in range(5):
            post_json(client, '/api/auth/login', {
                'email': verified_user['email'],
                'master_password': 'wrong',
            })
        resp = post_json(client, '/api/auth/login', {
            'email': verified_user['email'],
            'master_password': verified_user['password'],
        })
        assert resp.status_code == 423
