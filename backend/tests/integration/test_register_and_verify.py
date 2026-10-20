import pytest

# Strong password used for registration tests
STRONG_PW = 'X9!kL@mN#pQ$rS%tU&vW*7zA'


class TestRegisterAndVerify:

    def test_register_strong_password_succeeds(self, client, post_json):
        resp = post_json(client, '/api/auth/register', {
            'email': 'newuser@example.com',
            'master_password': STRONG_PW,
            'check_breaches': False,
        })
        assert resp.status_code == 201
        body = resp.get_json()
        assert body['requires_verification'] is True
        assert body['email'] == 'newuser@example.com'

    def test_register_creates_user_row_with_token(self, client, post_json):
        post_json(client, '/api/auth/register', {
            'email': 'tokenuser@example.com',
            'master_password': STRONG_PW,
            'check_breaches': False,
        })

        import app as app_module
        from models import User
        with app_module.app.app_context():
            user = User.query.filter_by(email='tokenuser@example.com').first()
            assert user is not None
            assert user.email_verified is False
            assert user.email_verification_token is not None
            raw_token = next(
                token for email, token in app_module.app.config['TEST_EMAIL_TOKENS']
                if email == 'tokenuser@example.com'
            )
            assert user.email_verification_token != raw_token

    def test_verify_email_with_valid_token_marks_user_verified(self, client, registered_user):
        resp = client.get(f'/verify-email?token={registered_user["token"]}')
        assert resp.status_code == 200
        assert b'Email Verified' in resp.data

        import app as app_module
        from models import User
        with app_module.app.app_context():
            user = User.query.filter_by(email=registered_user['email']).first()
            assert user.email_verified is True

    def test_verify_email_with_invalid_token_rejected(self, client):
        resp = client.get('/verify-email?token=this-is-not-a-real-token')
        assert resp.status_code == 400
        assert b'Invalid' in resp.data or b'expired' in resp.data


class TestRegistrationGuards:

    def test_register_weak_password_is_rejected(self, client, post_json):
        resp = post_json(client, '/api/auth/register', {
            'email': 'weak@example.com',
            'master_password': 'abc',
            'check_breaches': False,
        })
        assert resp.status_code == 400
        body = resp.get_json()
        assert body.get('requires_confirmation') is not True

    def test_register_weak_password_cannot_be_overridden(self, client, post_json):
        resp = post_json(client, '/api/auth/register', {
            'email': 'weakok@example.com',
            'master_password': 'abc',
            'check_breaches': False,
            'confirm_weak': True,
        })
        assert resp.status_code == 400

    def test_register_duplicate_email_rejected(self, client, post_json):
        payload = {
            'email': 'dup@example.com',
            'master_password': STRONG_PW,
            'check_breaches': False,
        }
        post_json(client, '/api/auth/register', payload)
        resp = post_json(client, '/api/auth/register', payload)
        assert resp.status_code == 409

    def test_register_missing_fields_rejected(self, client, post_json):
        # Email only - no password
        resp = post_json(client, '/api/auth/register', {'email': 'a@b.com'})
        assert resp.status_code == 400

        # Password only - no email
        resp = post_json(client, '/api/auth/register', {'master_password': STRONG_PW})
        assert resp.status_code == 400
