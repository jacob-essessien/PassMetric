import os
import sys
import json
import pytest


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))


os.environ.setdefault('HCAPTCHA_SECRET', '')
os.environ.setdefault('SMTP_USER', '')


#Shared test credentials
TEST_EMAIL = 'integration@example.com'
TEST_PASSWORD = 'X9!kL@mN#pQ$rS%tU&vW*7zA'  # strong; passes the strength gate


#Flask test client
@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv('SMTP_USER', '')
    monkeypatch.setenv('HCAPTCHA_SECRET', '')

    # Lowers Argon2id cost
    import cryptManager
    monkeypatch.setattr(cryptManager.CryptManager, 'ARGON2_TIME_COST', 1)
    monkeypatch.setattr(cryptManager.CryptManager, 'ARGON2_MEMORY_COST', 8)

    import app as app_module

    # replaces PasswordHasher with a lowcost one
    from argon2 import PasswordHasher
    monkeypatch.setattr(app_module, 'ph', PasswordHasher(time_cost=1, memory_cost=8, parallelism=1))

    # Registration/change-email do not open real SMTP sockets.
    sent_tokens = []
    monkeypatch.setattr(
        app_module,
        'send_verification_email',
        lambda email, token: sent_tokens.append((email, token)),
    )
    monkeypatch.setattr(app_module, 'send_email_change_email', lambda *a, **k: None)
    monkeypatch.setattr(app_module.generator, 'wordlist', ['alpha', 'bravo', 'charlie', 'delta'])

    flask_app = app_module.app
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    flask_app.config['TEST_EMAIL_TOKENS'] = sent_tokens
    app_module.limiter.enabled = False
    app_module._vault_keys.clear()

    with flask_app.app_context():
        app_module.db.drop_all()
        app_module.db.create_all()

    with flask_app.test_client() as test_client:
        yield test_client

    with flask_app.app_context():
        app_module.db.session.remove()
        app_module.db.drop_all()


#JSON helpers
@pytest.fixture
def post_json():
    def _post(client, path, payload):
        return client.post(path, data=json.dumps(payload),
                           content_type='application/json')
    return _post


@pytest.fixture
def put_json():
    def _put(client, path, payload):
        return client.put(path, data=json.dumps(payload),
                          content_type='application/json')
    return _put


@pytest.fixture
def registered_user(client, post_json):
    post_json(client, '/api/auth/register', {
        'email': TEST_EMAIL,
        'master_password': TEST_PASSWORD,
        'check_breaches': False,
    })

    import app as app_module
    from models import User
    with app_module.app.app_context():
        user = User.query.filter_by(email=TEST_EMAIL).first()
        assert user.email_verification_token is not None

    token = next(token for email, token in client.application.config['TEST_EMAIL_TOKENS']
                 if email == TEST_EMAIL)

    return {'email': TEST_EMAIL, 'password': TEST_PASSWORD, 'token': token}


@pytest.fixture
def verified_user(client, registered_user):
    client.get(f'/verify-email?token={registered_user["token"]}')
    return registered_user


@pytest.fixture
def logged_in_user(client, verified_user, post_json):
    post_json(client, '/api/auth/login', {
        'email': verified_user['email'],
        'master_password': verified_user['password'],
    })
    return verified_user
