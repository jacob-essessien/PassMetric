import secrets
import os
import json
import base64
import smtplib
import hashlib
import hmac
import re
import threading
import time
import requests as http_requests

# Loads env
try:
    from dotenv import load_dotenv
    _base = os.path.dirname(os.path.abspath(__file__))
    _env_path = os.path.join(_base, '.env')
    if os.path.exists(_env_path):
        load_dotenv(_env_path)
except ImportError:
    pass

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import Flask, redirect, session, request, jsonify, send_from_directory
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from combinedAnalyzer import CombinedPasswordAnalyzer
from passGen import PasswordGenerator, PasswordRequirements
from models import db, User, VaultEntry
from cryptManager import CryptManager
from breachChecker import BreachChecker
from datetime import datetime, timedelta, timezone
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import func
from werkzeug.exceptions import HTTPException


app = Flask(
    __name__,
    static_folder=os.path.join(os.path.dirname(__file__), '..', 'frontend'),
    static_url_path=''
)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    strategy="fixed-window",
)


app.config['RATELIMIT_IN_MEMORY_FALLBACK_ENABLED'] = True
app.config['RATELIMIT_SWALLOW_ERRORS'] = True

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

csrf = CSRFProtect(app)

ph = PasswordHasher()

analyzer = CombinedPasswordAnalyzer()
generator = PasswordGenerator()
breach_checker = BreachChecker()
breach_checker.load_dataset()

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)
ATTEMPT_RESET_WINDOW = timedelta(minutes=30)

def env_flag(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {'1', 'true', 'yes', 'on'}


app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = env_flag('SESSION_COOKIE_SECURE')
app.config['WTF_CSRF_TIME_LIMIT'] = 3600
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024

SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASS = os.environ.get('SMTP_PASS', '')
APP_URL = os.environ.get('APP_URL', 'http://localhost:5000')

HCAPTCHA_SECRET = os.environ.get('HCAPTCHA_SECRET', '')
CAPTCHA_THRESHOLD = 2  # Number of failed attempts before showing CAPTCHA
MAX_MASTER_PASSWORD_LENGTH = 1024
MAX_VAULT_PASSWORD_LENGTH = 4096
MAX_NOTES_LENGTH = 4000
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def verify_captcha(token):
    if not HCAPTCHA_SECRET:
        return True

    try:
        response = http_requests.post(
            'https://api.hcaptcha.com/siteverify',
            data={
                'secret': HCAPTCHA_SECRET,
                'response': token,
                'remoteip': request.remote_addr,
            },
            timeout=5
        )
        response.raise_for_status()
        result = response.json().get('success', False)
    except Exception:
        result = False
    return result


def generate_email_token(email):
    return email_serializer.dumps(email, salt='email-confirm')

def verify_email_token(token, max_age=3600):
    try:
        email = email_serializer.loads(token, salt='email-confirm', max_age=max_age)
        return email
    except Exception:
        return None


def token_digest(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def valid_email(email):
    return len(email) <= 255 and EMAIL_RE.fullmatch(email) is not None


def normalized_email(value):
    return value.strip().lower() if isinstance(value, str) else ''
    
def send_verification_email(to_email, token):
    verify_url = f"{APP_URL}/verify-email?token={token}"

    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'PassMetric - Verify your email'
    msg['From'] = SMTP_USER
    msg['To'] = to_email

    html = f"""
    <html><body style="font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 40px;">
        <div style="max-width: 480px; margin: auto;">
            <h2 style="color: #6366f1;">PassMetric</h2>
            <p>Welcome! Please verify your email to activate your vault.</p>
            <a href="{verify_url}"
               style="display: inline-block; padding: 12px 28px; background: #6366f1;
                      color: white; text-decoration: none; border-radius: 8px;
                      font-weight: 600; margin: 20px 0;">
                Verify Email
            </a>
            <p style="font-size: 13px; color: #94a3b8;">
                This link expires in 1 hour. If you didn't create this account, ignore this email.
            </p>
        </div>
    </body></html>
    """

    msg.attach(MIMEText(html, 'html'))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        print(f"[EMAIL] Verification sent to {to_email}")
    except Exception:
        app.logger.exception("Could not send verification email to %s", to_email)

# blocks access to routes if email not verified
def require_verified_email(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.email_verified:
            return jsonify({
                'error': 'Please verify your email first',
                'email_verified': False
            }), 403
        return f(*args, **kwargs)
    return decorated

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SECRET_KEY_FILE = os.path.join(BASE_DIR, '.secret_key')
 
def get_or_create_secret_key():
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, 'r') as f:
            key = f.read().strip()
            if key:  # Make sure it's not empty
                return key
    # Generate a new key and save it
    key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, 'w') as f:
        f.write(key)
    return key
 
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or get_or_create_secret_key()
email_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

DB_PATH = os.path.join(BASE_DIR, 'passmetric.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH
 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
 
db.init_app(app)
 
with app.app_context():
    db.create_all()


@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'indexx.html')

@app.route('/dashboard')
@login_required
@require_verified_email
def dashboard():
    return send_from_directory(app.static_folder, 'dashboard.html')


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'message': 'PassMetric API is running!'})

@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    token = generate_csrf()
    return jsonify({'csrf_token': token})

@app.route('/api/config', methods=['GET'])
def get_config():
    return jsonify({
        'hcaptcha_sitekey': os.environ.get('HCAPTCHA_SITEKEY', ''),
    })

@app.route('/api/auth/login-status', methods=['POST'])
def login_status():
    # CAPTCHA is requested by the login response after the threshold is met.
    # Do not reveal whether an email address exists or its failure count.
    return jsonify({'captcha_required': False})



# security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '0'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'

    if app.config['SESSION_COOKIE_SECURE']:
        response.headers['Strict-Transport-Security'] = (
            'max-age=31536000; includeSubDomains'
        )

    if request.path.startswith('/api/') or request.path == '/dashboard':
        response.headers['Cache-Control'] = 'no-store, private'

    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://js.hcaptcha.com https://*.hcaptcha.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://*.hcaptcha.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https://*.hcaptcha.com; "
        "frame-src https://*.hcaptcha.com; "
        "connect-src 'self' https://*.hcaptcha.com; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none';"
    )
    return response


# error handling
@app.errorhandler(Exception)
def handle_any_exception(e):
    if isinstance(e, HTTPException):
        if request.path.startswith('/api/'):
            return jsonify({'error': e.description, 'code': e.code}), e.code
        return e
    app.logger.exception("Unhandled request error")
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error', 'code': 500}), 500
    return 'Internal server error', 500



@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@login_manager.unauthorized_handler
def unauthorized():
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Unauthorized'}), 401
    return redirect('/')

@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("3 per minute")  # limit registration attempts to prevent abuse
@limiter.limit("20 per hour")
def register():
    data = request.get_json(silent=True) or {}
    email = normalized_email(data.get('email'))
    master_password = data.get('master_password', '')
    check_breaches = data.get('check_breaches', True)

    if not email or not master_password:
        return jsonify({'error': 'Email and password are required'}), 400

    if not valid_email(email):
        return jsonify({'error': 'Enter a valid email address'}), 400

    if not isinstance(master_password, str) or len(master_password) > MAX_MASTER_PASSWORD_LENGTH:
        return jsonify({'error': 'Master password is too long'}), 400

    if User.query.filter(func.lower(User.email) == email).first():
        return jsonify({'error': 'Account already exists'}), 409


    try:
        analysis = analyzer.analyze_password(master_password, include_ml=False)
        if analysis is None or 'rule_based' not in analysis:
            print(f"[REGISTER] analyze_password returned unexpected shape: {analysis!r}")
            return jsonify({'error': 'Password analysis failed'}), 500
        
        score = analysis['rule_based'].get('score', 0)

        is_breached = False
        breach_msg = None
        if check_breaches and breach_checker.is_loaded:
            result = breach_checker.is_breached(master_password)
            if result is not None:
                is_breached, breach_msg = result

        if is_breached or score < 30 or len(master_password) < 12:
            return jsonify({
                'error': 'Choose a stronger master password (at least 12 characters)',
                'is_breached': is_breached,
                'breach_message': breach_msg,
                'score': score,
                'strength': analysis.get('combined_strength', 'WEAK'),
                'issues': analysis['rule_based'].get('issues', []),
                'recommendations': analysis['rule_based'].get('recommendations', []),
            }), 400

        password_hash = ph.hash(master_password)

        vault_salt = CryptManager.generate_salt()


        vault_key = CryptManager.derive_key(master_password, vault_salt)


        verification = CryptManager.encrypt_data("passmetric_ok", vault_key)

        email_token = generate_email_token(email)

        user = User(
            email=email,
            master_password_hash=password_hash,
            vault_salt=base64.b64encode(vault_salt).decode('utf-8'),
            vault_verification=json.dumps(verification),
            email_verified=False,
            email_verification_token=token_digest(email_token),
            email_verification_sent_at=datetime.now(timezone.utc)

        )
        db.session.add(user)
        db.session.commit()

        send_verification_email(email, email_token) 

    
        return jsonify({'requires_verification': True, 'message': 'Account created. Please verify your email.', 'email': email}), 201
    except Exception:
        db.session.rollback()
        app.logger.exception("Registration failed")
        return jsonify({'error': 'Could not create account'}), 500
                
@app.route('/verify-email')
def verify_email():
    token = request.args.get('token', '')
    email = verify_email_token(token)

    if not email:
        return '<h2>Invalid or expired verification link.</h2>', 400

    user = User.query.filter_by(email=email).first()
    if (not user or not user.email_verification_token or
            not hmac.compare_digest(user.email_verification_token, token_digest(token))):
        return '<h2>Invalid or expired verification link.</h2>', 400

    user.email_verified = True
    user.email_verification_token = None
    db.session.commit()

    # redirects to login page with a success message
    return '''
    <html><body style="font-family:sans-serif;background:#0f172a;color:#e2e8f0;
          display:flex;justify-content:center;align-items:center;height:100vh;">
        <div style="text-align:center;">
            <h2 style="color:#22c55e;">Email Verified!</h2>
            <p>Your account is now active.</p>
            <a href="/" style="color:#6366f1;">Go to login</a>
        </div>
    </body></html>
    '''


@app.route('/api/auth/resend-verification', methods=['POST'])
@limiter.limit("2 per minute")
def resend_verification():
    data = request.get_json(silent=True) or {}
    email = normalized_email(data.get('email'))
    master_password = data.get('master_password', '')

    user = None
    if current_user.is_authenticated:
        user = current_user
    elif email:
        user = User.query.filter(func.lower(User.email) == email).first()
    else:
        return jsonify({'error': 'Email is required'}), 400

    if not user:
        return jsonify({'error': 'Invalid email or password'}), 401

    if user.email_verified:
        return jsonify({'message': 'Already verified'}), 200

    if not current_user.is_authenticated:
        if not master_password:
            return jsonify({'error': 'Invalid email or password'}), 401
        try:
            ph.verify(user.master_password_hash, master_password)
        except (VerifyMismatchError, VerificationError):
            return jsonify({'error': 'Invalid email or password'}), 401

    token = generate_email_token(user.email)
    user.email_verification_token = token_digest(token)
    user.email_verification_sent_at = datetime.now(timezone.utc)
    db.session.commit()

    send_verification_email(user.email, token)
    return jsonify({'message': 'Verification email resent'}), 200



@app.route('/api/auth/precheck-password', methods=['POST'])
def precheck_password():
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')

    if not isinstance(password, str) or not password:
        return jsonify({'error': 'Password is required'}), 400
    if len(password) > MAX_MASTER_PASSWORD_LENGTH:
        return jsonify({'error': 'Password is too long'}), 400

    try:
        analysis = analyzer.analyze_password(password)
    except Exception:
        analysis = analyzer.analyze_password(password, include_ml=False)

    is_breached = False
    breach_msg = None
    if breach_checker.is_loaded:
        is_breached, breach_msg = breach_checker.is_breached(password)

    return jsonify({
        'score': analysis['rule_based']['score'],
        'strength': analysis['combined_strength'],
        'is_breached': is_breached,
        'breach_message': breach_msg,
        'is_weak': analysis['rule_based']['score'] < 30,
        'needs_warning': bool(is_breached or analysis['rule_based']['score'] < 30),
    }), 200

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("7 per minute")  # limit login attempts to prevent abuse
@limiter.limit("20 per hour")
def login():
    data = request.get_json(silent=True) or {}
    email = normalized_email(data.get('email'))
    master_password = data.get('master_password', '')
    captcha_token = data.get('captcha_token', '')

    if (not isinstance(master_password, str) or
            len(master_password) > MAX_MASTER_PASSWORD_LENGTH):
        return jsonify({'error': 'Invalid email or password'}), 401

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'Invalid email or password'}), 401
    
    if (user.failed_login_attempts >= CAPTCHA_THRESHOLD and HCAPTCHA_SECRET):
        if not captcha_token or not verify_captcha(captcha_token):
            return jsonify({'error': 'CAPTCHA verification failed', 'requires_captcha': True}), 400
    
    now = datetime.now(timezone.utc)

    # Check if account is locked due to too many failed attempts
    locked_until = user.locked_until
    if locked_until is not None and locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    if locked_until and locked_until > now:
        remaining = int((locked_until - now).total_seconds())
        minutes_left = max(1, remaining // 60)
        return jsonify({
            'error': f'Account temporarily locked. Try again in {minutes_left} minute(s).',
            'locked': True,
            'retry_after_seconds': remaining
        }), 423  # 423 Locked

    # Reset failed attempts if last failure was long ago
    last_failed = user.last_failed_login
    if last_failed is not None and last_failed.tzinfo is None:
        last_failed = last_failed.replace(tzinfo=timezone.utc)
    if (last_failed and
        user.failed_login_attempts > 0 and
        (now - last_failed) > ATTEMPT_RESET_WINDOW):
        user.failed_login_attempts = 0


    # Verify password against stored hash
    try:
        ph.verify(user.master_password_hash, master_password)
    except (VerifyMismatchError, VerificationError):
        #records failed attempts
        user.failed_login_attempts += 1
        user.last_failed_login = now

        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = now + LOCKOUT_DURATION
            db.session.commit()
            return jsonify({
                'error': f'Too many failed attempts. Account locked for {LOCKOUT_DURATION.seconds // 60} minutes.',
                'locked': True
            }), 423

        remaining_attempts = MAX_FAILED_ATTEMPTS - user.failed_login_attempts
        db.session.commit()
        return jsonify({
            'error': 'Invalid email or password',
            'attempts_remaining': remaining_attempts
        }), 401

    if not user.email_verified:
        return jsonify({
            'error': 'Please verify your email before logging in',
            'requires_verification': True,
            'email': user.email,
        }), 403

    # Login successful, reset lockout state
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_failed_login = None

    # Rehash if needed
    if ph.check_needs_rehash(user.master_password_hash):
        user.master_password_hash = ph.hash(master_password)

    # Derive vault key
    vault_salt = base64.b64decode(user.vault_salt)
    vault_key = CryptManager.derive_key(master_password, vault_salt)
    verification = json.loads(user.vault_verification)
    try:
        vault_is_valid = CryptManager.decrypt_data(verification, vault_key) == 'passmetric_ok'
    except Exception:
        vault_is_valid = False
    if not vault_is_valid:
        app.logger.error("Vault verification failed for user %s", user.id)
        return jsonify({'error': 'Vault data could not be unlocked'}), 500
    login_user(user)
    install_vault_key(user.id, vault_key)

    db.session.commit()
    return jsonify({'message': 'Logged in', 'email': email}), 200

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'error': 'Too many attempts. Please try again later.',
        'retry_after': e.description
    }), 429


@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    clear_vault_key()
    session.clear()
    logout_user()
    return jsonify({'message': 'Logged out'}), 200


#lock and unlock vault (remove/re-derive vault key in session)
@app.route('/api/auth/lock', methods=['POST'])
@login_required
def lock_vault():
    clear_vault_key()
    return jsonify({'message': 'Vault locked'}), 200


# Unlocking the vault requires re-entering the master password to re-derive the key.
@app.route('/api/auth/unlock', methods=['POST'])
@login_required
@require_verified_email
@limiter.limit("10 per minute")
def unlock_vault():
    data = request.get_json(silent=True) or {}
    master_password = data.get('master_password', '')

    if not isinstance(master_password, str) or not master_password:
        return jsonify({'error': 'Master password is required'}), 400

    try:
        ph.verify(current_user.master_password_hash, master_password)
    except (VerifyMismatchError, VerificationError):
        return jsonify({'error': 'Incorrect master password'}), 401

    # Re-derive and re-install the vault key
    vault_salt = base64.b64decode(current_user.vault_salt)
    vault_key = CryptManager.derive_key(master_password, vault_salt)
    install_vault_key(current_user.id, vault_key)

    return jsonify({'message': 'Vault unlocked'}), 200


# route to check if vault is currently locked
@app.route('/api/auth/vault-status', methods=['GET'])
@login_required
def vault_status():
    return jsonify({
        'locked': get_vault_key() is None,
        'email': current_user.email,
    }), 200

@app.route('/api/auth/me', methods=['GET'])
@login_required
def me():
    return jsonify({'email': current_user.email}), 200



@app.route('/api/analyze', methods=['POST'])
def analyze_password():
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')

    if not isinstance(password, str) or not password:
        return jsonify({'error': 'Password is required'}), 400
    if len(password) > MAX_MASTER_PASSWORD_LENGTH:
        return jsonify({'error': 'Password is too long'}), 400

    analysis = analyzer.analyze_password(password)

    if breach_checker.is_loaded:
        is_breached, breach_msg = breach_checker.is_breached(password)
        analysis['breach'] = {
            'is_breached': is_breached,
            'message': breach_msg,
            'dataset_size': breach_checker.total_passwords
        }
    return jsonify(analysis), 200

@app.route('/api/generate', methods=['POST'])
def generate_password():
    data = request.get_json(silent=True) or {}
    requirements_data = data.get('requirements', {})

    if not isinstance(requirements_data, dict):
        return jsonify({'error': 'Invalid password requirements'}), 400

    requirements = PasswordRequirements(
        length=requirements_data.get('length', 12),
        include_uppercase=requirements_data.get('include_uppercase', True),
        include_lowercase=requirements_data.get('include_lowercase', True),
        include_digits=requirements_data.get('include_digits', True),
        include_symbols=requirements_data.get('include_special', True)
    )

    try:
        password = generator.generate_password(requirements)
    except (TypeError, ValueError) as error:
        return jsonify({'error': str(error)}), 400
    return jsonify({'password': password}), 200

# Flask's default session is a signed browser cookie, not encrypted storage.
# Keep derived vault keys in this process and put only an opaque handle in the
# cookie. A multi-process deployment would need a shared server-side store.
VAULT_KEY_TTL_SECONDS = 900
_vault_keys = {}
_vault_keys_lock = threading.RLock()


def _discard_key_unlocked(handle):
    record = _vault_keys.pop(handle, None)
    if record:
        for index in range(len(record['key'])):
            record['key'][index] = 0


def clear_vault_key():
    handle = session.pop('vault_key_handle', None)
    if handle:
        with _vault_keys_lock:
            _discard_key_unlocked(handle)


def clear_user_vault_keys(user_id):
    session.pop('vault_key_handle', None)
    with _vault_keys_lock:
        handles = [
            handle for handle, record in _vault_keys.items()
            if record['user_id'] == user_id
        ]
        for handle in handles:
            _discard_key_unlocked(handle)


def install_vault_key(user_id, key):
    clear_vault_key()
    handle = secrets.token_urlsafe(32)
    now = time.monotonic()
    with _vault_keys_lock:
        expired = [
            item for item, record in _vault_keys.items()
            if record['expires_at'] <= now
        ]
        for item in expired:
            _discard_key_unlocked(item)
        _vault_keys[handle] = {
            'user_id': user_id,
            'key': bytearray(key),
            'expires_at': now + VAULT_KEY_TTL_SECONDS,
        }
    session['vault_key_handle'] = handle


def get_vault_key():
    handle = session.get('vault_key_handle')
    if not handle or not current_user.is_authenticated:
        return None

    with _vault_keys_lock:
        record = _vault_keys.get(handle)
        now = time.monotonic()
        if (not record or record['user_id'] != current_user.id or
                record['expires_at'] <= now):
            _discard_key_unlocked(handle)
            session.pop('vault_key_handle', None)
            return None
        record['expires_at'] = now + VAULT_KEY_TTL_SECONDS
        return bytes(record['key'])


#add vault entry
@app.route('/api/vault/entries', methods=['POST'])
@login_required
@require_verified_email
def add_entry():
    vault_key = get_vault_key()
    if not vault_key:
        return jsonify({'error': 'Vault locked'}), 403

    data = request.get_json(silent=True) or {}
    if any(not isinstance(data.get(field, ''), str)
           for field in ('website', 'username', 'password', 'notes')):
        return jsonify({'error': 'Entry fields must be text'}), 400
    website = data.get('website', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    notes = data.get('notes', '')

    if not website or not username or not password:
        return jsonify({'error': 'All fields required'}), 400
    if (len(website) > 255 or len(username) > 255 or
            len(password) > MAX_VAULT_PASSWORD_LENGTH or
            len(notes) > MAX_NOTES_LENGTH):
        return jsonify({'error': 'One or more entry fields are too long'}), 400

    # Check if the vault password is breached 
    breach_warning = None
    if breach_checker.is_loaded:
        is_breached, breach_msg = breach_checker.is_breached(password)
        if is_breached:
            breach_warning = breach_msg

    # Encrypt the password before storing
    encrypted = CryptManager.encrypt_data(password, vault_key)
    now = datetime.now(timezone.utc)
    entry = VaultEntry(
        entry_id=VaultEntry.generate_entry_id(),
        user_id=current_user.id,
        website=website,
        username=username,
        encrypted_password=json.dumps(encrypted),
        notes=notes,
        password_changed_at=now,
    )
    db.session.add(entry)
    db.session.commit()

    response = {'message': 'Entry added', 'entry_id': entry.entry_id}
    if breach_warning:
        response['breach_warning'] = breach_warning
    
    return jsonify(response), 201

#list vault entries
@app.route('/api/vault/entries', methods=['GET'])
@login_required
@require_verified_email
def list_entries():
    vault_key = get_vault_key()
    if not vault_key:
        return jsonify({'error': 'Vault locked'}), 403

    entries = VaultEntry.query.filter_by(user_id=current_user.id).all()
    result = []

    for entry in entries:
        encrypted = json.loads(entry.encrypted_password)
        password = CryptManager.decrypt_data(encrypted, vault_key)

        result.append({
            'entry_id': entry.entry_id,
            'website': entry.website,
            'username': entry.username,
            'password': password,
            'notes': entry.notes,
            'password_changed_at': (
                entry.password_changed_at.isoformat()
                if entry.password_changed_at else None
            ),
            'created_at': entry.created_at.isoformat() if entry.created_at else None,
            'updated_at': entry.updated_at.isoformat() if entry.updated_at else None,
        })

    return jsonify({'entries': result}), 200

#Update vault entry
@app.route('/api/vault/entries/<entry_id>', methods=['PUT'])
@login_required
@require_verified_email
def update_entry(entry_id):
    vault_key = get_vault_key()
    if not vault_key:
        return jsonify({'error': 'Vault locked'}), 403

    entry = VaultEntry.query.filter_by(
        entry_id=entry_id, user_id=current_user.id
    ).first()
    if not entry:
        return jsonify({'error': 'Not found'}), 404

    data = request.get_json(silent=True) or {}
    for field in ('website', 'username', 'password', 'notes'):
        if field in data and not isinstance(data[field], str):
            return jsonify({'error': 'Entry fields must be text'}), 400
    if 'website' in data:
        website = data['website'].strip()
        if not website or len(website) > 255:
            return jsonify({'error': 'Invalid website'}), 400
        entry.website = website
    if 'username' in data:
        username = data['username'].strip()
        if not username or len(username) > 255:
            return jsonify({'error': 'Invalid username'}), 400
        entry.username = username
    if 'password' in data:
        if not data['password'] or len(data['password']) > MAX_VAULT_PASSWORD_LENGTH:
            return jsonify({'error': 'Invalid password'}), 400
        try:
            existing_enc = json.loads(entry.encrypted_password)
            existing_plain = CryptManager.decrypt_data(existing_enc, vault_key)
        except Exception:
            existing_plain = None
        new_plain = data['password']
        if new_plain != existing_plain:
            encrypted = CryptManager.encrypt_data(new_plain, vault_key)
            entry.encrypted_password = json.dumps(encrypted)
            entry.password_changed_at = datetime.now(timezone.utc)
    if 'notes' in data:
        if len(data['notes']) > MAX_NOTES_LENGTH:
            return jsonify({'error': 'Notes are too long'}), 400
        entry.notes = data['notes']

    entry.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({'message': 'Updated'}), 200

#Delete vault entry
@app.route('/api/vault/entries/<entry_id>', methods=['DELETE'])
@login_required
@require_verified_email
def delete_entry(entry_id):
    if not get_vault_key():
        return jsonify({'error': 'Vault locked'}), 403

    entry = VaultEntry.query.filter_by(
        entry_id=entry_id, user_id=current_user.id
    ).first()
    if not entry:
        return jsonify({'error': 'Not found'}), 404

    db.session.delete(entry)
    db.session.commit()
    return jsonify({'message': 'Deleted'}), 200


#Search vault entries
@app.route('/api/vault/search', methods=['GET'])
@login_required
@require_verified_email
def search_entries():
    vault_key = get_vault_key()
    if not vault_key:
        return jsonify({'error': 'Vault locked'}), 403

    query = request.args.get('q', '').lower()[:255]
    entries = VaultEntry.query.filter_by(user_id=current_user.id).all()

    results = []
    for entry in entries:
        if query in entry.website.lower() or query in entry.username.lower():
            encrypted = json.loads(entry.encrypted_password)
            password = CryptManager.decrypt_data(encrypted, vault_key)
            results.append({
                'entry_id': entry.entry_id,
                'website': entry.website,
                'username': entry.username,
                'password': password,
                'notes': entry.notes
            })

    return jsonify({'entries': results}), 200

#CLEAR all VAULT ENTRIES
@app.route('/api/vault/clear', methods=['POST'])
@login_required
@require_verified_email
def clear_vault():
    if not get_vault_key():
        return jsonify({'error': 'Vault locked'}), 403

    data = request.get_json(silent=True) or {}
    password = data.get('master_password', '')
    try:
        ph.verify(current_user.master_password_hash, password)
    except (VerifyMismatchError, VerificationError):
        return jsonify({'error': 'Incorrect master password'}), 401

    VaultEntry.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    return jsonify({'message': 'Vault cleared'}), 200

#Route for generating passphrase
@app.route('/api/tools/generate-passphrase', methods=['POST'])
@login_required
def generate_passphrase():
    data = request.get_json(silent=True) or {}
    word_count = data.get('word_count', 4)
    separator = data.get('separator', '-')
    if (not isinstance(word_count, int) or not 3 <= word_count <= 8 or
            not isinstance(separator, str) or len(separator) > 3):
        return jsonify({'error': 'Invalid passphrase options'}), 400
    try:
        passphrase = generator.generate_passphrase(
            word_count=word_count,
            separator=separator,
            capitalize=bool(data.get('capitalize', True)),
            add_number=bool(data.get('add_number', True))
        )
    except ValueError:
        return jsonify({'error': 'Passphrase wordlist is not installed'}), 503
    analysis = analyzer.analyze_password(passphrase, include_ml=False)
    return jsonify({'passphrase': passphrase, 'analysis': analysis})

#Route for health audit
@app.route('/api/tools/health-audit', methods=['GET'])
@login_required
@require_verified_email
def health_audit():
    vault_key = get_vault_key()
    if not vault_key:
        return jsonify({'error': 'Vault locked'}), 403

    entries = VaultEntry.query.filter_by(user_id=current_user.id).all()
    results = []

    for entry in entries:
        encrypted = json.loads(entry.encrypted_password)
        password = CryptManager.decrypt_data(encrypted, vault_key)
        analysis = analyzer.analyze_password(password)  # ML included auto

        # Breach check
        is_breached = False
        if breach_checker.is_loaded:
            is_breached, _ = breach_checker.is_breached(password)

        results.append({
            'website': entry.website,
            'username': entry.username,
            'score': analysis['rule_based']['score'],
            'strength': analysis['combined_strength'],
            'is_breached': is_breached,            
            'ml_prediction': analysis.get('ml_based', {}).get('prediction') if analysis.get('ml_based') else None
        })

    avg = sum(r['score'] for r in results) / len(results) if results else 0
    weak = sum(1 for r in results if r['score'] < 40)
    breached = sum(1 for r in results if r['is_breached'])

    return jsonify({
        'average_score': round(avg, 1),
        'total': len(results),
        'weak_count': weak,
        'breached_count': breached,                
        'entries': results
    })

@app.route('/api/tools/breach-check', methods=['POST'])
@login_required
def check_breach():
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')

    if not isinstance(password, str) or not password:
        return jsonify({'error': 'Password is required'}), 400
    if len(password) > MAX_VAULT_PASSWORD_LENGTH:
        return jsonify({'error': 'Password is too long'}), 400

    if not breach_checker.is_loaded:
        return jsonify({
            'error': 'Breach database not available',
            'is_breached': False
        }), 503

    is_breached, breach_msg = breach_checker.is_breached(password)
    return jsonify({
        'is_breached': is_breached,
        'message': breach_msg,
        'dataset_size': breach_checker.total_passwords
    }), 200


@app.route('/api/auth/change-password', methods=['POST'])
@login_required
@limiter.limit("5 per hour")
def change_master_password():
    vault_key = get_vault_key()
    if not vault_key:
        return jsonify({'error': 'Vault locked'}), 403

    data = request.get_json(silent=True) or {}
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')

    if (not isinstance(current_password, str) or
            not isinstance(new_password, str) or
            not current_password or not new_password):
        return jsonify({'error': 'Both current and new passwords are required'}), 400
    if len(new_password) > MAX_MASTER_PASSWORD_LENGTH:
        return jsonify({'error': 'New password is too long'}), 400
    if current_password == new_password:
        return jsonify({'error': 'New password must be different'}), 400

    # Verify current password
    try:
        ph.verify(current_user.master_password_hash, current_password)
    except (VerifyMismatchError, VerificationError):
        return jsonify({'error': 'Current password is incorrect'}), 401

    # Analyze new password strength
    analysis = analyzer.analyze_password(new_password, include_ml=False)
    score = analysis['rule_based'].get('score', 0)

    # Check breach
    is_breached = False
    if breach_checker.is_loaded:
        result = breach_checker.is_breached(new_password)
        if result is not None:
            is_breached, _ = result

    if is_breached:
        return jsonify({
            'error': 'This password has been found in a data breach and cannot be used.',
            'is_breached': True,
            'score': score,
        }), 400

    if score < 30 or len(new_password) < 12:
        return jsonify({
            'error': 'Choose a stronger master password (at least 12 characters)',
            'is_breached': False,
            'score': score,
            'strength': analysis.get('combined_strength', 'WEAK'),
            'issues': analysis['rule_based'].get('issues', []),
        }), 400

    try:
        # Re-encrypt every stored password before changing the credentials.
        new_salt = CryptManager.generate_salt()
        new_vault_key = CryptManager.derive_key(new_password, new_salt)
        entries = VaultEntry.query.filter_by(user_id=current_user.id).all()
        for entry in entries:
            encrypted = json.loads(entry.encrypted_password)
            plaintext = CryptManager.decrypt_data(encrypted, vault_key)
            new_encrypted = CryptManager.encrypt_data(plaintext, new_vault_key)
            entry.encrypted_password = json.dumps(new_encrypted)

        current_user.master_password_hash = ph.hash(new_password)
        current_user.vault_salt = base64.b64encode(new_salt).decode('utf-8')
        new_verification = CryptManager.encrypt_data("passmetric_ok", new_vault_key)
        current_user.vault_verification = json.dumps(new_verification)
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Master password rotation failed for user %s", current_user.id)
        return jsonify({'error': 'Could not update master password'}), 500

    # Update session with new vault key
    clear_user_vault_keys(current_user.id)
    install_vault_key(current_user.id, new_vault_key)

    return jsonify({'message': 'Master password updated successfully'}), 200


@app.route('/api/tools/breach-check-vault', methods=['GET'])
@login_required
def check_vault_breaches():
    vault_key = get_vault_key()
    if not vault_key:
        return jsonify({'error': 'Vault locked'}), 403

    if not breach_checker.is_loaded:
        return jsonify({'error': 'Breach database not available'}), 503

    entries = VaultEntry.query.filter_by(user_id=current_user.id).all()
    results = []
    breached_count = 0

    for entry in entries:
        encrypted = json.loads(entry.encrypted_password)
        password = CryptManager.decrypt_data(encrypted, vault_key)
        is_breached, breach_msg = breach_checker.is_breached(password)

        if is_breached:
            breached_count += 1

        results.append({
            'entry_id': entry.entry_id,
            'website': entry.website,
            'username': entry.username,
            'is_breached': is_breached,
        })


    

    return jsonify({
        'total': len(results),
        'breached_count': breached_count,
        'entries': results,
        'dataset_size': breach_checker.total_passwords
    }), 200






def send_email_change_email(to_email, verify_url):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'PassMetric - Verify your new email'
    msg['From'] = SMTP_USER
    msg['To'] = to_email

    html = f"""
    <html><body style="font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 40px;">
        <div style="max-width: 480px; margin: auto;">
            <h2 style="color: #6366f1;">PassMetric</h2>
            <p>You requested to change your email address. Click the button below to confirm.</p>
            <a href="{verify_url}"
               style="display: inline-block; padding: 12px 28px; background: #6366f1;
                      color: white; text-decoration: none; border-radius: 8px;
                      font-weight: 600; margin: 20px 0;">
                Verify New Email
            </a>
            <p style="font-size: 13px; color: #94a3b8;">
                This link expires in 1 hour. If you didn't request this change, you can safely ignore this email.
            </p>
        </div>
    </body></html>
    """

    msg.attach(MIMEText(html, 'html'))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        print(f"[EMAIL] Email change verification sent to {to_email}")
    except Exception:
        app.logger.exception("Could not send email-change message to %s", to_email)


@app.route('/api/auth/delete-account', methods=['POST'])
@login_required
@limiter.limit("3 per hour")
def delete_account():
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')

    if not isinstance(password, str) or not password:
        return jsonify({'error': 'Password is required'}), 400

    try:
        ph.verify(current_user.master_password_hash, password)
    except (VerifyMismatchError, VerificationError):
        return jsonify({'error': 'Incorrect password'}), 401

    # Delete all vault entries then the user record
    VaultEntry.query.filter_by(user_id=current_user.id).delete()
    db.session.delete(current_user)
    db.session.commit()

    clear_user_vault_keys(current_user.id)
    session.clear()
    logout_user()

    return jsonify({'message': 'Account deleted'}), 200


@app.route('/api/auth/request-email-change', methods=['POST'])
@login_required
@limiter.limit("3 per hour")
def request_email_change():
    data = request.get_json(silent=True) or {}
    new_email = normalized_email(data.get('new_email'))
    password = data.get('password', '')

    if not new_email or not password:
        return jsonify({'error': 'New email and password are required'}), 400

    if not valid_email(new_email):
        return jsonify({'error': 'Invalid email address'}), 400

    if new_email == current_user.email:
        return jsonify({'error': 'New email is the same as your current email'}), 400

    # Verify master password
    try:
        ph.verify(current_user.master_password_hash, password)
    except (VerifyMismatchError, VerificationError):
        return jsonify({'error': 'Incorrect password'}), 401

    # Check email not already in use
    if User.query.filter_by(email=new_email).first():
        return jsonify({'error': 'Email address is already in use'}), 409

    token = email_serializer.dumps(
        {'user_id': current_user.id, 'new_email': new_email},
        salt='email-change'
    )
    current_user.pending_email = new_email
    current_user.pending_email_token = token_digest(token)
    db.session.commit()

    verify_url = f"{APP_URL}/verify-new-email?token={token}"
    send_email_change_email(new_email, verify_url)

    return jsonify({'message': f'Verification email sent to {new_email}. Click the link to confirm the change.'}), 200


@app.route('/verify-new-email')
def verify_new_email():
    token = request.args.get('token', '')

    try:
        payload = email_serializer.loads(token, salt='email-change', max_age=3600)
        user_id = payload['user_id']
        new_email = payload['new_email']
    except Exception:
        return '<h2>Invalid or expired verification link.</h2>', 400

    user = db.session.get(User, user_id)
    if (not user or not user.pending_email_token or
            not hmac.compare_digest(user.pending_email_token, token_digest(token))):
        return '<h2>Invalid or expired verification link.</h2>', 400

    if User.query.filter(User.email == new_email, User.id != user_id).first():
        return '<h2>That email address is already taken.</h2>', 409

    user.email = new_email
    user.email_verified = True
    user.pending_email = None
    user.pending_email_token = None
    db.session.commit()

    return  ''' <html><body style="font-family:sans-serif;background:#0f172a;color:#e2e8f0;
          display:flex;justify-content:center;align-items:center;height:100vh;">
        <div style="text-align:center;">
            <h2 style="color:#22c55e;">Email Updated!</h2>
            <p>Your email address has been changed successfully.</p>
            <a href="/" style="color:#6366f1;">Go to login</a>
        </div>
    </body></html>
    '''


if __name__ == '__main__':
    app.run(debug=env_flag('FLASK_DEBUG'), port=5000)
