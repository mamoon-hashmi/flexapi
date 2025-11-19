# routes/auth.py → FINAL VERCEL + PRODUCTION READY (NO JSON FILE!)
from flask import Blueprint, request, jsonify, redirect, session, current_app
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import random
import smtplib
from email.mime.text import MIMEText
from config import Config
from utils import generate_jwt, hash_password, check_password
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from functools import wraps
import os
import uuid

auth_bp = Blueprint('auth', __name__)

# Global flow - lazy loaded
_google_flow = None

def get_google_flow():
    """Create Google OAuth flow using only environment variables"""
    global _google_flow
    if _google_flow is None:
        client_id = os.getenv("GOOGLE_CLIENT_ID")
        client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
        redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")

        if not all([client_id, client_secret, redirect_uri]):
            print("Google OAuth env vars missing!")
            return None

        _google_flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [redirect_uri]
                }
            },
            scopes=[
                "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/userinfo.profile",
                "openid"
            ],
            redirect_uri=redirect_uri
        )
    return _google_flow

# In-memory storage (for demo, use Redis in real app)
pending_registrations = {}
password_resets = {}

def send_email(to_email, subject, html_body):
    try:
        msg = MIMEText(html_body, 'html')
        msg['Subject'] = subject
        msg['From'] = Config.SMTP_EMAIL
        msg['To'] = to_email
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(Config.SMTP_EMAIL, Config.SMTP_APP_PASSWORD)
            server.sendmail(Config.SMTP_EMAIL, to_email, msg.as_string())
        return True
    except Exception as e:
        print("SMTP Error:", e)
        return False

def secure_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
        app = current_app._get_current_object()
        if token in getattr(app, 'blacklisted_tokens', set()):
            return jsonify({'error': 'Token revoked'}), 401
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user_id = str(payload['user_id'])
        except:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

def register_routes(app, mongo, config):
    users = mongo.db.users
    app.blacklisted_tokens = set()

    # ===================== GOOGLE OAUTH =====================
    @auth_bp.route('/google')
    def google_login():
        flow = get_google_flow()
        if not flow:
            return "Google OAuth not configured", 500

        if request.args.get('from_register') == '1':
            session['from_register'] = True

        auth_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        session['state'] = state
        return redirect(auth_url)

    @auth_bp.route('/google/callback')
    def google_callback():
        flow = get_google_flow()
        if not flow:
            return redirect('/login?error=oauth')

        try:
            flow.fetch_token(authorization_response=request.url)
            credentials = flow.credentials
            service = build('oauth2', 'v2', credentials=credentials)
            info = service.userinfo().get().execute()

            email = info['email'].lower()
            name = info.get('name', email.split('@')[0])

            user = users.find_one({'email': email})

            if user:
                if session.pop('from_register', None):
                    return redirect('/login?flash=You already have an account!')
                token = generate_jwt(str(user['_id']), config.SECRET_KEY)
            else:
                result = users.insert_one({
                    'email': email,
                    'name': name,
                    'email_verified': True,
                    'created_at': datetime.utcnow(),
                    'google_auth': True,
                    'plan': 'free',
                    'max_projects': 2,
                    'current_projects': 0
                })
                token = generate_jwt(str(result.inserted_id), config.SECRET_KEY)

            return f"""
            <script>
                localStorage.setItem('token', '{token}');
                localStorage.setItem('userName', '{name}');
                location.href = '/dashboard';
            </script>
            """
        except Exception as e:
            print("Google OAuth Error:", e)
            return redirect('/login?error=google_failed')

    # ===================== REGISTER + OTP =====================
    @auth_bp.route('/register', methods=['POST'])
    def register():
        data = request.get_json() or {}
        email = data.get('email', '').lower().strip()
        name = data.get('name', '').strip()
        password = data.get('password', '')

        if not all([email, name, password]) or len(password) < 6:
            return jsonify({'error': 'Invalid data'}), 400
        if users.find_one({'email': email}):
            return jsonify({'error': 'Email already exists'}), 400

        otp = random.randint(100000, 999999)
        pending_registrations[email] = {
            'name': name,
            'password': password,
            'otp': otp,
            'time': datetime.utcnow()
        }

        html = f"""
        <div style="font-family:Arial;text-align:center;padding:40px;background:#f8fafc;">
          <h1 style="color:#6366f1">MockAPI Pro</h1>
          <h2>Verify Your Email</h2>
          <p style="font-size:36px;letter-spacing:8px;color:#1d4ed8"><b>{otp}</b></p>
          <p>Valid for 5 minutes</p>
        </div>
        """

        if send_email(email, "Your MockAPI Pro OTP", html):
            return jsonify({'message': 'OTP sent!'})
        return jsonify({'error': 'Failed to send OTP'}), 500

    @auth_bp.route('/verify-registration', methods=['POST'])
    def verify_otp():
        data = request.get_json() or {}
        email = data.get('email', '').lower()
        otp = data.get('otp', '')

        reg = pending_registrations.get(email)
        if not reg or (datetime.utcnow() - reg['time']) > timedelta(minutes=5):
            pending_registrations.pop(email, None)
            return jsonify({'error': 'OTP expired'}), 400
        if str(reg['otp']) != str(otp):
            return jsonify({'error': 'Invalid OTP'}), 400

        user_id = users.insert_one({
            'email': email,
            'name': reg['name'],
            'password_hash': hash_password(reg['password']),
            'email_verified': True,
            'created_at': datetime.utcnow(),
            'plan': 'free',
            'max_projects': 2,
            'current_projects': 0
        }).inserted_id

        pending_registrations.pop(email, None)
        token = generate_jwt(str(user_id), config.SECRET_KEY)
        return jsonify({'token': token})

    # ===================== LOGIN =====================
    @auth_bp.route('/login', methods=['POST'])
    def login():
        data = request.get_json() or {}
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')

        user = users.find_one({'email': email})
        if user and check_password(user.get('password_hash'), password):
            token = generate_jwt(str(user['_id']), config.SECRET_KEY)
            return jsonify({'token': token})
        return jsonify({'error': 'Invalid email or password'}), 401

    # ===================== LOGOUT =====================
    @auth_bp.route('/logout', methods=['POST'])
    @secure_auth
    def logout():
        token = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
        if token:
            app.blacklisted_tokens.add(token)
        return jsonify({'message': 'Logged out'})

    # ===================== FORGOT PASSWORD =====================
    @auth_bp.route('/forgot-password', methods=['POST'])
    def forgot_password():
        data = request.get_json() or {}
        email = data.get('email', '').lower().strip()
        if not email:
            return jsonify({'error': 'Email required'}), 400

        user = users.find_one({'email': email})
        if not user:
            return jsonify({'message': 'If email exists, reset link sent!'})

        token = str(uuid.uuid4())
        password_resets[token] = {
            'email': email,
            'expires_at': datetime.utcnow() + timedelta(hours=1)
        }

        reset_link = f"{request.url_root[:-1]}reset-password?token={token}"
        html = f"""
        <div style="font-family:Arial;text-align:center;padding:40px;background:#f8fafc;">
          <h1 style="color:#6366f1">MockAPI Pro</h1>
          <h2>Password Reset</h2>
          <a href="{reset_link}" style="padding:14px 32px;background:#4f46e5;color:white;border-radius:8px;text-decoration:none;">
            Reset Password
          </a>
          <p>Link expires in 1 hour</p>
        </div>
        """

        if send_email(email, "Reset Your Password", html):
            return jsonify({'message': 'Reset link sent!'})
        return jsonify({'error': 'Email failed'}), 500

    # ===================== RESET PASSWORD =====================
    @auth_bp.route('/reset-password', methods=['POST'])
    def reset_password():
        data = request.get_json() or {}
        token = data.get('token')
        password = data.get('password')

        if not token or token not in password_resets:
            return jsonify({'error': 'Invalid token'}), 400
        if len(password) < 6:
            return jsonify({'error': 'Password too short'}), 400

        info = password_resets[token]
        if datetime.utcnow() > info['expires_at']:
            password_resets.pop(token, None)
            return jsonify({'error': 'Token expired'}), 400

        users.update_one(
            {'email': info['email']},
            {'$set': {'password_hash': hash_password(password)}}
        )
        password_resets.pop(token, None)
        return jsonify({'message': 'Password updated!'})

    # Register blueprint
    app.secure_auth = secure_auth
    app.register_blueprint(auth_bp, url_prefix='/api/auth')