# routes/auth.py → FINAL BULLETPROOF VERSION (Database Token + No Session Expired!)
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

# Global Google Flow
_google_flow = None

def get_google_flow():
    global _google_flow
    if _google_flow is None:
        client_id = os.getenv("GOOGLE_CLIENT_ID")
        client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
        redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")
        if not all([client_id, client_secret, redirect_uri]):
            print("Google OAuth env vars missing!")
            return None
        _google_flow = Flow.from_client_config(
            {"web": {
                "client_id": client_id,
                "client_secret": client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [redirect_uri]
            }},
            scopes=["https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile", "openid"],
            redirect_uri=redirect_uri
        )
    return _google_flow

# In-memory for demo (use Redis in production)
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

# SECURE AUTH DECORATOR (JWT + Database Blacklist)
def secure_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
        if not token:
            return jsonify({'error': 'Token missing'}), 401

        # Check if token is blacklisted (logged out)
        if mongo.db.revoked_tokens.find_one({'token': token}):
            return jsonify({'error': 'Token revoked'}), 401

        try:
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user_id = str(payload['user_id'])
            return f(*args, **kwargs)
        except:
            return jsonify({'error': 'Invalid token'}), 401
    return decorated

def register_routes(app, mongo, config):
    users = mongo.db.users
    tokens_col = mongo.db.active_tokens     # ← NEW: Store active tokens
    revoked_col = mongo.db.revoked_tokens   # ← NEW: Blacklisted tokens

    # ===================== GOOGLE OAUTH =====================
    @auth_bp.route('/google')
    def google_login():
        flow = get_google_flow()
        if not flow: return "Google OAuth not configured", 500
        if request.args.get('from_register') == '1':
            session['from_register'] = True
        auth_url, state = flow.authorization_url(access_type='offline', prompt='consent')
        session['state'] = state
        return redirect(auth_url)

    @auth_bp.route('/google/callback')
    def google_callback():
        flow = get_google_flow()
        if not flow: return redirect('/login')
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
                    return redirect('/login')
                user_id = str(user['_id'])
            else:
                result = users.insert_one({
                    'email': email, 'name': name, 'email_verified': True,
                    'created_at': datetime.utcnow(), 'google_auth': True,
                    'plan': 'free', 'max_projects': 2, 'current_projects': 0
                })
                user_id = str(result.inserted_id)

            token = generate_jwt(user_id, config.SECRET_KEY)
            # SAVE TOKEN IN DATABASE
            tokens_col.insert_one({
                'token': token,
                'user_id': user_id,
                'created_at': datetime.utcnow(),
                'expires_at': datetime.utcnow() + timedelta(days=30)
            })

            return f"""
            <script>
                localStorage.setItem('token', '{token}');
                localStorage.setItem('userName', '{name}');
                location.href = '/dashboard';
            </script>
            """
        except Exception as e:
            print("Google Error:", e)
            return redirect('/login')

    # ===================== REGISTER + OTP =====================
    @auth_bp.route('/register', methods=['POST'])
    def register():
        data = request.get_json() or {}
        email = data.get('email', '').lower().strip()
        name = data.get('name', '').strip()
        password = data.get('password', '')
        if not all([email, name, password]) or len(password) < 3:
            return jsonify({'error': 'Invalid data'}), 400
        if users.find_one({'email': email}):
            return jsonify({'error': 'Email exists'}), 400

        otp = random.randint(100000, 999999)
        pending_registrations[email] = {'name': name, 'password': password, 'otp': otp, 'time': datetime.utcnow()}
        if send_email(email, "MockAPI Pro - OTP", f"<h2>OTP: <b>{otp}</b></h2>"):
            return jsonify({'message': 'OTP sent'})
        return jsonify({'error': 'Email failed'}), 500

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
            'email': email, 'name': reg['name'], 'password_hash': hash_password(reg['password']),
            'email_verified': True, 'created_at': datetime.utcnow(),
            'plan': 'free', 'max_projects': 2, 'current_projects': 0
        }).inserted_id

        token = generate_jwt(str(user_id), config.SECRET_KEY)
        tokens_col.insert_one({'token': token, 'user_id': str(user_id), 'created_at': datetime.utcnow()})
        pending_registrations.pop(email, None)
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
            # SAVE TOKEN IN DB
            tokens_col.insert_one({
                'token': token,
                'user_id': str(user['_id']),
                'created_at': datetime.utcnow(),
                'expires_at': datetime.utcnow() + timedelta(days=30)
            })
            return jsonify({'token': token})
        return jsonify({'error': 'Invalid credentials'}), 401

    # ===================== LOGOUT =====================
    @auth_bp.route('/logout', methods=['POST'])
    @secure_auth
    def logout():
        token = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
        if token:
            # Move to revoked list
            revoked_col.insert_one({'token': token, 'revoked_at': datetime.utcnow()})
            tokens_col.delete_one({'token': token})
        return jsonify({'message': 'Logged out'})

    # ===================== CURRENT USER INFO =====================
    @auth_bp.route('/me', methods=['GET'])
    @secure_auth
    def me():
        user = users.find_one({'_id': ObjectId(request.user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({
            'name': user.get('name', 'User'),
            'email': user['email'],
            'plan': user.get('plan', 'free')
        })

    # Register everything
    app.secure_auth = secure_auth
    app.register_blueprint(auth_bp, url_prefix='/api/auth')