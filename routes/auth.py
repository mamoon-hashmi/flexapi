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
import jwt
import uuid

auth_bp = Blueprint('auth', __name__)

# GOOGLE OAUTH — ONLY FROM ENV (NO client_secrets.json!)
def get_google_flow():
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")  # https://objexapi.vercel.app/api/auth/google/callback

    if not all([client_id, client_secret, redirect_uri]):
        print("Google OAuth env vars missing!")
        return None

    return Flow.from_client_config(
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

# In-memory storage (demo only)
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
        print("Email Error:", e)
        return False

def register_routes(app, mongo, config):
    users = mongo.db.users
    app.blacklisted_tokens = set()  # Memory blacklist (restart pe clear ho jayega)

    # Secure decorator
    def secure_auth(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
            if token in app.blacklisted_tokens:
                return jsonify({'error': 'Session expired'}), 401
            try:
                payload = jwt.decode(token, config.SECRET_KEY, algorithms=['HS256'])
                request.user_id = str(payload['user_id'])
            except:
                return jsonify({'error': 'Invalid token'}), 401
            return f(*args, **kwargs)
        return decorated

    # GOOGLE LOGIN
    @auth_bp.route('/google')
    def google_login():
        flow = get_google_flow()
        if not flow:
            return "Google OAuth not configured", 500
        auth_url, state = flow.authorization_url(prompt='consent')
        session['state'] = state
        return redirect(auth_url)

    @auth_bp.route('/google/callback')
    def google_callback():
        flow = get_google_flow()
        if not flow:
            return redirect('/login')
        try:
            flow.fetch_token(authorization_response=request.url)
            credentials = flow.credentials
            service = build('oauth2', 'v2', credentials=credentials)
            info = service.userinfo().get().execute()

            email = info['email'].lower()
            name = info.get('name', email.split('@')[0])

            user = users.find_one({'email': email})
            if user:
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
            print("Google Error:", e)
            return redirect('/login')

    # REGISTER + OTP
    @auth_bp.route('/register', methods=['POST'])
    def register():
        data = request.get_json() or {}
        email = data.get('email', '').lower().strip()
        name = data.get('name', '').strip()
        password = data.get('password', '')

        if not all([email, name, password]) or len(password) < 6:
            return jsonify({'error': 'Invalid data'}), 400
        if users.find_one({'email': email}):
            return jsonify({'error': 'Email exists'}), 400

        otp = random.randint(100000, 999999)
        pending_registrations[email] = {
            'name': name, 'password': password, 'otp': otp, 'time': datetime.utcnow()
        }

        if send_email(email, "MockAPI Pro - OTP", f"<h2>OTP: <b>{otp}</b></h2>"):
            return jsonify({'message': 'OTP sent'})
        return jsonify({'error': 'Email failed'}), 500

    @auth_bp.route('/verify-registration', methods=['POST'])
    def verify_otp():
        data = request.get_json() or {}
        email = data.get('email', '').lower()
        otp = data.get('otp')
        reg = pending_registrations.get(email)

        if not reg or (datetime.utcnow() - reg['time']) > timedelta(minutes=5):
            pending_registrations.pop(email, None)
            return jsonify({'error': 'OTP expired'}), 400
        if str(reg['otp']) != str(otp):
            return jsonify({'error': 'Wrong OTP'}), 400

        user_id = users.insert_one({
            'email': email, 'name': reg['name'],
            'password_hash': hash_password(reg['password']),
            'email_verified': True, 'created_at': datetime.utcnow(),
            'plan': 'free', 'max_projects': 2, 'current_projects': 0
        }).inserted_id

        token = generate_jwt(str(user_id), config.SECRET_KEY)
        pending_registrations.pop(email, None)
        return jsonify({'token': token})

    # LOGIN
    @auth_bp.route('/login', methods=['POST'])
    def login():
        data = request.get_json() or {}
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        user = users.find_one({'email': email})

        if user and check_password(user.get('password_hash'), password):
            token = generate_jwt(str(user['_id']), config.SECRET_KEY)
            return jsonify({'token': token})
        return jsonify({'error': 'Invalid credentials'}), 401

    # LOGOUT
    @auth_bp.route('/logout', methods=['POST'])
    @secure_auth
    def logout():
        token = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
        if token:
            app.blacklisted_tokens.add(token)
        return jsonify({'message': 'Logged out'})

    # FORGOT PASSWORD
    @auth_bp.route('/forgot-password', methods=['POST'])
    def forgot_password():
        data = request.get_json() or {}
        email = data.get('email', '').lower().strip()
        if not email:
            return jsonify({'error': 'Email required'}), 400

        user = users.find_one({'email': email})
        if not user:
            return jsonify({'message': 'If email exists, reset link sent!'})

        reset_token = str(uuid.uuid4())
        password_resets[reset_token] = {
            'email': email,
            'expires_at': datetime.utcnow() + timedelta(hours=1)
        }

        reset_link = f"{request.url_root}reset-password?token={reset_token}"
        html = f"""
        <div style="font-family:Arial;text-align:center;padding:40px;">
          <h1>MockAPI Pro</h1>
          <h2>Reset Your Password</h2>
          <a href="{reset_link}" style="background:#4f46e5;color:white;padding:14px 32px;border-radius:8px;text-decoration:none;">
            Reset Password
          </a>
          <p>Link expires in 1 hour</p>
        </div>
        """

        if send_email(email, "Reset Password", html):
            return jsonify({'message': 'Reset link sent!'})
        return jsonify({'error': 'Email failed'}), 500

    # RESET PASSWORD API
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
            del password_resets[token]
            return jsonify({'error': 'Token expired'}), 400

        users.update_one(
            {'email': info['email']},
            {'$set': {'password_hash': hash_password(password)}}
        )
        del password_resets[token]
        return jsonify({'message': 'Password updated!'})

    # RESET PASSWORD PAGE — OUTSIDE BLUEPRINT (TERA TEMPLATE)
    @app.route('/reset-password')
    def reset_password_page():
        token = request.args.get('token')
        return render_template('reset_password.html', token=token)

    # ME ENDPOINT
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

    # Register blueprint
    app.secure_auth = secure_auth
    app.register_blueprint(auth_bp, url_prefix='/api/auth')