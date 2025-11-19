# routes/auth.py — FINAL 100% WORKING VERSION (LOGIN FIXED + FORGOT PASSWORD + RESET)
from flask import Blueprint, request, jsonify, redirect, session, current_app, url_for
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

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")

auth_bp = Blueprint('auth', __name__)

# Google OAuth
flow = Flow.from_client_secrets_file(
    'client_secrets.json',
    scopes=['https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile', 'openid'],
    redirect_uri='http://localhost:5000/api/auth/google/callback'
)

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

def secure_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
        app = current_app._get_current_object()
        if token in app.blacklisted_tokens:
            return jsonify({'error': 'Session expired'}), 401
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user_id = str(payload['user_id'])
        except:
            return jsonify({'error': 'Invalid or expired token'}), 401
        return f(*args, **kwargs)
    return decorated

def register_routes(app, mongo, config):
    users = mongo.db.users
    app.blacklisted_tokens = set()

    # ==================== GOOGLE LOGIN (same as before) ====================
    @auth_bp.route('/google')
    def google_login():
        if request.args.get('from_register') == '1':
            session['from_register'] = True
        else:
            session.pop('from_register', None)
        auth_url, state = flow.authorization_url(prompt='consent')
        session['state'] = state
        return redirect(auth_url)

    @auth_bp.route('/google/callback')
    def google_callback():
        try:
            flow.fetch_token(authorization_response=request.url)
            credentials = flow.credentials
            service = build('oauth2', 'v2', credentials=credentials)
            info = service.userinfo().get().execute()
            email = info['email'].lower()

            user = users.find_one({'email': email})
            if user:
                if session.get('from_register'):
                    session.pop('from_register', None)
                    session['flash_message'] = 'You already have an account!'
                    return redirect('/login')
                token = generate_jwt(str(user['_id']), config.SECRET_KEY)
                return f"""
                <script>
                    localStorage.setItem('token', '{token}');
                    localStorage.setItem('userName', '{info.get('name', 'User')}');
                    location.href = '/dashboard';
                </script>
                """
            else:
                user_id = users.insert_one({
                    'email': email,
                    'name': info.get('name', 'User'),
                    'email_verified': True,
                    'created_at': datetime.utcnow(),
                    'google_auth': True,
                    'plan': 'free',
                    'max_projects': 2,
                    'current_projects': 0
                }).inserted_id
                token = generate_jwt(str(user_id), config.SECRET_KEY)
                return f"""
                <script>
                    localStorage.setItem('token', '{token}');
                    localStorage.setItem('userName', '{info.get('name', 'User')}');
                    alert('Account created with Google!');
                    location.href = '/dashboard';
                </script>
                """
        except Exception as e:
            print("Google Error:", e)
            return redirect('/login')

    # ==================== REGISTER & VERIFY (same) ====================
    @auth_bp.route('/register', methods=['POST'])
    def register_step1():
        data = request.json
        email = data.get('email', '').lower().strip()
        name = data.get('name', '').strip()
        password = data.get('password', '')

        if not all([email, name, password]):
            return jsonify({'error': 'All fields required'}), 400
        if users.find_one({'email': email}):
            return jsonify({'error': 'Email already exists'}), 400

        otp = random.randint(100000, 999999)
        pending_registrations[email] = {
            'name': name, 'password': password, 'otp': otp, 'time': datetime.utcnow()
        }

        if send_email(email, "Your OTP - MockAPI Pro", f"<h2>Your OTP is: <b>{otp}</b></h2><p>Valid for 5 minutes.</p>"):
            return jsonify({'message': 'OTP sent!'})
        return jsonify({'error': 'Failed to send OTP'}), 500

    @auth_bp.route('/verify-registration', methods=['POST'])
    def verify_otp():
        data = request.json
        email = data.get('email', '').lower().strip()
        otp = data.get('otp')
        reg = pending_registrations.get(email)

        if not reg or (datetime.utcnow() - reg['time']) > timedelta(minutes=5):
            if email in pending_registrations: del pending_registrations[email]
            return jsonify({'error': 'OTP expired!'}), 400
        if str(reg['otp']) != str(otp):
            return jsonify({'error': 'Invalid OTP!'}), 400

        user_id = users.insert_one({
            'email': email,
            'password_hash': hash_password(reg['password']),
            'name': reg['name'],
            'email_verified': True,
            'created_at': datetime.utcnow(),
            'plan': 'free',
            'max_projects': 2,
            'current_projects': 0
        }).inserted_id

        del pending_registrations[email]
        token = generate_jwt(str(user_id), config.SECRET_KEY)
        return jsonify({'token': token})

    # ==================== LOGIN — AB 100% WORKING ====================
    @auth_bp.route('/login', methods=['POST'])
    def login():
        data = request.json
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')

        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400

        user = users.find_one({'email': email})
        if user and check_password(user.get('password_hash'), password):
            token = generate_jwt(str(user['_id']), config.SECRET_KEY)
            return jsonify({
                'token': token,
                'message': 'Login successful'
            })
        return jsonify({'error': 'Invalid email or password'}), 401

    # ==================== LOGOUT ====================
    @auth_bp.route('/logout', methods=['POST'])
    def logout():
        token = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
        if token:
            app.blacklisted_tokens.add(token)
        return jsonify({'message': 'Logged out successfully'})

    # ==================== FORGOT PASSWORD ====================
    @auth_bp.route('/forgot-password', methods=['POST'])
    def forgot_password():
        data = request.json
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

        reset_link = f"http://localhost:5000/reset-password?token={reset_token}"
        html = f"""
        <h2>Reset Your Password</h2>
        <p>Click below to reset:</p>
        <a href="{reset_link}" style="padding:10px 20px;background:#4f46e5;color:white;border-radius:8px;text-decoration:none;">
            Reset Password
        </a>
        <p>Link expires in 1 hour.</p>
        """

        if send_email(email, "Password Reset - MockAPI Pro", html):
            return jsonify({'message': 'Password reset link sent!'})
        return jsonify({'error': 'Failed to send email'}), 500

    # ==================== RESET PASSWORD PAGE & ENDPOINT ====================
    @app.route('/reset-password')
    def reset_page():
        token = request.args.get('token')
        if not token or token not in password_resets:
            return "<h3>Invalid or expired link!</h3>"
        return f"""
        <!DOCTYPE html>
        <html>
        <head><script src="https://cdn.tailwindcss.com"></script></head>
        <body class="bg-gradient-to-br from-blue-50 to-purple-50 min-h-screen flex items-center justify-center">
            <div class="bg-white p-8 rounded-xl shadow-2xl w-96">
                <h2 class="text-2xl font-bold text-center mb-6">Set New Password</h2>
                <input type="password" id="pass" placeholder="New Password" class="w-full p-3 border rounded-lg mb-4">
                <input type="password" id="confirm" placeholder="Confirm Password" class="w-full p-3 border rounded-lg mb-6">
                <button onclick="reset()" class="w-full bg-indigo-600 text-white py-3 rounded-lg font-bold">Update</button>
                <p id="msg" class="text-center mt-4"></p>
            </div>
            <script>
                async function reset() {{
                    const p1 = document.getElementById('pass').value;
                    const p2 = document.getElementById('confirm').value;
                    if (p1 !== p2) return document.getElementById('msg').innerHTML = "Passwords don't match!";
                    if (p1.length < 6) return document.getElementById('msg').innerHTML = "Too short!";
                    const res = await fetch('/api/auth/reset-password', {{ method: 'POST', headers: {{'Content-Type':'application/json'}}, body: JSON.stringify({{token: '{token}', password: p1}}) }});
                    const d = await res.json();
                    document.getElementById('msg').innerHTML = d.message ? "<span style='color:green'>"+d.message+"</span>" : "<span style='color:red'>"+(d.error||"Error")+"</span>";
                    if (d.message) setTimeout(()=>location.href='/login',2000);
                }}
            </script>
        </body>
        </html>
        """

    @auth_bp.route('/reset-password', methods=['POST'])
    def reset_password():
        data = request.json
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
        return jsonify({'message': 'Password updated! Redirecting...'})

    # ==================== FINAL SETUP ====================
    app.secure_auth = secure_auth
    app.register_blueprint(auth_bp, url_prefix='/api/auth')