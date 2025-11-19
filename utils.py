from datetime import datetime, timedelta
import jwt
import bcrypt
from functools import wraps
from flask import request, jsonify

from bson.objectid import ObjectId
from datetime import datetime
import json

def to_json_serializable(obj):
    """Convert MongoDB documents to JSON-serializable format"""
    if isinstance(obj, ObjectId):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {key: to_json_serializable(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [to_json_serializable(item) for item in obj]
    return obj

def generate_jwt(user_id, secret_key):
    return jwt.encode({'user_id': str(user_id), 'exp': datetime.utcnow() + timedelta(hours=24)}, secret_key, algorithm='HS256')

def decode_jwt(token, secret_key):
    try:
        return jwt.decode(token, secret_key, algorithms=['HS256'])
    except:
        return None

def auth_required(secret_key):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.headers.get('Authorization')
            if not token:
                return jsonify({'error': 'Unauthorized'}), 401
            data = decode_jwt(token.split(' ')[1] if ' ' in token else token, secret_key)
            if not data:
                return jsonify({'error': 'Invalid token'}), 401
            request.user_id = data['user_id']
            return f(*args, **kwargs)
        return wrapper
    return decorator

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(hashed, password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))