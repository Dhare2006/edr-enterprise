"""
JWT Authentication Module
"""
import jwt
import os
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'edr-super-secret-key-change-in-production')
REFRESH_SECRET_KEY = os.environ.get('REFRESH_SECRET_KEY', 'edr-refresh-secret-key')

def generate_access_token(user_id: int, username: str, email: str) -> str:
    """Generate short-lived access token (15 minutes)"""
    payload = {
        'user_id': user_id,
        'username': username,
        'email': email,
        'exp': datetime.utcnow() + timedelta(minutes=15),
        'iat': datetime.utcnow(),
        'type': 'access'
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def generate_refresh_token(user_id: int) -> str:
    """Generate long-lived refresh token (7 days)"""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=7),
        'iat': datetime.utcnow(),
        'type': 'refresh'
    }
    return jwt.encode(payload, REFRESH_SECRET_KEY, algorithm='HS256')

def verify_token(token: str, token_type: str = 'access') -> dict:
    """Verify and decode JWT token"""
    try:
        secret = SECRET_KEY if token_type == 'access' else REFRESH_SECRET_KEY
        payload = jwt.decode(token, secret, algorithms=['HS256'])
        if payload.get('type') != token_type:
            return None
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return jsonify({'error': 'Authorization header missing'}), 401
        
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Invalid token format'}), 401
        
        token = auth_header[7:]
        payload = verify_token(token)
        
        if not payload:
            return jsonify({'error': 'Token is invalid or expired'}), 401
        
        request.user_id = payload['user_id']
        request.username = payload['username']
        request.user_email = payload['email']
        
        return f(*args, **kwargs)
    return decorated