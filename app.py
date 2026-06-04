"""
EDR LITE - Enterprise Endpoint Detection & Response
Complete secure application
"""
from flask import Flask, render_template, request, jsonify, session, g
from flask_cors import CORS
from flask_talisman import Talisman
from datetime import datetime
import os
import json

# Security modules
from src.security.encryption import hash_password, verify_password
from src.security.jwt_auth import (generate_access_token, generate_refresh_token, 
                                   verify_token, token_required)
from src.security.rate_limiter import limiter, track_failed_attempt, is_ip_blocked
from src.security.validator import (validate_email, validate_password, 
                                   validate_username, sanitize_input)
from src.security.audit import log_event, log_login, log_api_access
from src.models import users_db, threats_db
from src.monitor.engine import start_monitoring, get_threats, clear_threats

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'super-secret-key')

# Security middleware
CORS(app, resources={r"/api/*": {"origins": "*"}})
Talisman(app, 
    content_security_policy={
        'default-src': "'self'",
        'script-src': ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net"],
        'style-src': ["'self'", "'unsafe-inline'"],
    },
    force_https=False
)

# Rate limiter
limiter.init_app(app)

# Store refresh tokens (use Redis in production)
refresh_tokens = {}

# ==================== INITIALIZE ADMIN ====================
def init_admin():
    """Create default admin user if not exists"""
    if 'admin@edr.com' not in users_db:
        users_db['admin@edr.com'] = {
            'id': 1,
            'username': 'admin',
            'email': 'admin@edr.com',
            'password_hash': hash_password('Admin@123'),
            'is_admin': True,
            'is_active': True,
            'created_at': datetime.utcnow().isoformat()
        }
        print("✅ Admin user created: admin@edr.com / Admin@123")

# ==================== ROUTES ====================

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/register', methods=['POST'])
@limiter.limit("3 per hour")
def register():
    """User registration with validation"""
    data = request.get_json()
    
    email = data.get('email', '').lower()
    username = data.get('username', '')
    password = data.get('password', '')
    invite_code = data.get('invite_code', '')
    
    # Validate invite code
    if invite_code != "EDR2024":
        return jsonify({'error': 'Invalid invite code'}), 403
    
    # Validate email
    if not validate_email(email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    # Validate username
    valid, msg = validate_username(username)
    if not valid:
        return jsonify({'error': msg}), 400
    
    # Validate password
    valid, msg = validate_password(password)
    if not valid:
        return jsonify({'error': msg}), 400
    
    # Check if user exists
    if email in users_db:
        return jsonify({'error': 'Email already registered'}), 409
    
    # Create user
    users_db[email] = {
        'id': len(users_db) + 1,
        'username': sanitize_input(username),
        'email': email,
        'password_hash': hash_password(password),
        'is_admin': False,
        'is_active': True,
        'created_at': datetime.utcnow().isoformat()
    }
    
    log_event('USER_REGISTERED', email, {'username': username}, request.remote_addr)
    
    return jsonify({'message': 'Registration successful! Please login.'}), 201

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    """User login with JWT token"""
    data = request.get_json()
    email = data.get('email', '').lower()
    password = data.get('password', '')
    ip = request.remote_addr
    
    # Check if IP is blocked
    if is_ip_blocked(ip):
        return jsonify({'error': 'Too many failed attempts. Try again later.'}), 429
    
    # Validate email
    if not validate_email(email):
        track_failed_attempt(ip)
        log_login(email, False, ip, 'invalid_email')
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Check user
    user = users_db.get(email)
    if not user or not verify_password(password, user['password_hash']):
        track_failed_attempt(ip)
        log_login(email, False, ip, 'invalid_password')
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Check if user is active
    if not user.get('is_active', True):
        return jsonify({'error': 'Account is disabled'}), 403
    
    # Generate tokens
    access_token = generate_access_token(user['id'], user['username'], user['email'])
    refresh_token = generate_refresh_token(user['id'])
    
    # Store refresh token
    refresh_tokens[refresh_token] = user['id']
    
    log_login(email, True, ip, 'success')
    
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'Bearer',
        'expires_in': 900,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'is_admin': user.get('is_admin', False)
        }
    })

@app.route('/api/refresh', methods=['POST'])
def refresh():
    """Refresh access token"""
    data = request.get_json()
    refresh_token = data.get('refresh_token')
    
    if not refresh_token or refresh_token not in refresh_tokens:
        return jsonify({'error': 'Invalid refresh token'}), 401
    
    payload = verify_token(refresh_token, 'refresh')
    if not payload:
        return jsonify({'error': 'Refresh token expired'}), 401
    
    user_id = payload['user_id']
    user = next((u for u in users_db.values() if u['id'] == user_id), None)
    
    if not user:
        return jsonify({'error': 'User not found'}), 401
    
    # Generate new access token
    new_access_token = generate_access_token(user['id'], user['username'], user['email'])
    
    return jsonify({
        'access_token': new_access_token,
        'expires_in': 900
    })

@app.route('/api/logout', methods=['POST'])
@token_required
def logout():
    """Logout and invalidate tokens"""
    data = request.get_json()
    refresh_token = data.get('refresh_token')
    
    if refresh_token and refresh_token in refresh_tokens:
        del refresh_tokens[refresh_token]
    
    log_event('USER_LOGOUT', request.user_email, {}, request.remote_addr)
    
    return jsonify({'message': 'Logged out successfully'})

@app.route('/api/threats', methods=['GET'])
@token_required
@limiter.limit("30 per minute")
def get_threats_api():
    """Get detected threats"""
    log_api_access(request.user_email, '/api/threats', 'GET', request.remote_addr)
    
    threats = get_threats()
    return jsonify({'threats': threats, 'total': len(threats)})

@app.route('/api/stats', methods=['GET'])
@token_required
def get_stats():
    """Get dashboard statistics"""
    threats = get_threats()
    
    stats = {
        'total': len(threats),
        'critical': len([t for t in threats if t['severity'] == 'CRITICAL']),
        'high': len([t for t in threats if t['severity'] == 'HIGH']),
        'medium': len([t for t in threats if t['severity'] == 'MEDIUM']),
        'unique_processes': len(set([t['process_name'] for t in threats]))
    }
    
    return jsonify(stats)

@app.route('/api/threats/clear', methods=['POST'])
@token_required
def clear_threats_api():
    """Clear all threats (admin only)"""
    user = users_db.get(request.user_email)
    
    if not user or not user.get('is_admin', False):
        return jsonify({'error': 'Admin access required'}), 403
    
    clear_threats()
    log_event('THREATS_CLEARED', request.user_email, {}, request.remote_addr)
    
    return jsonify({'message': 'All threats cleared'})

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    })

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(429)
def rate_limit_error(error):
    log_event('RATE_LIMIT_EXCEEDED', 'anonymous', {'endpoint': request.endpoint}, request.remote_addr)
    return jsonify({'error': 'Rate limit exceeded. Try again later.'}), 429

@app.errorhandler(500)
def internal_error(error):
    log_event('SERVER_ERROR', 'system', {'error': str(error)}, request.remote_addr)
    return jsonify({'error': 'Internal server error'}), 500

# ==================== START APPLICATION ====================
if __name__ == '__main__':
    init_admin()
    
    # Start EDR monitoring thread
    import threading
    monitor_thread = threading.Thread(target=start_monitoring, daemon=True)
    monitor_thread.start()
    
    print("="*60)
    print("🔒 EDR LITE - ENTERPRISE SECURITY PLATFORM")
    print("="*60)
    print(f"📍 Web Interface: http://localhost:5000")
    print(f"🔐 API Endpoint: http://localhost:5000/api")
    print(f"👤 Admin Login: admin@edr.com / Admin@123")
    print(f"🎫 Invite Code: EDR2024")
    print("="*60)
    print("✅ SECURITY FEATURES:")
    print("   - JWT Authentication")
    print("   - AES-256 Encryption")
    print("   - Rate Limiting")
    print("   - Input Validation")
    print("   - Audit Logging")
    print("   - Security Headers")
    print("="*60)
    
    app.run(debug=False, host='0.0.0.0', port=5000)