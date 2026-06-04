"""
EDR LITE - COMPLETE LOCKED SYSTEM
No public registration. Only admin can add users.
"""

from flask import Flask, render_template, request, jsonify, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import hashlib
import secrets
import jwt
import os
import time
import threading
import psutil
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'edr-secret-key-2024'

# ==================== SECURITY KEYS ====================
JWT_SECRET_KEY = "ndQzXu62CLEIAamvNmZh8XXyrB9kTd5kEpEHmLYcyMQ"
REFRESH_SECRET_KEY = "4WMn_1GbDJD0VXeXNr8vYj1eHvnl5D59r_r9_NDI8uc"

# ==================== RATE LIMITING ====================
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)
limiter.init_app(app)

# Track failed login attempts
failed_attempts = {}

def track_failed_attempt(ip):
    if ip not in failed_attempts:
        failed_attempts[ip] = []
    failed_attempts[ip].append(datetime.now())
    failed_attempts[ip] = [t for t in failed_attempts[ip] if (datetime.now() - t).seconds < 900]
    return len(failed_attempts[ip]) >= 5

def is_ip_blocked(ip):
    if ip not in failed_attempts:
        return False
    recent = [t for t in failed_attempts[ip] if (datetime.now() - t).seconds < 900]
    return len(recent) >= 5

# ==================== PASSWORD HASHING ====================
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    return hash_password(password) == hashed

# ==================== AUTHORIZED USERS (ONLY THESE CAN LOGIN) ====================
# NO PUBLIC REGISTRATION - Add users manually here
AUTHORIZED_USERS = {
    'admin@edr.com': {
        'username': 'admin',
        'password_hash': hash_password('Admin@123'),
        'is_admin': True,
        'is_active': True,
        'created_at': datetime.now().isoformat()
    },
    # ========== ADD NEW USERS BELOW THIS LINE ==========
    # Example:
    # 'friend@gmail.com': {
    #     'username': 'friend',
    #     'password_hash': hash_password('FriendPass123'),
    #     'is_admin': False,
    #     'is_active': True,
    #     'created_at': datetime.now().isoformat()
    # },
}

# ==================== JWT TOKENS ====================
refresh_tokens = {}

def generate_access_token(email, username):
    payload = {
        'user_id': email,
        'username': username,
        'email': email,
        'exp': datetime.utcnow() + timedelta(minutes=15),
        'iat': datetime.utcnow(),
        'type': 'access'
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')

def generate_refresh_token(email):
    payload = {
        'user_id': email,
        'exp': datetime.utcnow() + timedelta(days=7),
        'type': 'refresh'
    }
    return jwt.encode(payload, REFRESH_SECRET_KEY, algorithm='HS256')

def verify_token(token, token_type='access'):
    try:
        secret = JWT_SECRET_KEY if token_type == 'access' else REFRESH_SECRET_KEY
        payload = jwt.decode(token, secret, algorithms=['HS256'])
        if payload.get('type') != token_type:
            return None
        return payload
    except:
        return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Invalid token'}), 401
        token = auth_header[7:]
        payload = verify_token(token)
        if not payload:
            return jsonify({'error': 'Token expired'}), 401
        request.user_email = payload['email']
        request.username = payload['username']
        return f(*args, **kwargs)
    return decorated

# ==================== EDR MONITORING ENGINE ====================
MALICIOUS_PROCESSES = {
    'ransomware.exe', 'wannacry.exe', 'locky.exe', 'cryptolocker.exe',
    'xmrig.exe', 'miner.exe', 'cgminer.exe', 'minerd.exe',
    'nc.exe', 'netcat.exe', 'reverse_shell.exe', 'mimikatz.exe',
    'procdump.exe', 'psexec.exe', 'payload.exe', 'backdoor.exe'
}

SUSPICIOUS_COMMANDS = [
    'powershell -enc', 'powershell -e', 'cmd /c', 'schtasks /create',
    'reg add', 'sc create', 'net user', 'vssadmin delete', 'Invoke-Mimikatz'
]

detected_threats = []
monitoring_active = True

def analyze_process(proc):
    try:
        name = proc.name().lower()
        pid = proc.pid
        
        skip = ['system idle process', 'svchost.exe', 'services.exe', 'lsass.exe']
        if name in skip:
            return None
        
        cpu = proc.cpu_percent(interval=0.1)
        memory = proc.memory_percent()
        
        try:
            cmdline = ' '.join(proc.cmdline()).lower()
        except:
            cmdline = ''
        
        severity = None
        reason = None
        detection_type = None
        
        if name in MALICIOUS_PROCESSES:
            severity = 'CRITICAL'
            detection_type = 'Malware'
            reason = f'Known malware: {name}'
        elif cpu > 200:
            severity = 'HIGH'
            detection_type = 'Crypto Miner'
            reason = f'High CPU: {cpu}%'
        elif any(cmd in cmdline for cmd in SUSPICIOUS_COMMANDS):
            severity = 'HIGH'
            detection_type = 'Suspicious Command'
            reason = cmdline[:80]
        elif memory > 60:
            severity = 'MEDIUM'
            detection_type = 'Memory Bomb'
            reason = f'Memory: {memory}%'
        
        if severity:
            threat = {
                'process_name': name,
                'process_pid': pid,
                'severity': severity,
                'detection_type': detection_type,
                'reason': reason,
                'cpu_usage': round(cpu, 1),
                'memory_usage': round(memory, 1),
                'action_taken': 'terminated',
                'timestamp': datetime.now().isoformat()
            }
            try:
                proc.terminate()
                time.sleep(1)
                if proc.is_running():
                    proc.kill()
            except:
                threat['action_taken'] = 'failed'
            return threat
    except:
        pass
    return None

def start_monitoring():
    global monitoring_active, detected_threats
    print("🟢 EDR Monitoring Started")
    while monitoring_active:
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                threat = analyze_process(proc)
                if threat:
                    detected_threats.insert(0, threat)
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚨 {threat['severity']} - {threat['detection_type']}")
            time.sleep(3)
        except:
            time.sleep(5)

def get_threats():
    return detected_threats[:100]

def clear_threats():
    global detected_threats
    detected_threats = []

def get_stats():
    total = len(detected_threats)
    critical = len([t for t in detected_threats if t['severity'] == 'CRITICAL'])
    high = len([t for t in detected_threats if t['severity'] == 'HIGH'])
    medium = len([t for t in detected_threats if t['severity'] == 'MEDIUM'])
    return total, critical, high, medium

# ==================== API ROUTES ====================

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.json
    email = data.get('email', '').lower()
    password = data.get('password', '')
    ip = request.remote_addr
    
    if is_ip_blocked(ip):
        return jsonify({'error': 'Too many attempts. Try later.'}), 429
    
    # CHECK IF EMAIL IS AUTHORIZED (NO PUBLIC REGISTRATION)
    if email not in AUTHORIZED_USERS:
        track_failed_attempt(ip)
        return jsonify({'error': 'Access denied. Email not authorized.'}), 403
    
    user = AUTHORIZED_USERS[email]
    
    if not user.get('is_active', True):
        return jsonify({'error': 'Account disabled. Contact admin.'}), 403
    
    if not verify_password(password, user['password_hash']):
        track_failed_attempt(ip)
        return jsonify({'error': 'Invalid password'}), 401
    
    access_token = generate_access_token(email, user['username'])
    refresh_token = generate_refresh_token(email)
    refresh_tokens[refresh_token] = email
    
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': {'email': email, 'username': user['username'], 'is_admin': user.get('is_admin', False)}
    })

@app.route('/api/register', methods=['POST'])
def register():
    """REGISTRATION IS DISABLED - Only admin can add users"""
    return jsonify({'error': 'Public registration disabled. Contact administrator for access.'}), 403

@app.route('/api/refresh', methods=['POST'])
def refresh():
    data = request.json
    token = data.get('refresh_token')
    if not token or token not in refresh_tokens:
        return jsonify({'error': 'Invalid refresh token'}), 401
    payload = verify_token(token, 'refresh')
    if not payload:
        return jsonify({'error': 'Refresh token expired'}), 401
    email = payload['user_id']
    user = AUTHORIZED_USERS.get(email)
    if not user:
        return jsonify({'error': 'User not found'}), 401
    new_token = generate_access_token(email, user['username'])
    return jsonify({'access_token': new_token})

@app.route('/api/logout', methods=['POST'])
@token_required
def logout():
    data = request.json
    token = data.get('refresh_token')
    if token and token in refresh_tokens:
        del refresh_tokens[token]
    return jsonify({'message': 'Logged out'})

@app.route('/api/threats', methods=['GET'])
@token_required
def get_threats_api():
    threats = get_threats()
    return jsonify({'threats': threats, 'total': len(threats)})

@app.route('/api/stats', methods=['GET'])
@token_required
def get_stats_api():
    total, critical, high, medium = get_stats()
    return jsonify({
        'total': total,
        'critical': critical,
        'high': high,
        'medium': medium,
        'username': request.username
    })

@app.route('/api/threats/clear', methods=['POST'])
@token_required
def clear_threats_api():
    user = AUTHORIZED_USERS.get(request.user_email)
    if not user or not user.get('is_admin'):
        return jsonify({'error': 'Admin only'}), 403
    clear_threats()
    return jsonify({'message': 'Threats cleared'})

# ==================== START APP ====================
if __name__ == '__main__':
    # Start monitoring thread
    monitor_thread = threading.Thread(target=start_monitoring, daemon=True)
    monitor_thread.start()
    
    print("="*60)
    print("🔒 EDR LITE - COMPLETE LOCKED SYSTEM")
    print("="*60)
    print("📍 Dashboard: http://localhost:5000")
    print("👤 Admin: admin@edr.com / Admin@123")
    print("🔐 Registration: DISABLED (Admin only)")
    print("="*60)
    
    app.run(debug=False, host='0.0.0.0', port=5000)