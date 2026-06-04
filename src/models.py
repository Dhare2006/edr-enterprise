"""
Database Models with Security Fields
"""
from datetime import datetime
import json

class User:
    """User model"""
    def __init__(self, id=None, username=None, email=None, password_hash=None):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.is_admin = False
        self.is_active = True
        self.created_at = datetime.utcnow()
        self.last_login = None
        self.failed_attempts = 0
        self.locked_until = None
        self.totp_secret = None
        self.api_keys = []
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Threat:
    """Threat detection model"""
    def __init__(self, id=None, user_id=None, process_name=None, pid=None):
        self.id = id
        self.user_id = user_id
        self.process_name = process_name
        self.pid = pid
        self.severity = None
        self.reason = None
        self.cmdline = None
        self.connections = None
        self.cpu_usage = None
        self.memory_usage = None
        self.action_taken = None
        self.timestamp = datetime.utcnow()
    
    def to_dict(self):
        return {
            'id': self.id,
            'process_name': self.process_name,
            'pid': self.pid,
            'severity': self.severity,
            'reason': self.reason,
            'action_taken': self.action_taken,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }

class ApiKey:
    """API Key model for external integrations"""
    def __init__(self, id=None, user_id=None, name=None, key_hash=None):
        self.id = id
        self.user_id = user_id
        self.name = name
        self.key_hash = key_hash
        self.last_used = None
        self.created_at = datetime.utcnow()
        self.is_active = True

# In-memory storage (replace with real database in production)
users_db = {}
threats_db = []
api_keys_db = {}