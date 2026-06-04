"""
Security Audit Logging
"""
import logging
import json
from datetime import datetime
from pathlib import Path

# Setup audit log directory
AUDIT_DIR = Path('logs')
AUDIT_DIR.mkdir(exist_ok=True)

# Configure audit logger
audit_logger = logging.getLogger('security_audit')
audit_logger.setLevel(logging.INFO)

# File handler
file_handler = logging.FileHandler(AUDIT_DIR / 'audit.log')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
audit_logger.addHandler(file_handler)

def log_event(event_type: str, user_id: str, details: dict, ip: str = None):
    """Log security event to audit trail"""
    log_entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'event_type': event_type,
        'user_id': user_id,
        'details': details,
        'ip_address': ip,
        'session_id': None
    }
    audit_logger.info(json.dumps(log_entry))
    return log_entry

def log_login(user_id: str, success: bool, ip: str, method: str = 'password'):
    """Log login attempt"""
    return log_event(
        'LOGIN_ATTEMPT',
        user_id,
        {'success': success, 'method': method, 'ip': ip},
        ip
    )

def log_api_access(user_id: str, endpoint: str, method: str, ip: str):
    """Log API access"""
    return log_event(
        'API_ACCESS',
        user_id,
        {'endpoint': endpoint, 'method': method, 'ip': ip},
        ip
    )

def log_threat_detection(user_id: str, threat_data: dict):
    """Log threat detection event"""
    return log_event(
        'THREAT_DETECTED',
        user_id,
        {
            'process': threat_data.get('process_name'),
            'severity': threat_data.get('severity'),
            'reason': threat_data.get('reason')
        },
        None
    )

def log_config_change(user_id: str, config_key: str, old_value: str, new_value: str):
    """Log configuration changes"""
    return log_event(
        'CONFIG_CHANGE',
        user_id,
        {'key': config_key, 'old': old_value, 'new': new_value},
        None
    )