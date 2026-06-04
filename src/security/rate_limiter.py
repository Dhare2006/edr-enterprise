"""
Rate Limiting Module
"""
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Rate limit configurations
RATE_LIMITS = {
    'login': "5 per minute",
    'register': "3 per hour",
    'api': "100 per minute",
    'sensitive': "10 per minute",
    'threats': "30 per minute"
}

# Track failed login attempts
failed_attempts = {}

def track_failed_attempt(ip: str) -> bool:
    """Track failed login attempts for IP blocking"""
    if ip not in failed_attempts:
        failed_attempts[ip] = []
    
    failed_attempts[ip].append(datetime.now())
    
    # Remove attempts older than 15 minutes
    failed_attempts[ip] = [t for t in failed_attempts[ip] 
                          if (datetime.now() - t).seconds < 900]
    
    return len(failed_attempts[ip]) >= 5

def is_ip_blocked(ip: str) -> bool:
    """Check if IP is blocked due to too many failures"""
    if ip not in failed_attempts:
        return False
    
    recent_attempts = [t for t in failed_attempts[ip] 
                      if (datetime.now() - t).seconds < 900]
    return len(recent_attempts) >= 5