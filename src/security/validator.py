"""
Input Validation and Sanitization
"""
import re

def validate_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_password(password: str) -> tuple:
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain an uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain a lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain a number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain a special character"
    return True, "Password is strong"

def validate_username(username: str) -> tuple:
    """Validate username"""
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    if len(username) > 50:
        return False, "Username must be less than 50 characters"
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False, "Username can only contain letters, numbers, underscores, and hyphens"
    return True, "Valid username"

def sanitize_input(input_str: str) -> str:
    """Sanitize user input to prevent XSS/SQL injection"""
    if not input_str:
        return ""
    
    # Remove dangerous characters and patterns
    dangerous_patterns = [
        r'<script', r'</script>', r'javascript:', r'onclick=', r'onload=',
        r'SELECT.*FROM', r'INSERT.*INTO', r'UPDATE.*SET', r'DELETE.*FROM',
        r'UNION.*SELECT', r'DROP.*TABLE', r'--', r';', r'xp_'
    ]
    
    for pattern in dangerous_patterns:
        input_str = re.sub(pattern, '', input_str, flags=re.IGNORECASE)
    
    # Escape HTML characters
    html_escape = {
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;'
    }
    
    for char, escape in html_escape.items():
        input_str = input_str.replace(char, escape)
    
    return input_str.strip()