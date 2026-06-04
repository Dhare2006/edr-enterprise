"""
AES-256 Encryption Module
"""
from cryptography.fernet import Fernet
import base64
import os
import hashlib
from dotenv import load_dotenv

load_dotenv()

# Generate or load encryption key
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())
cipher = Fernet(ENCRYPTION_KEY)

def encrypt_data(data: str) -> str:
    """Encrypt sensitive data"""
    if not data:
        return ""
    if isinstance(data, str):
        data = data.encode()
    encrypted = cipher.encrypt(data)
    return base64.b64encode(encrypted).decode()

def decrypt_data(encrypted_data: str) -> str:
    """Decrypt encrypted data"""
    if not encrypted_data:
        return ""
    try:
        decoded = base64.b64decode(encrypted_data.encode())
        decrypted = cipher.decrypt(decoded)
        return decrypted.decode()
    except Exception:
        return None

def hash_password(password: str) -> str:
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return hash_password(password) == hashed