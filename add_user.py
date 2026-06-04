#!/usr/bin/env python
"""ADD NEW USERS TO EDR SYSTEM - Run this script"""
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

print("=" * 60)
print("👤 ADD NEW USER TO EDR SYSTEM")
print("=" * 60)

email = input("Enter user email: ").lower()
username = input("Enter username: ")
password = input("Enter password: ")
is_admin = input("Is admin? (yes/no): ").lower() == 'yes'

print("\n" + "=" * 60)
print("COPY THIS INTO app.py AUTHORIZED_USERS section:")
print("=" * 60)
print(f"""
    '{email}': {{
        'username': '{username}',
        'password_hash': '{hash_password(password)}',
        'is_admin': {str(is_admin).lower()},
        'is_active': True,
        'created_at': 'datetime.now().isoformat()'
    }},""")
print("=" * 60)