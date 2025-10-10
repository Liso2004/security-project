# Secure Authentication System

A robust, secure authentication system built with Python featuring multi-factor authentication, brute-force protection, password policies, and session management.

## Features

- 🔐 **Secure Password Hashing** - Uses bcrypt with salt
- 🛡️ **Brute-Force Protection** - Account locking after failed attempts
- 📱 **Multi-Factor Authentication** - TOTP support with backup codes
- 🔄 **Password Policy Enforcement** - Configurable complexity requirements
- 📊 **Password History** - Prevents password reuse
- 🔄 **Session Management** - Secure token-based sessions
- 🌐 **IP Monitoring** - Detects suspicious activity
- ⏰ **Password Expiration** - Automatic password rotation
- 🗄️ **SQLite Database** - Lightweight and portable

## Installation

### Prerequisites

- Python 3.7+
- pip package manager

### Dependencies

```bash
pip install bcrypt
```

The system uses these built-in Python modules:
- `hashlib`, `secrets`, `sqlite3`, `datetime`
- `re`, `json`, `typing`

### Quick Start

1. **Download the code:**
```python
# Save as secure_auth.py
import hashlib
import secrets
import time
import re
import sqlite3
from datetime import datetime, timedelta
import json
from typing import Tuple, Optional, Dict, Any
import bcrypt

2. **Basic usage:**
```python
from secure_auth import SecureAuthSystem

# Initialize
auth = SecureAuthSystem()

# Register user
auth.register_user("alice", "alice@email.com", "SecurePass123!")

# Authenticate
success, message, session = auth.authenticate("alice", "SecurePass123!")
```

## API Reference

### Core Methods

#### `register_user(username, email, password)`
Register a new user with password policy validation.

```python
success, message = auth.register_user(
    username="john_doe",
    email="john@example.com", 
    password="SecurePass123!"
)
```

#### `authenticate(username, password, mfa_token=None, ip_address=None)`
Authenticate a user with optional MFA.

```python
success, message, session_data = auth.authenticate(
    username="john_doe",
    password="SecurePass123!",
    mfa_token="123456",  # Optional
    ip_address="192.168.1.100"  # Optional
)
```

Returns session data including:
- `session_token`: Secure token for subsequent requests
- `user_id`: Unique user identifier
- `expires_at`: Session expiration timestamp

#### `verify_session(session_token, ip_address=None)`
Verify session validity and get user information.

```python
valid, user_info = auth.verify_session("your_session_token")
```

#### `change_password(username, current_password, new_password)`
Change user password with policy and history validation.

```python
success, message = auth.change_password(
    username="john_doe",
    current_password="old_password",
    new_password="NewSecurePass456!"
)
```

#### `enable_mfa(username)`
Enable Multi-Factor Authentication for a user.

```python
success, message, secret = auth.enable_mfa("john_doe")
```

### Security Configuration

#### Password Policy
```python
# Default configuration
password_policy = {
    'min_length': 8,
    'require_uppercase': True,
    'require_lowercase': True,
    'require_numbers': True,
    'require_special_chars': True,
    'special_chars': '!@#$%^&*()_+-=[]{}|;:,.<>?',
    'max_age_days': 90  # Password expiration
}
```

#### Brute-Force Protection
```python
brute_force_protection = {
    'max_attempts': 5,           # Lock after 5 failed attempts
    'lockout_duration': 900,     # 15 minutes lockout
    'ip_monitoring': True        # Monitor IP addresses
}
```

## Usage Examples

### Basic Authentication Flow

```python
from secure_auth import SecureAuthSystem

# Initialize system
auth = SecureAuthSystem("my_app.db")

# 1. Register user
success, message = auth.register_user(
    "alice", "alice@example.com", "AlicePass123!"
)
print(f"Registration: {message}")

# 2. Login user
success, message, session = auth.authenticate(
    "alice", "AlicePass123!", ip_address="192.168.1.100"
)

if success:
    print(f"Login successful! Session: {session['session_token']}")
    
    # 3. Verify session
    valid, user_info = auth.verify_session(session['session_token'])
    if valid:
        print(f"Welcome {user_info['username']}!")
```

### Web Application Integration

```python
from flask import Flask, request, jsonify, session
from secure_auth import SecureAuthSystem

app = Flask(__name__)
auth = SecureAuthSystem()

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    success, message = auth.register_user(
        data['username'], data['email'], data['password']
    )
    return jsonify({'success': success, 'message': message})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    success, message, session_data = auth.authenticate(
        data['username'], data['password'], ip_address=request.remote_addr
    )
    
    if success:
        return jsonify({
            'success': True,
            'message': message,
            'session_token': session_data['session_token']
        })
    return jsonify({'success': False, 'message': message})

@app.route('/api/profile', methods=['GET'])
def profile():
    token = request.headers.get('Authorization')
    if token:
        valid, user_info = auth.verify_session(token)
        if valid:
            return jsonify({'user': user_info})
    return jsonify({'error': 'Unauthorized'}), 401
```

### MFA Setup and Usage

```python
# Enable MFA
success, message, secret = auth.enable_mfa("alice")
if success:
    print(f"Scan this QR code with Google Authenticator:")
    print(f"Secret: {secret}")

# Login with MFA
success, message, session = auth.authenticate(
    "alice", "AlicePass123!", mfa_token="123456"
)
```

### Password Management

```python
# Check password policy
is_valid, message = auth.validate_password_policy("MyPass123!")
print(f"Password valid: {is_valid}, Message: {message}")

# Change password
success, message = auth.change_password(
    "alice", "AlicePass123!", "NewAlicePass456!"
)
```

## Database Schema

The system automatically creates these tables:

### Users Table
- `id` - Primary key
- `username` - Unique username
- `email` - Unique email
- `password_hash` - BCrypt hashed password
- `mfa_secret` - MFA secret key
- `mfa_enabled` - MFA status
- `backup_codes` - JSON array of backup codes
- `account_locked` - Lock status
- `lock_until` - Lock expiration

### Other Tables
- `failed_attempts` - Track login attempts
- `password_history` - Store previous passwords
- `sessions` - Active user sessions

## Security Features

### Password Security
- **BCrypt Hashing**: Passwords are hashed with salt using industry-standard bcrypt
- **Policy Enforcement**: Configurable complexity requirements
- **History Tracking**: Prevents password reuse (last 5 passwords)
- **Automatic Expiration**: Passwords expire after 90 days

### Account Protection
- **Brute-Force Detection**: Locks accounts after 5 failed attempts
- **IP Monitoring**: Tracks and blocks suspicious IP addresses
- **Automatic Lockout**: 15-minute lockout period
- **Session Security**: Secure token generation with expiration

### Multi-Factor Authentication
- **TOTP Support**: Time-based one-time passwords
- **Backup Codes**: 5 one-time use backup codes
- **Flexible Enrollment**: MFA can be enabled per user

## Error Handling

All methods return tuples with success status and message:

```python
success, message = auth.register_user(username, email, password)

if success:
    print(f"Success: {message}")
else:
    print(f"Error: {message}")
```

Common error messages:
- `"Password policy violation: ..."`
- `"Username or email already exists"`
- `"Invalid credentials"`
- `"Account temporarily locked due to too many failed attempts"`
- `"MFA token required"`
- `"Password has expired"`

## Customization

### Modify Security Settings

```python
auth = SecureAuthSystem()

# Customize password policy
auth.password_policy['min_length'] = 12
auth.password_policy['max_age_days'] = 60

# Adjust brute-force protection
auth.brute_force_protection['max_attempts'] = 3
auth.brute_force_protection['lockout_duration'] = 1800  # 30 minutes

# Disable MFA by default
auth.mfa_settings['enabled'] = False
```

### Custom Database Path

```python
# Use different database file
auth = SecureAuthSystem("/path/to/your/database.db")
```

## Testing

Run the built-in demo:

```bash
python secure_auth.py
```

Expected output:
```
Registration: User registered successfully
Authentication: Authentication successful
Session token: [generated_token]
Testing brute force protection...
Attempt 1: Invalid credentials
...
Account temporarily locked due to too many failed attempts
```

## Best Practices

1. **Always use HTTPS** in production environments
2. **Store session tokens securely** (HTTP-only cookies)
3. **Implement proper logging** for security monitoring
4. **Regularly update dependencies**
5. **Use strong secret keys** for production
6. **Implement rate limiting** at the application level
7. **Regular security audits** of your implementation

## Limitations

- TOTP implementation is simplified (use `pyotp` library for production)
- Email functionality is not implemented
- No password reset mechanism included
- SQLite may not scale for high-traffic applications

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is open source and available under the MIT License.

## Support

For issues and questions:
1. Check the documentation
2. Review the example implementations
3. Create an issue in the repository

---

**Note**: This is a demonstration system. For production use, conduct thorough security testing and consider additional security measures like Web Application Firewalls (WAF), intrusion detection systems, and regular security audits.