import hashlib
import secrets
import time
import re
import sqlite3
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MimeText
import json
from typing import Tuple, Optional, Dict, Any
import bcrypt

class SecureAuthSystem:
    def __init__(self, db_path: str = "auth_system.db"):
        self.db_path = db_path
        self.init_database()
        
        # Password policy configuration
        self.password_policy = {
            'min_length': 8,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_numbers': True,
            'require_special_chars': True,
            'special_chars': '!@#$%^&*()_+-=[]{}|;:,.<>?',
            'max_age_days': 90  # Password expiration
        }
        
        # Brute-force protection configuration
        self.brute_force_protection = {
            'max_attempts': 5,
            'lockout_duration': 900,  # 15 minutes in seconds
            'ip_monitoring': True
        }
        
        # MFA configuration
        self.mfa_settings = {
            'enabled': True,
            'backup_codes_count': 5,
            'totp_period': 30  # Time-based OTP period in seconds
        }
        
        # Initialize rate limiting tracking
        self.failed_attempts = {}
        self.locked_accounts = {}
        self.locked_ips = {}

    def init_database(self):
        """Initialize the database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                password_created DATETIME DEFAULT CURRENT_TIMESTAMP,
                mfa_secret TEXT,
                mfa_enabled BOOLEAN DEFAULT FALSE,
                backup_codes TEXT,  # JSON array of backup codes
                account_locked BOOLEAN DEFAULT FALSE,
                lock_until DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Failed login attempts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS failed_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip_address TEXT,
                attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Password history table (to prevent reuse)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        conn.close()

    def validate_password_policy(self, password: str) -> Tuple[bool, str]:
        """Validate password against policy"""
        errors = []
        
        if len(password) < self.password_policy['min_length']:
            errors.append(f"Password must be at least {self.password_policy['min_length']} characters long")
        
        if self.password_policy['require_uppercase'] and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if self.password_policy['require_lowercase'] and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if self.password_policy['require_numbers'] and not re.search(r'[0-9]', password):
            errors.append("Password must contain at least one number")
        
        if self.password_policy['require_special_chars']:
            special_chars = re.escape(self.password_policy['special_chars'])
            if not re.search(f'[{special_chars}]', password):
                errors.append(f"Password must contain at least one special character: {self.password_policy['special_chars']}")
        
        if errors:
            return False, "; ".join(errors)
        
        return True, "Password meets policy requirements"

    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt with salt"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

    def check_brute_force(self, username: str, ip_address: str = None) -> Tuple[bool, Optional[str]]:
        """Check if account is locked due to brute force attempts"""
        # Check IP-based locking
        if ip_address and ip_address in self.locked_ips:
            if time.time() < self.locked_ips[ip_address]:
                return False, "IP address temporarily locked due to suspicious activity"
            else:
                del self.locked_ips[ip_address]
        
        # Check account locking
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT account_locked, lock_until FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        
        if result:
            account_locked, lock_until = result
            if account_locked and lock_until:
                lock_time = datetime.fromisoformat(lock_until)
                if datetime.now() < lock_time:
                    conn.close()
                    return False, "Account temporarily locked due to too many failed attempts"
                else:
                    # Unlock the account
                    cursor.execute('UPDATE users SET account_locked = FALSE, lock_until = NULL WHERE username = ?', (username,))
                    conn.commit()
        
        conn.close()
        return True, None

    def record_failed_attempt(self, username: str, ip_address: str = None):
        """Record a failed login attempt and lock account if necessary"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Record the attempt
        cursor.execute(
            'INSERT INTO failed_attempts (username, ip_address) VALUES (?, ?)',
            (username, ip_address)
        )
        
        # Count recent failed attempts
        cutoff_time = datetime.now() - timedelta(minutes=15)
        cursor.execute(
            'SELECT COUNT(*) FROM failed_attempts WHERE username = ? AND attempt_time > ?',
            (username, cutoff_time)
        )
        recent_attempts = cursor.fetchone()[0]
        
        # Lock account if threshold exceeded
        if recent_attempts >= self.brute_force_protection['max_attempts']:
            lock_until = datetime.now() + timedelta(seconds=self.brute_force_protection['lockout_duration'])
            cursor.execute(
                'UPDATE users SET account_locked = TRUE, lock_until = ? WHERE username = ?',
                (lock_until.isoformat(), username)
            )
        
        # IP-based monitoring
        if ip_address and self.brute_force_protection['ip_monitoring']:
            if ip_address not in self.failed_attempts:
                self.failed_attempts[ip_address] = []
            
            self.failed_attempts[ip_address].append(time.time())
            
            # Clean old attempts
            cutoff = time.time() - 900  # 15 minutes
            self.failed_attempts[ip_address] = [t for t in self.failed_attempts[ip_address] if t > cutoff]
            
            # Lock IP if too many attempts from same IP
            if len(self.failed_attempts[ip_address]) > self.brute_force_protection['max_attempts'] * 3:
                self.locked_ips[ip_address] = time.time() + self.brute_force_protection['lockout_duration']
        
        conn.commit()
        conn.close()

    def clear_failed_attempts(self, username: str):
        """Clear failed attempts after successful login"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM failed_attempts WHERE username = ?', (username,))
        cursor.execute('UPDATE users SET account_locked = FALSE, lock_until = NULL WHERE username = ?', (username,))
        
        conn.commit()
        conn.close()

    def generate_mfa_secret(self) -> str:
        """Generate a secret for TOTP-based MFA"""
        return secrets.token_hex(16)

    def verify_totp(self, secret: str, token: str) -> bool:
        """Verify Time-based One-Time Password"""
        # This is a simplified version. In production, use a library like pyotp
        try:
            # Simulate TOTP verification
            current_time = int(time.time() // self.mfa_settings['totp_period'])
            expected_token = hashlib.sha256(f"{secret}{current_time}".encode()).hexdigest()[:6]
            return secrets.compare_digest(token, expected_token)
        except:
            return False

    def generate_backup_codes(self, count: int = None) -> list:
        """Generate backup codes for MFA"""
        if count is None:
            count = self.mfa_settings['backup_codes_count']
        
        return [secrets.token_hex(5).upper() for _ in range(count)]

    def register_user(self, username: str, email: str, password: str) -> Tuple[bool, str]:
        """Register a new user with password policy validation"""
        # Validate password policy
        is_valid, message = self.validate_password_policy(password)
        if not is_valid:
            return False, f"Password policy violation: {message}"
        
        # Hash password
        password_hash = self.hash_password(password)
        
        # Generate MFA secret and backup codes
        mfa_secret = self.generate_mfa_secret()
        backup_codes = self.generate_backup_codes()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                'INSERT INTO users (username, email, password_hash, mfa_secret, backup_codes) VALUES (?, ?, ?, ?, ?)',
                (username, email, password_hash, mfa_secret, json.dumps(backup_codes))
            )
            
            # Store password in history
            user_id = cursor.lastrowid
            cursor.execute(
                'INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)',
                (user_id, password_hash)
            )
            
            conn.commit()
            conn.close()
            
            return True, "User registered successfully"
        except sqlite3.IntegrityError:
            conn.close()
            return False, "Username or email already exists"

    def authenticate(self, username: str, password: str, mfa_token: str = None, 
                    ip_address: str = None) -> Tuple[bool, str, Optional[Dict]]:
        """Authenticate a user with optional MFA"""
        # Check brute force protection
        can_login, message = self.check_brute_force(username, ip_address)
        if not can_login:
            return False, message, None
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT id, password_hash, mfa_secret, mfa_enabled FROM users WHERE username = ?',
            (username,)
        )
        result = cursor.fetchone()
        
        if not result:
            self.record_failed_attempt(username, ip_address)
            conn.close()
            return False, "Invalid credentials", None
        
        user_id, password_hash, mfa_secret, mfa_enabled = result
        
        # Verify password
        if not self.verify_password(password, password_hash):
            self.record_failed_attempt(username, ip_address)
            conn.close()
            return False, "Invalid credentials", None
        
        # Check if MFA is required
        if mfa_enabled:
            if not mfa_token:
                conn.close()
                return False, "MFA token required", {"mfa_required": True}
            
            # Check if it's a backup code
            cursor.execute('SELECT backup_codes FROM users WHERE id = ?', (user_id,))
            backup_codes_json = cursor.fetchone()[0]
            backup_codes = json.loads(backup_codes_json) if backup_codes_json else []
            
            if mfa_token in backup_codes:
                # Remove used backup code
                backup_codes.remove(mfa_token)
                cursor.execute(
                    'UPDATE users SET backup_codes = ? WHERE id = ?',
                    (json.dumps(backup_codes), user_id)
                )
                conn.commit()
            elif not self.verify_totp(mfa_secret, mfa_token):
                self.record_failed_attempt(username, ip_address)
                conn.close()
                return False, "Invalid MFA token", None
        
        # Check password expiration
        cursor.execute('SELECT password_created FROM users WHERE id = ?', (user_id,))
        password_created = datetime.fromisoformat(cursor.fetchone()[0])
        password_age = datetime.now() - password_created
        
        if password_age.days > self.password_policy['max_age_days']:
            conn.close()
            return False, "Password has expired. Please reset your password.", {"password_expired": True}
        
        # Clear failed attempts
        self.clear_failed_attempts(username)
        
        # Generate session token
        session_token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(days=7)  # 7-day session
        
        cursor.execute(
            'INSERT INTO sessions (user_id, session_token, expires_at, ip_address) VALUES (?, ?, ?, ?)',
            (user_id, session_token, expires_at.isoformat(), ip_address)
        )
        
        conn.commit()
        conn.close()
        
        return True, "Authentication successful", {
            "session_token": session_token,
            "user_id": user_id,
            "expires_at": expires_at.isoformat()
        }

    def enable_mfa(self, username: str) -> Tuple[bool, str, Optional[str]]:
        """Enable MFA for a user and return the secret for QR code generation"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT mfa_secret FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            return False, "User not found", None
        
        mfa_secret = result[0]
        
        cursor.execute(
            'UPDATE users SET mfa_enabled = TRUE WHERE username = ?',
            (username,)
        )
        
        conn.commit()
        conn.close()
        
        return True, "MFA enabled successfully", mfa_secret

    def change_password(self, username: str, current_password: str, new_password: str) -> Tuple[bool, str]:
        """Change user password with policy validation and history check"""
        # Validate new password policy
        is_valid, message = self.validate_password_policy(new_password)
        if not is_valid:
            return False, f"New password policy violation: {message}"
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Verify current password
        cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            return False, "User not found"
        
        user_id, current_hash = result
        
        if not self.verify_password(current_password, current_hash):
            conn.close()
            return False, "Current password is incorrect"
        
        # Check password history (prevent reuse)
        cursor.execute(
            'SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 5',
            (user_id,)
        )
        
        recent_passwords = [row[0] for row in cursor.fetchall()]
        new_hash = self.hash_password(new_password)
        
        if new_hash in recent_passwords:
            conn.close()
            return False, "New password cannot be the same as one of your recent passwords"
        
        # Update password
        cursor.execute(
            'UPDATE users SET password_hash = ?, password_created = CURRENT_TIMESTAMP WHERE id = ?',
            (new_hash, user_id)
        )
        
        # Add to password history
        cursor.execute(
            'INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)',
            (user_id, new_hash)
        )
        
        # Invalidate all existing sessions
        cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
        
        conn.commit()
        conn.close()
        
        return True, "Password changed successfully"

    def verify_session(self, session_token: str, ip_address: str = None) -> Tuple[bool, Optional[Dict]]:
        """Verify session token and return user info if valid"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT s.user_id, s.expires_at, u.username, u.email 
            FROM sessions s 
            JOIN users u ON s.user_id = u.id 
            WHERE s.session_token = ? AND s.expires_at > datetime('now')
        ''', (session_token,))
        
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            return False, None
        
        user_id, expires_at, username, email = result
        
        # Update session if IP address provided and different
        if ip_address:
            cursor.execute(
                'SELECT ip_address FROM sessions WHERE session_token = ?',
                (session_token,)
            )
            current_ip = cursor.fetchone()[0]
            
            if current_ip != ip_address:
                # Log suspicious activity (in a real system)
                print(f"Warning: Session IP changed from {current_ip} to {ip_address} for user {username}")
        
        conn.close()
        
        return True, {
            "user_id": user_id,
            "username": username,
            "email": email,
            "expires_at": expires_at
        }

# Example usage and testing
if __name__ == "__main__":
    # Initialize the auth system
    auth_system = SecureAuthSystem()
    
    # Register a new user
    success, message = auth_system.register_user(
        "john_doe", 
        "john@example.com", 
        "SecurePass123!"
    )
    print(f"Registration: {message}")
    
    # Attempt authentication
    success, message, session_data = auth_system.authenticate(
        "john_doe", 
        "SecurePass123!",
        ip_address="192.168.1.100"
    )
    print(f"Authentication: {message}")
    
    if success and session_data:
        print(f"Session token: {session_data['session_token']}")
        
        # Verify session
        valid, user_info = auth_system.verify_session(session_data['session_token'])
        if valid:
            print(f"Session valid for user: {user_info['username']}")
    
    # Test brute force protection
    for i in range(6):
        success, message, _ = auth_system.authenticate(
            "john_doe", 
            "WrongPassword",
            ip_address="192.168.1.100"
        )
        print(f"Attempt {i+1}: {message}")
    
    # Try correct password after lockout
    success, message, _ = auth_system.authenticate(
        "john_doe", 
        "SecurePass123!",
        ip_address="192.168.1.100"
    )
    print(f"After lockout: {message}")