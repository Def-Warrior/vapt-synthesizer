"""
agent/auth.py
Secure Role-Based Authentication System for VAPT Synthesizer.
Operates 100% offline with zero external cloud or identity provider dependencies.
Implements PBKDF2-HMAC-SHA256 password hashing and session token verification.
"""

from __future__ import annotations
import hashlib
import hmac
import os
import secrets
import time
from typing import Any, Dict, Optional, Tuple

PBKDF2_ITERATIONS = 120_000
SALT_BYTES = 16


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    """Hashes a password with PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${derived.hex()}"


def verify_password(password: str, hashed_value: str) -> bool:
    """Constant-time verification of password against stored PBKDF2 hash."""
    try:
        parts = hashed_value.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected_derived = bytes.fromhex(parts[3])
        actual_derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(expected_derived, actual_derived)
    except Exception:
        return False


# In-memory user database for air-gapped security operations.
# Can be overridden via environment variables for deployment flexibility.
DEFAULT_ANALYSTS = {
    "analyst": {
        "username": "analyst",
        "name": "Alex Vance",
        "role": "Lead Penetration Tester",
        "clearance": "Top Secret / Operational",
        "password_hash": hash_password(os.getenv("VAPT_ANALYST_PASSWORD", "VaptSecure2026!"))
    },
    "auditor": {
        "username": "auditor",
        "name": "Sarah Connor",
        "role": "Compliance & Security Auditor",
        "clearance": "Confidential / Audit Only",
        "password_hash": hash_password(os.getenv("VAPT_AUDITOR_PASSWORD", "AuditSafe2026!"))
    },
    "admin": {
        "username": "admin",
        "name": "Chief Security Officer",
        "role": "Air-Gap Admin & Red Team Lead",
        "clearance": "Director / All Access",
        "password_hash": hash_password(os.getenv("VAPT_ADMIN_PASSWORD", "AdminAirGap2026!"))
    }
}

# Failed attempt tracker for brute-force lock protection
_FAILED_ATTEMPTS: Dict[str, Tuple[int, float]] = {}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 60.0


def authenticate_analyst(username: str, password: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Authenticates an analyst using credentials.
    Returns: (success: bool, status_message: str, user_profile: dict | None)
    """
    username_clean = username.strip().lower()
    now = time.time()

    # Check brute force lockout
    if username_clean in _FAILED_ATTEMPTS:
        attempts, last_time = _FAILED_ATTEMPTS[username_clean]
        if attempts >= MAX_ATTEMPTS:
            remaining = int(LOCKOUT_SECONDS - (now - last_time))
            if remaining > 0:
                return False, f"Account temporarily locked due to failed attempts. Try again in {remaining}s.", None
            else:
                del _FAILED_ATTEMPTS[username_clean]

    user = DEFAULT_ANALYSTS.get(username_clean)
    if not user:
        _record_failed_attempt(username_clean)
        return False, "Invalid analyst username or credentials.", None

    if not verify_password(password, user["password_hash"]):
        _record_failed_attempt(username_clean)
        return False, "Invalid analyst username or credentials.", None

    # Reset attempts on success
    if username_clean in _FAILED_ATTEMPTS:
        del _FAILED_ATTEMPTS[username_clean]

    session_token = secrets.token_hex(24)
    profile = {
        "username": user["username"],
        "name": user["name"],
        "role": user["role"],
        "clearance": user["clearance"],
        "authenticated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "session_token": session_token
    }
    return True, f"Welcome, {user['name']} ({user['role']})", profile


def _record_failed_attempt(username: str) -> None:
    now = time.time()
    if username in _FAILED_ATTEMPTS:
        attempts, _ = _FAILED_ATTEMPTS[username]
        _FAILED_ATTEMPTS[username] = (attempts + 1, now)
    else:
        _FAILED_ATTEMPTS[username] = (1, now)
