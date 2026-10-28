import pytest
from agent.auth import (
    hash_password,
    verify_password,
    authenticate_analyst,
    MAX_ATTEMPTS,
    _FAILED_ATTEMPTS
)


def test_hash_and_verify_password():
    pwd = "SecuredPassword99!"
    hashed = hash_password(pwd)
    assert hashed.startswith("pbkdf2_sha256$")
    assert verify_password(pwd, hashed)
    assert not verify_password("WrongPassword!", hashed)


def test_malformed_hash_verification():
    assert not verify_password("test", "invalid$format")
    assert not verify_password("test", "")


def test_authenticate_analyst_success():
    success, msg, profile = authenticate_analyst("analyst", "VaptSecure2026!")
    assert success
    assert profile is not None
    assert profile["username"] == "analyst"
    assert profile["role"] == "Lead Penetration Tester"
    assert "session_token" in profile
    assert len(profile["session_token"]) == 48


def test_authenticate_analyst_bad_credentials():
    success, msg, profile = authenticate_analyst("analyst", "IncorrectPassword123")
    assert not success
    assert profile is None
    assert "Invalid" in msg


def test_authenticate_unknown_user():
    success, msg, profile = authenticate_analyst("ghost_user", "password")
    assert not success
    assert profile is None


def test_brute_force_lockout():
    user = "lockout_test_analyst"
    _FAILED_ATTEMPTS.clear()
    for _ in range(MAX_ATTEMPTS):
        success, msg, _ = authenticate_analyst(user, "wrong")
        assert not success

    # 6th attempt should hit lockout
    success, msg, profile = authenticate_analyst(user, "wrong")
    assert not success
    assert "temporarily locked" in msg.lower()
    _FAILED_ATTEMPTS.clear()
