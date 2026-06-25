"""Password hashing compatible with bcrypt 4.x/5.x (no passlib)."""

import bcrypt

_MAX_PASSWORD_BYTES = 72


def _normalize(password: str) -> bytes:
    raw = password.encode("utf-8")
    if len(raw) > _MAX_PASSWORD_BYTES:
        raw = raw[:_MAX_PASSWORD_BYTES]
    return raw


def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        _normalize(password),
        bcrypt.gensalt(rounds=12),
    ).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(
            _normalize(plain_password),
            hashed_password.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False
