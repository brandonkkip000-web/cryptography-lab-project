"""bcrypt password hashing utilities.

This module provides a minimal API for password hashing and verification using
`bcrypt`. bcrypt is intentionally slow to resist brute-force attacks. We use
`bcrypt.gensalt()` which generates a secure random salt and encodes cost in the
hash string.
"""

from __future__ import annotations

import bcrypt


def hash_password(password: str) -> bytes:
    """Hash a plaintext password and return the bcrypt hash as bytes.

    The returned hash embeds the salt and cost parameter. Store the hash as-is.
    """

    if not isinstance(password, str):
        raise TypeError("password must be a string")
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password_bytes, salt)


def verify_password(password: str, hashed: bytes) -> bool:
    """Verify a plaintext password against a stored bcrypt hash.

    Returns True if the password matches, False otherwise.
    """

    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if not isinstance(hashed, (bytes, bytearray)):
        raise TypeError("hashed must be bytes")
    return bcrypt.checkpw(password.encode("utf-8"), hashed)


