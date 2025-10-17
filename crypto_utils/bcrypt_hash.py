from __future__ import annotations

import bcrypt


def hash_password(password: str) -> bytes:
  
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password_bytes, salt)


def verify_password(password: str, hashed: bytes) -> bool:
  
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if not isinstance(hashed, (bytes, bytearray)):
        raise TypeError("hashed must be bytes")
    return bcrypt.checkpw(password.encode("utf-8"), hashed)


