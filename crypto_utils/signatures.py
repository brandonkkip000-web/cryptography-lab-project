"""RSA-PSS digital signatures.

RSA-PSS with SHA-256 is a modern, probabilistic signature scheme providing
strong security guarantees. Use for authenticating metadata or digests.
"""

from __future__ import annotations

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss


def sign_data(data: bytes, private_key_pem: bytes) -> bytes:
    """Produce an RSA-PSS signature over data using SHA-256."""

    key = RSA.import_key(private_key_pem)
    h = SHA256.new(data)
    signer = pss.new(key)
    return signer.sign(h)


def verify_signature(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """Verify an RSA-PSS signature. Returns True if valid, else False."""

    key = RSA.import_key(public_key_pem)
    h = SHA256.new(data)
    verifier = pss.new(key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


