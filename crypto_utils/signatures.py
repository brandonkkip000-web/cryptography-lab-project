from __future__ import annotations

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss


def sign_data(data: bytes, private_key_pem: bytes) -> bytes:
  
    key = RSA.import_key(private_key_pem)
    h = SHA256.new(data)
    signer = pss.new(key)
    return signer.sign(h)


def verify_signature(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
   
    key = RSA.import_key(public_key_pem)
    h = SHA256.new(data)
    verifier = pss.new(key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


