"""RSA helpers: key generation and OAEP encryption/decryption of AES keys.

We use 2048-bit RSA keys by default and OAEP with SHA-256 for padding,
which is the modern, secure choice for RSA encryption.
"""

from __future__ import annotations

from typing import Tuple

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256


def generate_rsa_keys(bits: int = 2048) -> Tuple[bytes, bytes]:
    """Generate an RSA private/public key pair and return PEM-encoded bytes."""

    key = RSA.generate(bits)
    private_pem = key.export_key(format="PEM")
    public_pem = key.publickey().export_key(format="PEM")
    return private_pem, public_pem


def encrypt_aes_key_rsa(aes_key: bytes, public_key_pem: bytes) -> bytes:
    """Encrypt an AES key using RSA-OAEP with SHA-256, returning ciphertext."""

    rsa_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    return cipher_rsa.encrypt(aes_key)


def decrypt_aes_key_rsa(encrypted_key: bytes, private_key_pem: bytes) -> bytes:
    """Decrypt an RSA-OAEP wrapped AES key using the RSA private key."""

    rsa_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    return cipher_rsa.decrypt(encrypted_key)


