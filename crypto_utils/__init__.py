"""Utility package exposing cryptographic helpers for the project.

Modules
-------
- bcrypt_hash: bcrypt password hashing and verification
- sha256_digest: streaming SHA-256 file digest
- aes_cipher: AES-256 file encryption/decryption (GCM mode)
- rsa_cipher: RSA key generation and OAEP key wrapping
- signatures: RSA-PSS digital signatures
- utils: base64 helpers and metadata helpers
"""

from .bcrypt_hash import hash_password, verify_password
from .sha256_digest import compute_sha256
from .aes_cipher import encrypt_file_aes, decrypt_file_aes
from .rsa_cipher import (
    generate_rsa_keys,
    encrypt_aes_key_rsa,
    decrypt_aes_key_rsa,
)
from .signatures import sign_data, verify_signature
from .utils import (
    b64encode_bytes,
    b64decode_to_bytes,
    load_json,
    save_json,
    build_encryption_metadata,
)

__all__ = [
    "hash_password",
    "verify_password",
    "compute_sha256",
    "encrypt_file_aes",
    "decrypt_file_aes",
    "generate_rsa_keys",
    "encrypt_aes_key_rsa",
    "decrypt_aes_key_rsa",
    "sign_data",
    "verify_signature",
    "b64encode_bytes",
    "b64decode_to_bytes",
    "load_json",
    "save_json",
    "build_encryption_metadata",
]


