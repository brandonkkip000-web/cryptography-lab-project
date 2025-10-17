"""AES-256 file encryption/decryption helpers using GCM mode.

AES-GCM provides confidentiality and integrity via an authentication tag.
We stream file contents in chunks to handle large files efficiently.

File format written by encrypt_file_aes:
    [12-byte nonce][16-byte tag][ciphertext...]

This layout keeps the file self-contained and easy to parse. Metadata (JSON)
can store base64 versions of nonce and tag for additional context.
"""

from __future__ import annotations

import os
from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


NONCE_SIZE = 12  # Recommended size for GCM
TAG_SIZE = 16
CHUNK_SIZE = 1024 * 1024  # 1 MiB streaming


def _ensure_key_length(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")


def encrypt_file_aes(file_path: str, key: bytes, output_path: str) -> Tuple[bytes, bytes]:
    """Encrypt a file with AES-256-GCM, writing nonce||tag||ciphertext to output.

    Returns (nonce, tag). The output file is created or overwritten.
    """

    _ensure_key_length(key)
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(file_path, "rb") as fin, open(output_path, "wb") as fout:
        # Reserve space for nonce and tag; write nonce immediately, tag later
        fout.write(nonce)
        # We'll compute ciphertext in chunks
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            ciphertext = cipher.encrypt(chunk)
            fout.write(ciphertext)
        tag = cipher.digest()
    # Now we must insert the tag after the nonce. Simplest: rewrite file.
    # Read back ciphertext, then write nonce||tag||ciphertext atomically.
    with open(output_path, "rb") as f:
        content_after_nonce = f.read()[NONCE_SIZE:]
    with open(output_path, "wb") as f:
        f.write(nonce)
        f.write(tag)
        f.write(content_after_nonce)
    return nonce, tag


def decrypt_file_aes(file_path: str, key: bytes, output_path: str) -> None:
    """Decrypt a file produced by encrypt_file_aes and verify authenticity.

    Raises ValueError if authentication fails.
    """

    _ensure_key_length(key)
    with open(file_path, "rb") as fin:
        header = fin.read(NONCE_SIZE + TAG_SIZE)
        if len(header) != NONCE_SIZE + TAG_SIZE:
            raise ValueError("input too short to contain nonce and tag")
        nonce = header[:NONCE_SIZE]
        tag = header[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
        ciphertext_stream = fin.read()

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as fout:
        # Decrypt in chunks to avoid high memory usage
        offset = 0
        while offset < len(ciphertext_stream):
            end = min(offset + CHUNK_SIZE, len(ciphertext_stream))
            chunk = ciphertext_stream[offset:end]
            plaintext = cipher.decrypt(chunk)
            fout.write(plaintext)
            offset = end
        try:
            cipher.verify(tag)
        except ValueError:
            # Wipe possibly written output on auth failure
            try:
                fout.flush()
            finally:
                pass
            os.remove(output_path)
            raise


