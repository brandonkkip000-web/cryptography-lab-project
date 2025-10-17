"""Shared utilities for base64 conversions and JSON metadata handling.

These helpers keep encoding/decoding and metadata I/O consistent across the
project. All functions here are intentionally small and dependency-light so
they can be used from any module.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict


def b64encode_bytes(data: bytes) -> str:
    """Return URL-safe base64 string without newlines for given bytes."""

    return base64.urlsafe_b64encode(data).decode("utf-8")


def b64decode_to_bytes(data_b64: str) -> bytes:
    """Decode URL-safe base64 string into bytes, forgiving missing padding."""

    padding_needed = (-len(data_b64)) % 4
    data_b64_padded = data_b64 + ("=" * padding_needed)
    return base64.urlsafe_b64decode(data_b64_padded.encode("utf-8"))


def load_json(path: str) -> Dict[str, Any]:
    """Load JSON file as dict. Returns empty dict if file does not exist."""

    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(obj: Dict[str, Any], path: str) -> None:
    """Write dict to JSON file with indentation and stable key order."""

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)


@dataclass
class EncryptionMetadata:
    """Container for encryption metadata stored alongside ciphertext.

    Fields intentionally use JSON-friendly types (str, int) and base64 for
    bytes. Times are ISO 8601 in UTC.
    """

    original_filename: str
    sha256_digest_hex: str
    aes_mode: str
    rsa_encrypted_key_b64: str
    nonce_b64: str
    tag_b64: str
    timestamp_utc: str
    rsa_signature_b64: str | None = None


def build_encryption_metadata(
    *,
    original_filename: str,
    sha256_digest_hex: str,
    aes_mode: str,
    rsa_encrypted_key: bytes,
    nonce: bytes,
    tag: bytes,
    rsa_signature: bytes | None = None,
) -> Dict[str, Any]:
    """Build a dict suitable for JSON serialization with standard fields."""

    timestamp = datetime.now(timezone.utc).isoformat()
    meta = EncryptionMetadata(
        original_filename=original_filename,
        sha256_digest_hex=sha256_digest_hex,
        aes_mode=aes_mode,
        rsa_encrypted_key_b64=b64encode_bytes(rsa_encrypted_key),
        nonce_b64=b64encode_bytes(nonce),
        tag_b64=b64encode_bytes(tag),
        timestamp_utc=timestamp,
        rsa_signature_b64=b64encode_bytes(rsa_signature) if rsa_signature else None,
    )
    return asdict(meta)


