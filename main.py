"""Main demo for cryptography-lab-project.

Runs an end-to-end demonstration:
  1) bcrypt password hashing and verification
  2) SHA-256 digest of a sample file in uploads/
  3) AES-256-GCM file encryption
  4) RSA keypair generation
  5) RSA-OAEP wrapping of AES key
  6) Decryption and integrity verification
  7) Optional RSA-PSS signature over metadata
Includes simple timing outputs for educational purposes.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from Crypto.Random import get_random_bytes

from crypto_utils import (
    hash_password,
    verify_password,
    compute_sha256,
    encrypt_file_aes,
    decrypt_file_aes,
    generate_rsa_keys,
    encrypt_aes_key_rsa,
    decrypt_aes_key_rsa,
    sign_data,
    verify_signature,
    save_json,
    build_encryption_metadata,
)


def _paths():
    base = os.path.dirname(__file__)
    return {
        "uploads": os.path.join(base, "uploads"),
        "encrypted": os.path.join(base, "encrypted"),
        "decrypted": os.path.join(base, "decrypted"),
        "keys": os.path.join(base, "keys"),
    }


def ensure_sample_file(path: str) -> None:
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("Hello cryptography lab!\nThis is a sample file for testing.\n")


def main() -> int:
    p = _paths()
    sample = os.path.join(p["uploads"], "sample.txt")
    ensure_sample_file(sample)

    print("== bcrypt demo ==")
    start = time.perf_counter()
    hashed = hash_password("correct horse battery staple")
    ok = verify_password("correct horse battery staple", hashed)
    not_ok = verify_password("wrong password", hashed)
    elapsed = (time.perf_counter() - start) * 1000
    print(f"hash len: {len(hashed)} bytes | verify ok={ok} not_ok={not_ok} | {elapsed:.1f} ms")

    print("\n== SHA-256 digest ==")
    start = time.perf_counter()
    sha_hex = compute_sha256(sample)
    elapsed = (time.perf_counter() - start) * 1000
    print(f"{sha_hex} | {elapsed:.1f} ms")

    print("\n== RSA keygen ==")
    start = time.perf_counter()
    priv_pem, pub_pem = generate_rsa_keys(2048)
    os.makedirs(p["keys"], exist_ok=True)
    with open(os.path.join(p["keys"], "private.pem"), "wb") as f:
        f.write(priv_pem)
    with open(os.path.join(p["keys"], "public.pem"), "wb") as f:
        f.write(pub_pem)
    elapsed = (time.perf_counter() - start) * 1000
    print(f"Generated 2048-bit RSA keypair | {elapsed:.1f} ms")

    print("\n== AES-256-GCM encrypt ==")
    aes_key = get_random_bytes(32)
    enc_out = os.path.join(p["encrypted"], "sample.enc")
    start = time.perf_counter()
    nonce, tag = encrypt_file_aes(sample, aes_key, enc_out)
    enc_ms = (time.perf_counter() - start) * 1000
    print(f"Encrypted to {enc_out} | {enc_ms:.1f} ms | nonce={len(nonce)}B tag={len(tag)}B")

    print("\n== RSA-OAEP wrap AES key ==")
    start = time.perf_counter()
    wrapped = encrypt_aes_key_rsa(aes_key, pub_pem)
    wrap_ms = (time.perf_counter() - start) * 1000
    print(f"Wrapped AES key | {wrap_ms:.1f} ms | wrapped_len={len(wrapped)}B")

    # Optional: sign metadata with RSA-PSS
    meta_core = f"{os.path.basename(sample)}|{sha_hex}".encode("utf-8")
    signature = sign_data(meta_core, priv_pem)
    sig_ok = verify_signature(meta_core, signature, pub_pem)
    print(f"RSA-PSS signature verified={sig_ok}")

    meta = build_encryption_metadata(
        original_filename=os.path.basename(sample),
        sha256_digest_hex=sha_hex,
        aes_mode="AES-256-GCM",
        rsa_encrypted_key=wrapped,
        nonce=nonce,
        tag=tag,
        rsa_signature=signature,
    )
    meta_path = enc_out + ".json"
    save_json(meta, meta_path)
    print(f"Saved metadata -> {meta_path}")

    print("\n== RSA-OAEP unwrap and decrypt ==")
    start = time.perf_counter()
    unwrapped = decrypt_aes_key_rsa(wrapped, priv_pem)
    unwrap_ms = (time.perf_counter() - start) * 1000
    dec_out = os.path.join(p["decrypted"], "sample.txt")
    start2 = time.perf_counter()
    decrypt_file_aes(enc_out, unwrapped, dec_out)
    dec_ms = (time.perf_counter() - start2) * 1000
    print(f"Unwrapped in {unwrap_ms:.1f} ms; Decrypted to {dec_out} in {dec_ms:.1f} ms")

    sha_after = compute_sha256(dec_out)
    print(f"Digest match after decrypt: {sha_after == sha_hex}")

    print("\nAll steps completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


