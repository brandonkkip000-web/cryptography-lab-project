"""Command Line Interface for cryptography-lab-project.

Commands:
  - gen-keys: Generate RSA keypair and save to keys/private.pem and keys/public.pem
  - hash-pass "password": Hash a password with bcrypt
  - digest <file>: Compute SHA-256 digest
  - encrypt <file> --pubkey keys/public.pem: Encrypt file with AES-256-GCM and wrap key with RSA
  - decrypt <file.enc> --privkey keys/private.pem: Decrypt file and verify tag
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Optional

from Crypto.Random import get_random_bytes

from crypto_utils import (
    compute_sha256,
    encrypt_file_aes,
    decrypt_file_aes,
    generate_rsa_keys,
    encrypt_aes_key_rsa,
    decrypt_aes_key_rsa,
    b64encode_bytes,
    b64decode_to_bytes,
    save_json,
    load_json,
    build_encryption_metadata,
    hash_password,
    verify_password,
    sign_data,
    verify_signature,
)


def _default_paths():
    return {
        "uploads": os.path.join(os.path.dirname(__file__), "uploads"),
        "encrypted": os.path.join(os.path.dirname(__file__), "encrypted"),
        "decrypted": os.path.join(os.path.dirname(__file__), "decrypted"),
        "keys": os.path.join(os.path.dirname(__file__), "keys"),
    }


def cmd_gen_keys(_: argparse.Namespace) -> None:
    paths = _default_paths()
    os.makedirs(paths["keys"], exist_ok=True)
    priv, pub = generate_rsa_keys(2048)
    with open(os.path.join(paths["keys"], "private.pem"), "wb") as f:
        f.write(priv)
    with open(os.path.join(paths["keys"], "public.pem"), "wb") as f:
        f.write(pub)
    print("Generated RSA keypair under keys/ (private.pem, public.pem)")


def cmd_hash_pass(ns: argparse.Namespace) -> None:
    hashed = hash_password(ns.password)
    print(hashed.decode("utf-8"))


def cmd_digest(ns: argparse.Namespace) -> None:
    digest = compute_sha256(ns.file)
    print(digest)


def cmd_encrypt(ns: argparse.Namespace) -> None:
    paths = _default_paths()
    with open(ns.pubkey, "rb") as f:
        public_pem = f.read()
    aes_key = get_random_bytes(32)

    # Encrypt file with AES-GCM
    src_filename = os.path.basename(ns.file)
    sha_hex = compute_sha256(ns.file)
    out_base = os.path.splitext(src_filename)[0]
    enc_path = os.path.join(paths["encrypted"], out_base + ".enc")
    nonce, tag = encrypt_file_aes(ns.file, aes_key, enc_path)

    # Wrap AES key with RSA-OAEP
    wrapped = encrypt_aes_key_rsa(aes_key, public_pem)

    # Build metadata and signature over minimal canonical data (filename+sha)
    meta = build_encryption_metadata(
        original_filename=src_filename,
        sha256_digest_hex=sha_hex,
        aes_mode="AES-256-GCM",
        rsa_encrypted_key=wrapped,
        nonce=nonce,
        tag=tag,
        rsa_signature=None,  # filled via separate command if needed
    )
    meta_path = enc_path + ".json"
    save_json(meta, meta_path)
    print(f"Encrypted -> {enc_path}\nMetadata  -> {meta_path}")


def cmd_decrypt(ns: argparse.Namespace) -> None:
    paths = _default_paths()
    with open(ns.privkey, "rb") as f:
        private_pem = f.read()
    meta_path = ns.file + ".json"
    meta = load_json(meta_path)
    if not meta:
        print("Error: metadata JSON not found for encrypted file.", file=sys.stderr)
        sys.exit(2)

    # Unwrap AES key
    wrapped_b64 = meta.get("rsa_encrypted_key_b64")
    if not wrapped_b64:
        print("Error: metadata missing RSA-encrypted AES key.", file=sys.stderr)
        sys.exit(2)
    aes_key = decrypt_aes_key_rsa(b64decode_to_bytes(wrapped_b64), private_pem)

    # Decrypt
    out_name = meta.get("original_filename", "decrypted.bin")
    out_path = os.path.join(paths["decrypted"], out_name)
    decrypt_file_aes(ns.file, aes_key, out_path)

    # Verify SHA-256 for integrity (GCM already authenticates; this is educational)
    calc_sha = compute_sha256(out_path)
    if calc_sha != meta.get("sha256_digest_hex"):
        print("Warning: SHA-256 mismatch after decryption!", file=sys.stderr)
        sys.exit(3)
    print(f"Decrypted -> {out_path}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="cryptography-lab-project CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    s1 = sub.add_parser("gen-keys", help="Generate RSA keypair into keys/")
    s1.set_defaults(func=cmd_gen_keys)

    s2 = sub.add_parser("hash-pass", help="Hash a password with bcrypt")
    s2.add_argument("password", help="Plaintext password")
    s2.set_defaults(func=cmd_hash_pass)

    s3 = sub.add_parser("digest", help="Compute SHA-256 of a file")
    s3.add_argument("file", help="Path to file")
    s3.set_defaults(func=cmd_digest)

    s4 = sub.add_parser("encrypt", help="Encrypt a file with AES-256-GCM and RSA key wrap")
    s4.add_argument("file", help="Path to file to encrypt")
    s4.add_argument("--pubkey", required=True, help="Path to RSA public key PEM")
    s4.set_defaults(func=cmd_encrypt)

    s5 = sub.add_parser("decrypt", help="Decrypt a file produced by encrypt")
    s5.add_argument("file", help="Path to encrypted .enc file")
    s5.add_argument("--privkey", required=True, help="Path to RSA private key PEM")
    s5.set_defaults(func=cmd_decrypt)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    ns = parser.parse_args(argv)
    ns.func(ns)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


