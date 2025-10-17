## cryptography-lab-project

Educational, modular Python project demonstrating modern cryptographic primitives and best practices:

- bcrypt for password hashing
- SHA-256 for file fingerprinting
- AES-256-GCM for authenticated encryption
- RSA (OAEP) for AES key wrapping
- RSA-PSS for digital signatures

### Why this project?
This lab is designed for university cybersecurity courses. It shows how to combine building-block primitives into a practical workflow: hashing a password, computing a file digest, encrypting with AES, wrapping the AES key with RSA, signing metadata, and verifying integrity.

### Requirements
- Python 3.10+
- Libraries: `pycryptodome`, `bcrypt` (plus `tabulate` for nice tables)

Install dependencies:
```bash
pip install -r requirements.txt
```

### Project structure
```
cryptography-lab-project/
├── main.py                        # End-to-end demo
├── cli.py                         # Command-line interface
├── crypto_utils/
│   ├── __init__.py
│   ├── bcrypt_hash.py             # bcrypt hashing
│   ├── sha256_digest.py           # streaming SHA-256 digest
│   ├── aes_cipher.py              # AES-256-GCM encrypt/decrypt
│   ├── rsa_cipher.py              # RSA keygen + OAEP key wrap
│   ├── signatures.py              # RSA-PSS signatures
│   └── utils.py                   # base64 + metadata helpers
├── uploads/                       # unencrypted files
├── encrypted/                     # encrypted output + JSON metadata
├── decrypted/                     # decrypted files
├── keys/                          # RSA key storage
├── requirements.txt
└── README.md
```

### How the algorithms work (short explanations)
- bcrypt: Password hashing with built-in salt and cost, intentionally slow to resist brute-force.
- SHA-256: Cryptographic hash used here to fingerprint files for integrity checks.
- AES-256-GCM: Symmetric authenticated encryption. Provides confidentiality and integrity via a nonce and tag.
- RSA-OAEP: Asymmetric encryption with padding designed for security; used to wrap the random AES key.
- RSA-PSS: Probabilistic signature scheme providing strong security; used to sign metadata.

### Run the demo
```bash
python main.py
```
The demo will:
1. Hash and verify a sample password
2. Compute SHA-256 of `uploads/sample.txt` (auto-created if missing)
3. Encrypt it with AES-256-GCM
4. Generate an RSA keypair
5. Wrap the AES key with RSA-OAEP
6. Sign metadata with RSA-PSS
7. Decrypt and verify integrity

### CLI usage
```bash
# Generate RSA keypair into keys/
python cli.py gen-keys

# Hash a password
python cli.py hash-pass "correct horse battery staple"

# Compute SHA-256 of a file
python cli.py digest uploads/sample.txt

# Encrypt a file with AES-256-GCM and wrap key with RSA-OAEP
python cli.py encrypt uploads/sample.txt --pubkey keys/public.pem

# Decrypt the file and verify integrity
python cli.py decrypt encrypted/sample.enc --privkey keys/private.pem
```

The `encrypt` command emits two artifacts:
- `encrypted/<name>.enc`: nonce||tag||ciphertext
- `encrypted/<name>.enc.json`: metadata with base64 fields and timestamp

### Example output (abridged)
```
== bcrypt demo ==
hash len: 60 bytes | verify ok=True not_ok=False | 100.5 ms

== SHA-256 digest ==
1f3d...c2e | 0.8 ms

== RSA keygen ==
Generated 2048-bit RSA keypair | 75.2 ms

== AES-256-GCM encrypt ==
Encrypted to encrypted/sample.enc | 1.4 ms | nonce=12B tag=16B

== RSA-OAEP wrap AES key ==
Wrapped AES key | 0.7 ms | wrapped_len=256B
RSA-PSS signature verified=True
Saved metadata -> encrypted/sample.enc.json

== RSA-OAEP unwrap and decrypt ==
Unwrapped in 0.6 ms; Decrypted to decrypted/sample.txt in 0.7 ms
Digest match after decrypt: True
```

### Metadata JSON fields
- `original_filename`: source filename
- `sha256_digest_hex`: hex digest of plaintext file
- `aes_mode`: e.g., `AES-256-GCM`
- `rsa_encrypted_key_b64`: base64 RSA-wrapped AES key
- `nonce_b64`, `tag_b64`: base64 GCM values
- `rsa_signature_b64`: base64 RSA-PSS signature over `filename|sha256`
- `timestamp_utc`: ISO 8601

### Security notes and best practices
- Always use secure randomness for keys and nonces.
- Never reuse a nonce with AES-GCM for the same key.
- Store bcrypt hashes only, never plaintext passwords.
- Use OAEP (not raw RSA) for encryption; use PSS for signatures.
- Validate and handle errors: failed tag verification means tampering.

### Creativity and extensions
- Add a Tkinter GUI to run operations interactively.
- Add performance tables comparing file sizes and timings.
- Extend CLI to sign/verify arbitrary data or metadata files.

### Author and License
Author: Your Name
License: MIT


