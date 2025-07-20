# Encrypted Vault Format

> Version: **LSV1** (stable, Fernet) – **LSV2** (experimental, AES-256-GCM)

Locksum stores all text–hash pairs inside a single binary file `encrypted_data.bin`.  The file begins with a **fixed header** that unambiguously identifies the format version and the key-derivation function (KDF) used to derive the encryption key.

```text
+---------+-------------+----------------------+----------------+
| Offset  | Size (bytes)| Purpose              | Notes          |
+=========+=============+======================+================+
| 0       | 4           | Magic "LSVx"         | x = version no |
| 4       | 1           | KDF code             | 0 = PBKDF2     |
|         |             |                      | 1 = scrypt     |
| 5       | …           | Ciphertext           | Variable       |
| n-16    | 16 or 32    | Authentication tag   | AEAD or HMAC   |
+---------+-------------+----------------------+----------------+
```

## Header Fields

* **Magic** – ASCII `LSV1` for the legacy Fernet+HMAC scheme.  `LSV2` indicates the experimental AES-GCM AEAD scheme (enable via `LOCKSUM_VAULT_VERSION=LSV2`).
* **KDF code** – Single byte that informs Locksum which key derivation algorithm to run *before* decryption.

## Cryptography

| Version | Cipher | Integrity | Notes                             |
|---------|--------|-----------|-----------------------------------|
| LSV1    | Fernet | HMAC-SHA256 | Current stable format.            |
| LSV2    | AES-256-GCM | AEAD (tag appended) | Experimental – opt-in via env var. |

## Test Vector (LSV1)

This vector was generated with passcode `correct horse battery staple` and random 16-byte salt `000102030405060708090a0b0c0d0e0f`.

```
Magic:         4C 53 56 31                          # "LSV1"
KDF byte:      00                                  # PBKDF2 (01 = scrypt)
Ciphertext:    <truncated>
HMAC:          <last-32-bytes>
```

Use `tests/test_vault_format.py` (once implemented) for automated verification.

## Forward Compatibility

Future versions must *extend* the header rather than change existing fields.  Parsers must ignore unknown bytes that appear **after** the mandatory section above. 