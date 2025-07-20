# Locksum Threat Model

_Last updated: 2025-07-19_

## 1. Security Goals

* **Confidentiality** – Text–hash pairs and passcode–derived keys must remain secret on disk and in memory as far as practical for a Python application.
* **Integrity** – Detect any modification of the encrypted vault or supporting key files.
* **Availability** – Users must be able to access data with the correct passcode; accidental lock-outs should be impossible.

## 2. Assets

| Asset | Sensitivity | Notes |
|-------|-------------|-------|
| Encrypted vault (`encrypted_data.bin`) | High | Contains user secrets (plaintext + hashes). |
| Passcode hash (`pass_hash.bin`) | High | Needed to verify passcode; might aid offline brute-force. |
| Salt / HMAC / KDF keys | High | Required to derive keys and validate integrity. |
| In-memory plaintext & keys | High | Present only during active session; wiped afterwards. |

## 3. Adversary Model

| Capability | Included? | Rationale |
|-------------|----------|-----------|
| Read local files | Yes | Laptop stolen, cloud backup leak. |
| Modify local files | Yes | Malware tampers with vault to plant fake data. |
| Observe RAM after process exit | Partially | Memory zeroisation best-effort; Python may copy data. |
| Live RAM scraping while process runs | Out of scope | Requires low-level OS protections beyond Python. |
| Network attacker | N/A | App is fully offline. |

## 4. Trust Assumptions

* The Python interpreter and underlying OS are trusted.
* Disk encryption (e.g. FileVault, BitLocker) is encouraged but not assumed.
* Users choose sufficiently strong passcodes (enforced via zxcvbn score ≥ 2).

## 5. Mitigations

| Threat | Mitigation |
|--------|------------|
| Offline brute-force of passcode | Argon2-id hash, ≥ 64 MiB memory, auto-rehash on policy change. |
| Vault tampering | HMAC-SHA256 over header + ciphertext; detected on load. |
| Ciphertext bit-flipping | Authenticated Fernet token; invalid token triggers error. |
| Stale crypto parameters | Header encodes KDF; auto-rehash upgrades passcode hash. |
| Memory leakage | `secure_erase` overwrites passcodes / derived keys ASAP. |
| Cache-side channels | Modern AEAD (AES-GCM) reduces malleability; full constant-time implementation remains future work. |

## 6. Out-of-Scope Items

* Advanced side-channel attacks (cache-timing, micro-architectural).  
* We now acknowledge data-dependent timing risks and plan constant-time primitives in a future C extension.  
* Malicious Python packages or compromised runtime.  
* Attackers with live debugger access during an active session.

## 7. Future Work

1. Migrate from Fernet to libsodium `secretbox` for stronger primitives and wider language support.  
2. Add authenticated metadata (creation date, argon2 params) in header.  
3. Encrypt-in-memory buffers (requires C extension).  
4. Integration with FIDO2 / WebAuthn for second factor. 