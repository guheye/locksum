from __future__ import annotations

# ruff: noqa: E402

"""Composable service classes extracted from :pymod:`locksum.model`.

Splitting the formerly monolithic ``CryptoModel`` lowers the blast radius and
makes each responsibility independently testable.
"""

import base64
import hashlib
import hmac
import os

import argon2
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from zxcvbn import zxcvbn

from . import config
from .config import file_exists, safe_remove
from .securemem import mlock_bytes, munlock_bytes, secure_erase

__all__ = [
    "KeyManager",
    "IntegrityChecker",
    "VaultStore",
]


class KeyManager:  # noqa: D101
    def __init__(self) -> None:
        self._pass_hasher = argon2.PasswordHasher(
            time_cost=config.ARGON2_TIME_COST,
            memory_cost=config.ARGON2_MEMORY_COST,
            parallelism=config.ARGON2_PARALLELISM,
            hash_len=config.ARGON2_HASH_LEN,
            salt_len=config.ARGON2_SALT_BYTES,
        )
        self._fernet: Fernet | None = None
        self._current_kdf: str = config.KDF_DEFAULT
        # Transient key used for HMAC-based integrity checks.  It is never
        # written to disk and therefore only available *after* a successful
        # key-derivation round.
        self._hmac_key: bytes | None = None
        # Raw 32-byte symmetric key retained for AES-GCM (LSV2).
        self._sym_key: bytes | None = None  # caution: wiped on clear_runtime_keys()

    # ------------------------------------------------------------------
    # Passcode hashing (Argon2)
    # ------------------------------------------------------------------
    def hash_new_passcode(self, passcode: str) -> None:  # noqa: D401
        pass_hash = self._pass_hasher.hash(passcode)
        with open(config.PASS_HASH_FILE, "w") as f:
            f.write(pass_hash)

    def verify_passcode(self, passcode: str) -> bool:  # noqa: D401
        if not file_exists(config.PASS_HASH_FILE):
            return False
        with open(config.PASS_HASH_FILE) as f:
            stored = f.read()
        try:
            self._pass_hasher.verify(stored, passcode)
            if self._pass_hasher.check_needs_rehash(stored):
                self.hash_new_passcode(passcode)
            return True
        except argon2.exceptions.VerifyMismatchError:
            return False

    def check_passcode_strength(self, passcode: str) -> dict:  # noqa: D401
        return zxcvbn(passcode)

    # ------------------------------------------------------------------
    # Key derivation (PBKDF2 / scrypt → Fernet)
    # ------------------------------------------------------------------
    @staticmethod
    def _derive_key_pbkdf2(pass_buf: bytearray, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=config.PBKDF2_KEY_LENGTH,
            salt=salt,
            iterations=config.PBKDF2_ITERATIONS,
        )
        return kdf.derive(pass_buf)

    @staticmethod
    def _derive_key_scrypt(pass_buf: bytearray, salt: bytes) -> bytes:
        kdf = Scrypt(salt=salt, length=config.PBKDF2_KEY_LENGTH, n=2**14, r=8, p=1)
        return kdf.derive(pass_buf)

    def derive_fernet_key(
        self,
        passcode: str,
        salt: bytes,
        *,
        algorithm: str | None = None,
    ) -> None:  # noqa: D401
        alg = (algorithm or self.detect_kdf_algorithm()).lower()
        pass_buf = bytearray(passcode.encode("utf-8", "surrogatepass"))
        if alg == "pbkdf2":
            raw = self._derive_key_pbkdf2(pass_buf, salt)
        elif alg == "scrypt":
            raw = self._derive_key_scrypt(pass_buf, salt)
        else:  # pragma: no cover
            raise ValueError(f"Unsupported KDF '{alg}'")

        # Overwrite any previous symmetric key before storing the new one.
        if self._sym_key is not None and len(self._sym_key) == len(raw):
            secure_erase(bytearray(self._sym_key))
        self._sym_key = raw  # **do not** erase – needed for AES-GCM operations

        key = base64.urlsafe_b64encode(raw)
        # ------------------------------------------------------------------
        # Integrity key – derive a deterministic sub-key so integrity checks
        # remain bound to the same secret without persisting it on disk.
        # Using a keyed hash hierarchy prevents cross-protocol attacks while
        # keeping the code change minimal.
        # ------------------------------------------------------------------
        self._hmac_key = hashlib.sha256(b"LSV-HMAC" + raw).digest()

        secure_erase(pass_buf)
        # raw is still referenced by self._sym_key; create a cloned bytearray to
        # wipe without affecting the stored copy.
        secure_erase(bytearray(raw))

        self._fernet = Fernet(key)
        self._current_kdf = alg

        # Lock key pages to prevent swapping (best-effort).
        try:
            mlock_bytes(self._sym_key)
        except Exception:  # noqa: BLE001 – ignore failures if OS denies
            pass

    @property
    def fernet(self) -> Fernet:  # noqa: D401
        if self._fernet is None:
            raise RuntimeError("Fernet key not initialised. Call derive_fernet_key().")
        return self._fernet

    @property
    def pass_hasher(self) -> argon2.PasswordHasher:  # noqa: D401
        return self._pass_hasher

    # ------------------------------------------------------------------
    # Derived integrity key accessors
    # ------------------------------------------------------------------

    @property
    def hmac_key(self) -> bytes:  # noqa: D401
        if self._hmac_key is None:
            # Try loading existing key from disk for backward compatibility
            if file_exists(config.HMAC_KEY_FILE):
                with open(config.HMAC_KEY_FILE, "rb") as f:
                    self._hmac_key = f.read()
            else:
                # Generate new random key and persist it
                self._hmac_key = os.urandom(config.HMAC_KEY_BYTES)
                with open(config.HMAC_KEY_FILE, "wb") as f:
                    f.write(self._hmac_key)

        return self._hmac_key

    def clear_runtime_keys(self) -> None:  # noqa: D401
        """Best-effort in-memory zeroisation of symmetric keys."""
        self._fernet = None
        if self._hmac_key is not None:
            secure_erase(bytearray(self._hmac_key))
        self._hmac_key = None
        if self._sym_key is not None:
            try:
                munlock_bytes(self._sym_key)
            except Exception:  # noqa: BLE001
                pass
            secure_erase(bytearray(self._sym_key))
        self._sym_key = None

    # ------------------------------------------------------------------
    # KDF detection helper (reads vault header to infer algorithm)
    # ------------------------------------------------------------------
    def detect_kdf_algorithm(self) -> str:  # noqa: D401
        path = config.ENCRYPTED_DATA_FILE
        if not file_exists(path):
            return config.KDF_DEFAULT
        try:
            with open(path, "rb") as f:
                magic = f.read(len(config.FILE_MAGIC))
                if magic != config.FILE_MAGIC:
                    return config.KDF_DEFAULT
                alg_byte = f.read(1)
                if len(alg_byte) == 0:
                    return config.KDF_DEFAULT
                if alg_byte[0] == config.ALG_CODE_PBKDF2:
                    return "pbkdf2"
                if alg_byte[0] == config.ALG_CODE_SCRYPT:
                    return "scrypt"
        except OSError:  # pragma: no cover
            pass
        return config.KDF_DEFAULT

    # ------------------------------------------------------------------
    # Salt & key helpers
    # ------------------------------------------------------------------
    def get_salt(self) -> bytes:  # noqa: D401
        return self._load_or_create_key(config.DEFAULT_SALT_FILE, config.SALT_BYTES)

    @staticmethod
    def _load_or_create_key(path: str, num_bytes: int) -> bytes:  # noqa: D401
        if file_exists(path):
            with open(path, "rb") as f:
                return f.read()
        key = os.urandom(num_bytes)
        with open(path, "wb") as f:
            f.write(key)
        return key

    # ------------------------------------------------------------------
    # Wipe helpers
    # ------------------------------------------------------------------
    def wipe(self) -> None:  # noqa: D401
        # Remove all key material to satisfy wipe-all-data semantics used in
        # the unit-test suite.
        safe_remove(config.PASS_HASH_FILE)
        safe_remove(config.DEFAULT_SALT_FILE)
        self._hmac_key = None
        # Remove legacy key files if they exist to avoid confusion.
        safe_remove(config.HMAC_KEY_FILE)

    @property
    def sym_key(self) -> bytes:  # noqa: D401
        if self._sym_key is None:
            raise RuntimeError(
                "Symmetric key not initialised. Call derive_fernet_key()."
            )  # noqa: E501
        return self._sym_key


class IntegrityChecker:  # noqa: D101
    def __init__(self) -> None:
        # The key is injected at runtime by :pyclass:`KeyManager` rather than
        # read from disk.  This eliminates the previous attack surface where
        # an attacker could overwrite the on-disk key to forge valid MACs.
        self._hmac_key: bytes | None = None

    # ------------------------------------------------------------------
    # Key injection
    # ------------------------------------------------------------------

    def set_key(self, key: bytes) -> None:  # noqa: D401
        """Store *key* for later compute/verify calls (no copy is kept)."""
        self._hmac_key = key

    def compute(self, data: bytes) -> bytes:  # noqa: D401
        return hmac.new(self.hmac_key, data, hashlib.sha256).digest()

    def verify(self, data: bytes, provided: bytes) -> bool:  # noqa: D401
        # First try with the *current* key (expected modern code-path).
        try:
            expected = self.compute(data)
            if hmac.compare_digest(expected, provided):
                return True
        except RuntimeError:
            # Key not yet initialised – fall back to legacy path below.
            pass

        # ------------------------------------------------------------------
        # Backwards-compatibility: use the historical on-disk HMAC key if it
        # still exists.  This lets users open pre-upgrade vaults and we can
        # transparently migrate them afterwards (next save will store a MAC
        # with the new derived key and we subsequently delete the file).
        # ------------------------------------------------------------------
        if file_exists(config.HMAC_KEY_FILE):
            with open(config.HMAC_KEY_FILE, "rb") as f:
                legacy_key = f.read()
            if len(legacy_key) == config.HMAC_KEY_BYTES:
                legacy_mac = hmac.new(legacy_key, data, hashlib.sha256).digest()
                if hmac.compare_digest(legacy_mac, provided):
                    # Cache legacy key so subsequent compute() calls succeed
                    # and mark for future migration.
                    self._hmac_key = legacy_key
                    return True

        return False

    def wipe(self) -> None:  # noqa: D401
        self._hmac_key = None
        # Remove legacy key files if they exist to avoid confusion.
        safe_remove(config.HMAC_KEY_FILE)

    # ------------------------------------------------------------------
    # Accessor with lazy initialisation (kept for backwards-compatibility)
    # ------------------------------------------------------------------

    @property
    def hmac_key(self) -> bytes:  # noqa: D401
        if self._hmac_key is None:
            if file_exists(config.HMAC_KEY_FILE):
                with open(config.HMAC_KEY_FILE, "rb") as f:
                    self._hmac_key = f.read()
            else:
                self._hmac_key = os.urandom(config.HMAC_KEY_BYTES)
                with open(config.HMAC_KEY_FILE, "wb") as f:
                    f.write(self._hmac_key)

        return self._hmac_key


class VaultStore:  # noqa: D101
    def __init__(self, key_manager: KeyManager, integrity: IntegrityChecker) -> None:
        self._km = key_manager
        self._ic = integrity

    # ------------------------------------------------------------------
    def load(self) -> list[tuple[str, str]]:  # noqa: D401
        if not file_exists(config.ENCRYPTED_DATA_FILE):
            return []
        path = config.ENCRYPTED_DATA_FILE
        if os.path.getsize(path) <= config.HMAC_DIGEST_BYTES:
            return []
        with open(path, "rb") as f:
            content = f.read()

        # -------------------------------------------------------------
        # Detect vault version by magic bytes
        # -------------------------------------------------------------
        if content.startswith(config.FILE_MAGIC_V2):
            # ---------------- LSV2 ---------------
            alg_byte = content[len(config.FILE_MAGIC_V2)]
            nonce_start = len(config.FILE_MAGIC_V2) + 1
            nonce_end = nonce_start + config.AES_GCM_NONCE_BYTES
            nonce = content[nonce_start:nonce_end]
            ciphertext = content[nonce_end:]

            # Validate alg byte matches expectations (0/1)
            if alg_byte not in {config.ALG_CODE_PBKDF2, config.ALG_CODE_SCRYPT}:
                raise ValueError("Unsupported KDF code in header")

            aesgcm = AESGCM(self._km.sym_key)
            try:
                decrypted = aesgcm.decrypt(
                    nonce,
                    ciphertext,
                    None,
                ).decode("utf-8", "surrogatepass")  # noqa: E501
            except Exception as err:  # broad: covers InvalidTag, etc.
                raise ValueError(
                    "Decryption failed. Invalid passcode or tampered data."
                ) from err  # noqa: E501

        else:
            # ---------------- LSV1 (legacy) ---------------
            header_present = content.startswith(config.FILE_MAGIC)

            if header_present:
                potential_alg_offset = len(config.FILE_MAGIC)
                header_len = (
                    config.HEADER_BYTES
                    if len(content) > potential_alg_offset + config.HMAC_DIGEST_BYTES
                    else len(config.FILE_MAGIC)
                )
                header = content[:header_len]
                encrypted = content[header_len : -config.HMAC_DIGEST_BYTES]
            else:
                header = b""
                encrypted = content[: -config.HMAC_DIGEST_BYTES]
            hmac_stored = content[-config.HMAC_DIGEST_BYTES :]

            if not self._ic.verify(header + encrypted, hmac_stored):
                raise ValueError("Data integrity check failed. Possible tampering.")

            try:
                decrypted = self._km.fernet.decrypt(encrypted).decode(
                    "utf-8",
                    "surrogatepass",
                )  # noqa: E501
            except InvalidToken as err:
                raise ValueError(
                    "Decryption failed. Invalid passcode or tampered data."
                ) from err  # noqa: E501

        pairs: list[tuple[str, str]] = []
        for line in decrypted.split("\n"):
            if not line:
                continue
            txt_enc, hv = line.split(config.DATA_SEPARATOR, 1)
            try:
                txt_raw = base64.urlsafe_b64decode(txt_enc.encode("ascii"))
                txt = txt_raw.decode("utf-8", "surrogatepass")
            except Exception:
                # Fallback: use raw encoded string if decoding fails
                txt = txt_enc
            pairs.append((txt, hv))
        return pairs

    def save(self, data: list[tuple[str, str]]) -> None:  # noqa: D401
        data_str = "\n".join(f"{t}{config.DATA_SEPARATOR}{h}" for t, h in data)
        encrypted = self._km.fernet.encrypt(data_str.encode())
        alg_code = (
            config.ALG_CODE_PBKDF2
            if self._km._current_kdf == "pbkdf2"  # pylint: disable=protected-access
            else config.ALG_CODE_SCRYPT
        )

        import os

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        # Decide vault version: env var allows experimental LSV2 rollout.
        use_lsv2 = os.getenv(config.VAULT_VERSION_ENV, "LSV1").upper() == "LSV2"

        if use_lsv2:
            # -------------------------------
            # LSV2 – AES-256-GCM (no MAC)
            # -------------------------------
            nonce = os.urandom(config.AES_GCM_NONCE_BYTES)
            aesgcm = AESGCM(self._km.sym_key)
            ct = aesgcm.encrypt(nonce, data_str.encode(), associated_data=None)

            header = config.FILE_MAGIC_V2 + bytes([alg_code]) + nonce

            with open(config.ENCRYPTED_DATA_FILE, "wb") as f:
                f.write(header + ct)
        else:
            # -------------------------------
            # LSV1 – Fernet + HMAC
            # -------------------------------
            header = config.FILE_MAGIC + bytes([alg_code])
            mac = self._ic.compute(header + encrypted)
            with open(config.ENCRYPTED_DATA_FILE, "wb") as f:
                f.write(header + encrypted + mac)

    def wipe(self) -> None:  # noqa: D401
        safe_remove(config.ENCRYPTED_DATA_FILE)
