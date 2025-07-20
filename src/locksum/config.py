from __future__ import annotations

import os
from pathlib import Path
from typing import Final

"""Centralised configuration and paths for Locksum.

Supports optional ``LOCKSUM_DATA_DIR`` environment variable so all secret
artifacts live outside the repo (useful for tests/production)."""

# -----------------------------------------------------------------------------
# Data directory – default to ~/.locksum unless an override is supplied
# -----------------------------------------------------------------------------
# If the user sets the *LOCKSUM_DATA_DIR* environment variable we honour it, otherwise
# fall back to a hidden directory in their home folder.  Using a location outside the
# working tree avoids accidental commits of secret artefacts and aligns with common
# XDG-style conventions.


_env_dir = os.getenv("LOCKSUM_DATA_DIR")

if _env_dir:
    _data_dir = Path(_env_dir).expanduser().resolve()
else:
    _data_dir = (Path.home() / ".locksum").resolve()

DATA_DIR: Final[Path] = _data_dir

# Ensure the path exists so subsequent open() calls do not fail.  This is safe at
# import-time because the directory is user-specific and requires no elevated
# privileges.
DATA_DIR.mkdir(parents=True, exist_ok=True)

# -----------------------------------------------------------------------------
# Default file paths for security artifacts and data.
# -----------------------------------------------------------------------------
DEFAULT_SALT_FILE: Final[str] = str(DATA_DIR / "salt.bin")
HMAC_KEY_FILE: Final[str] = str(DATA_DIR / "hmac_key.bin")
PASS_HASH_FILE: Final[str] = str(DATA_DIR / "pass_hash.bin")
ENCRYPTED_DATA_FILE: Final[str] = str(DATA_DIR / "encrypted_data.bin")

# -----------------------------------------------------------------------------
# Argon2 password hashing parameters.
# -----------------------------------------------------------------------------
ARGON2_TIME_COST: Final[int] = 2  # passes over memory
ARGON2_MEMORY_COST: Final[int] = 1024 * 64  # 64 MiB
ARGON2_PARALLELISM: Final[int] = 4
ARGON2_HASH_LEN: Final[int] = 32
ARGON2_SALT_BYTES: Final[int] = 16

# -----------------------------------------------------------------------------
# PBKDF2 parameters for Fernet key derivation.
# -----------------------------------------------------------------------------
PBKDF2_ITERATIONS: Final[int] = 480_000
PBKDF2_KEY_LENGTH: Final[int] = 32  # AES-256

# -----------------------------------------------------------------------------
# Fernet / HMAC constants.
# -----------------------------------------------------------------------------
HMAC_KEY_BYTES: Final[int] = 32
HMAC_DIGEST_BYTES: Final[int] = 32
SALT_BYTES: Final[int] = 16

# -----------------------------------------------------------------------------
# Encrypted file-format metadata
# -----------------------------------------------------------------------------
FILE_MAGIC: Final[bytes] = b"LSV1"  # 4-byte magic + version tag

# New version 2 header (planned AES-GCM) – kept for forward-compatibility
FILE_MAGIC_V2: Final[bytes] = b"LSV2"

# AES-GCM specifics (LSV2)
AES_GCM_NONCE_BYTES: Final[int] = 12  # Recommended size per NIST SP 800-38D

# Optional env flag to opt-in to experimental LSV2 vaults.
VAULT_VERSION_ENV: Final[str] = "LOCKSUM_VAULT_VERSION"  # values: LSV1 | LSV2

# Supported KDF algorithm codes for on-disk header (1 byte following magic)
ALG_CODE_PBKDF2: Final[int] = 0x00
ALG_CODE_SCRYPT: Final[int] = 0x01

HEADER_BYTES: Final[int] = len(FILE_MAGIC) + 1  # magic + alg byte

# -----------------------------------------------------------------------------
# GUI constants.
# -----------------------------------------------------------------------------
APP_TITLE: Final[str] = "Locksum - Secure Hash Generator"
APP_GEOMETRY: Final[str] = "650x450"
DATA_SEPARATOR: Final[str] = "||"

# -----------------------------------------------------------------------------
# Helper utilities – avoids repetitive os.path.exists / remove boilerplate.
# -----------------------------------------------------------------------------
# Duplicate import removal: Path already imported at top of file.


def file_exists(path: str | Path) -> bool:  # noqa: D401
    """Return ``True`` if *path* exists on disk.

    Accepts both ``str`` and :class:`~pathlib.Path` for convenience so callers
    do not need to cast back and forth.
    """
    return Path(path).exists()


def safe_remove(path: str | Path) -> None:  # noqa: D401
    """Remove *path* if it exists, ignoring *FileNotFoundError* exceptions."""
    try:
        Path(path).unlink()
    except FileNotFoundError:  # pragma: no cover – already absent
        pass


# -----------------------------------------------------------------------------
# Key-derivation defaults
# -----------------------------------------------------------------------------

# ``PBKDF2`` remains the default for backwards-compatibility, but callers can
# opt-in to ``scrypt`` (or future algorithms) by passing the *algorithm* kwarg
# to :py:meth:`locksum.model.CryptoModel.derive_fernet_key`.
KDF_DEFAULT: Final[str] = "pbkdf2"
