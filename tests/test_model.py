from __future__ import annotations

import os
import pathlib

import pytest

from locksum import config
from locksum.model import CryptoModel


@pytest.fixture
def crypto_model(tmp_path: pathlib.Path) -> CryptoModel:
    """Fixture to provide a CryptoModel instance with a temporary work dir."""
    # Redirect configuration to the temporary directory so we don't write to the
    # actual user profile. This must happen **before** instantiating the model
    # so that any lazy-loaded files use the tmp_path location.
    from importlib import reload

    os.environ["LOCKSUM_DATA_DIR"] = str(tmp_path)

    # Ensure the config module picks up the new environment variable.
    from locksum import config as _config_module

    reload(_config_module)  # type: ignore[arg-type]

    # Update global reference so subsequent tests use reloaded config
    globals()["config"] = _config_module

    # Re-import the CryptoModel so it sees the reloaded config.
    from locksum.model import CryptoModel

    return CryptoModel()


class TestCryptoModel:
    """Test suite for the CryptoModel class."""

    def test_sha256_hash(self, crypto_model: CryptoModel):
        """The SHA-256 hash of 'hello' is well-known and should be consistent."""
        expected = (
            "2cf24dba5fb0a30e26e83b2ac5b9e29e"
            "1b161e5c1fa7425e73043362938b9824"
        )
        assert crypto_model.sha256_hash("hello") == expected

    def test_key_creation_and_loading(self, crypto_model: CryptoModel):
        """Tests that keys and salts are created, persisted, and re-read correctly."""
        salt = crypto_model.get_salt()
        assert os.path.exists(config.DEFAULT_SALT_FILE)
        assert len(salt) == config.SALT_BYTES

        # Subsequent call should return the same salt
        assert crypto_model.get_salt() == salt

        # Test HMAC key as well
        hmac_key = crypto_model.hmac_key
        assert os.path.exists(config.HMAC_KEY_FILE)
        assert len(hmac_key) == config.HMAC_KEY_BYTES
        assert crypto_model.hmac_key == hmac_key

    def test_passcode_hashing_and_verification(self, crypto_model: CryptoModel):
        """Tests the full lifecycle of passcode hashing and verification."""
        passcode = "StroNgP@ssw0rd123!"
        crypto_model.hash_new_passcode(passcode)
        assert os.path.exists(config.PASS_HASH_FILE)

        # Successful verification
        assert crypto_model.verify_passcode(passcode) is True

        # Failed verification
        assert crypto_model.verify_passcode("wrong-password") is False

    def test_fernet_derivation(self, crypto_model: CryptoModel):
        """Fernet key should be derived correctly and be able to encrypt/decrypt."""
        passcode = "password123"
        salt = crypto_model.get_salt()
        crypto_model.derive_fernet_key(passcode, salt)
        assert crypto_model.fernet is not None

        message = b"this is a secret message"
        token = crypto_model.fernet.encrypt(message)
        assert crypto_model.fernet.decrypt(token) == message

    def test_scrypt_kdf_derivation(self, crypto_model: CryptoModel):
        """The optional scrypt KDF should also round-trip correctly."""
        passcode = "different-pass"
        salt = crypto_model.get_salt()

        crypto_model.derive_fernet_key(passcode, salt, algorithm="scrypt")
        assert crypto_model.fernet is not None

        plaintext = b"secret w/ scrypt"
        token = crypto_model.fernet.encrypt(plaintext)
        assert crypto_model.fernet.decrypt(token) == plaintext

    def test_data_encryption_decryption_roundtrip(self, crypto_model: CryptoModel):
        """Full data persistence cycle: save (encrypt) -> load (decrypt)."""
        passcode = "my-secure-passcode"
        salt = crypto_model.get_salt()
        crypto_model.derive_fernet_key(passcode, salt)

        # Test with empty data
        crypto_model.save_encrypted_data([])
        assert os.path.exists(config.ENCRYPTED_DATA_FILE)
        assert crypto_model.load_encrypted_data() == []

        # Test with actual data
        sample_data: list[tuple[str, str]] = [
            ("text1", "hash1"),
            ("some text with a separator", "hash2"),
        ]
        crypto_model.save_encrypted_data(sample_data)
        loaded_data = crypto_model.load_encrypted_data()
        assert loaded_data == sample_data

    def test_load_data_with_bad_key_raises_error(self, crypto_model: CryptoModel):
        """Attempting to decrypt with a wrong key should raise ValueError."""
        passcode = "my-secure-passcode"
        salt = crypto_model.get_salt()
        crypto_model.derive_fernet_key(passcode, salt)

        sample_data: list[tuple[str, str]] = [("text1", "hash1")]
        crypto_model.save_encrypted_data(sample_data)

        # Derive a new, different key
        crypto_model.derive_fernet_key("a-different-password", salt)
        with pytest.raises(ValueError, match="Decryption failed"):
            crypto_model.load_encrypted_data()

    def test_load_tampered_data_raises_error(self, crypto_model: CryptoModel):
        """Loading data that has been tampered with should raise ValueError."""
        passcode = "my-secure-passcode"
        salt = crypto_model.get_salt()
        crypto_model.derive_fernet_key(passcode, salt)

        sample_data: list[tuple[str, str]] = [("text1", "hash1")]
        crypto_model.save_encrypted_data(sample_data)

        # Manually tamper with the HMAC portion of the file
        with open(config.ENCRYPTED_DATA_FILE, "r+b") as f:
            content = f.read()
            # Flip the last byte of the HMAC
            tampered_content = content[:-1] + bytes([content[-1] ^ 1])
            f.seek(0)
            f.write(tampered_content)

        with pytest.raises(ValueError, match="Data integrity check failed"):
            crypto_model.load_encrypted_data()

    def test_wipe_all_data(self, crypto_model: CryptoModel):
        """Wipe function should delete all generated artifacts."""
        # Create some artifacts first
        crypto_model.get_salt()
        crypto_model.hmac_key
        crypto_model.hash_new_passcode("pass")
        crypto_model.derive_fernet_key("pass", crypto_model.get_salt())
        crypto_model.save_encrypted_data([("a", "b")])

        assert os.path.exists(config.DEFAULT_SALT_FILE)
        assert os.path.exists(config.HMAC_KEY_FILE)
        assert os.path.exists(config.PASS_HASH_FILE)
        assert os.path.exists(config.ENCRYPTED_DATA_FILE)

        crypto_model.wipe_all_data()

        assert not os.path.exists(config.DEFAULT_SALT_FILE)
        assert not os.path.exists(config.HMAC_KEY_FILE)
        assert not os.path.exists(config.PASS_HASH_FILE)
        assert not os.path.exists(config.ENCRYPTED_DATA_FILE)
