import os
import importlib
from pathlib import Path

import pytest

from locksum import config
from locksum.model import CryptoModel


@pytest.fixture()
def _tmp_env(tmp_path):
    """Isolate DATA_DIR and enable LSV2 for AES-GCM tests."""
    os.environ["LOCKSUM_DATA_DIR"] = str(tmp_path)
    os.environ[config.VAULT_VERSION_ENV] = "LSV2"
    importlib.reload(config)  # pick up new env vars
    yield
    # Teardown – reset env & reload default config
    os.environ.pop("LOCKSUM_DATA_DIR", None)
    os.environ.pop(config.VAULT_VERSION_ENV, None)
    importlib.reload(config)


def test_aesgcm_roundtrip(_tmp_env):
    model = CryptoModel()
    passcode = "StrongPass_123!"

    salt = model.get_salt()
    model.derive_fernet_key(passcode, salt)

    pairs = [("alpha", model.sha256_hash("alpha"))]
    model.save_encrypted_data(pairs)

    loaded = model.load_encrypted_data()
    assert loaded == pairs


def test_aesgcm_tamper_detection(tmp_path, _tmp_env):
    model = CryptoModel()
    pwd = "AnotherStrongPass#1"
    salt = model.get_salt()
    model.derive_fernet_key(pwd, salt)

    data = [("beta", model.sha256_hash("beta"))]
    model.save_encrypted_data(data)

    data_file = Path(config.ENCRYPTED_DATA_FILE)
    raw = bytearray(data_file.read_bytes())
    # Flip last byte to break GCM tag
    raw[-1] ^= 0xFF
    data_file.write_bytes(raw)

    with pytest.raises(ValueError):
        model.load_encrypted_data()


def test_clear_runtime_secrets(_tmp_env):
    model = CryptoModel()
    passcode = "S3curePass!"
    salt = model.get_salt()
    model.derive_fernet_key(passcode, salt)

    # Key should be present
    assert model.keys.sym_key is not None
    model.clear_runtime_secrets()

    with pytest.raises(RuntimeError):
        _ = model.keys.sym_key
