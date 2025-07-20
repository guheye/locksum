import importlib
import os
from pathlib import Path

from locksum import config
from locksum.services import IntegrityChecker, KeyManager, VaultStore


def _setup_key_mgr(tmp_path):
    """Utility to create a KeyManager with isolated DATA_DIR."""

    os.environ["LOCKSUM_DATA_DIR"] = str(tmp_path)
    importlib.reload(config)

    km = KeyManager()
    ic = IntegrityChecker()
    vs = VaultStore(km, ic)

    pwd = "VeryStr0ngPass!"
    salt = km.get_salt()
    km.derive_fernet_key(pwd, salt)
    return vs, km


def test_vaultstore_save_lsv1(tmp_path):
    vs, _ = _setup_key_mgr(tmp_path)
    # Force legacy LSV1 path
    os.environ[config.VAULT_VERSION_ENV] = "LSV1"

    pairs = [("x", "y")]
    vs.save(pairs)
    assert Path(config.ENCRYPTED_DATA_FILE).exists(), "Vault file not created (LSV1)"


def test_vaultstore_save_lsv2(tmp_path):
    vs, _ = _setup_key_mgr(tmp_path)
    # Force experimental LSV2 path
    os.environ[config.VAULT_VERSION_ENV] = "LSV2"

    pairs = [("m", "n")]
    vs.save(pairs)
    assert Path(config.ENCRYPTED_DATA_FILE).exists(), "Vault file not created (LSV2)"
