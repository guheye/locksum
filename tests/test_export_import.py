import json
import os
from importlib import reload
from pathlib import Path

from locksum import config
from locksum.cli import _cmd_export, _cmd_import  # noqa: WPS433 (import inside tests)
from locksum.model import CryptoModel


def _tmp_env(tmp_path):
    os.environ["LOCKSUM_DATA_DIR"] = str(tmp_path)

    from locksum import config as _cfg

    reload(_cfg)  # type: ignore[arg-type]
    return _cfg


def test_export_then_import_roundtrip(tmp_path):
    """Exported vault should import back exactly the same entries."""
    cfg = _tmp_env(tmp_path)
    model = CryptoModel()
    passcode = "P@ss1234!"

    # Create some data.
    entries = [(f"txt{i}", model.sha256_hash(f"txt{i}")) for i in range(3)]
    salt = model.get_salt()
    model.derive_fernet_key(passcode, salt)
    model.save_encrypted_data(entries)

    export_file = Path(tmp_path) / "backup.hgv"
    _cmd_export(model, str(export_file), passcode)

    # Wipe current data to simulate restore scenario.
    model.wipe_all_data()

    # Import should recreate the entries.
    _cmd_import(model, str(export_file), passcode)
    salt = model.get_salt()
    model.derive_fernet_key(passcode, salt)
    imported = model.load_encrypted_data()

    assert imported == entries 