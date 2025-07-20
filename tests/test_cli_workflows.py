import os
import importlib
from types import SimpleNamespace

import pytest

from locksum import config
from locksum.model import CryptoModel
import locksum.cli as lcli


@pytest.fixture()
def _cli_env(tmp_path):
    os.environ["LOCKSUM_DATA_DIR"] = str(tmp_path)
    importlib.reload(config)
    yield
    os.environ.pop("LOCKSUM_DATA_DIR", None)
    importlib.reload(config)


def test_weak_pass_rejected(_cli_env, capsys):
    model = CryptoModel()
    weak = "abc"  # zxcvbn score 0

    with pytest.raises(SystemExit) as exc:
        lcli._cmd_store(model, "text", weak)  # noqa: SLF001 – intentional private call
    assert exc.value.code == 6
    captured = capsys.readouterr()
    assert "too weak" in captured.err


def test_change_passcode_flow(monkeypatch, _cli_env):
    # Setup vault with initial passcode
    model = CryptoModel()
    old_pass = "OldPass123!"
    salt = model.get_salt()
    model.derive_fernet_key(old_pass, salt)
    data = [("a", model.sha256_hash("a"))]
    model.hash_new_passcode(old_pass)
    model.save_encrypted_data(data)
    model.clear_runtime_secrets()

    # Patch helpers used by _cmd_change_passcode
    monkeypatch.setattr(lcli, "_read_passcode", lambda: old_pass)
    monkeypatch.setattr(lcli.getpass, "getpass", lambda prompt="": "NewPass123!")
    # Stub stdin readline for non-TTY path
    monkeypatch.setattr(lcli.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(lcli.sys.stdin, "readline", lambda: "NewPass123!\n")

    # Run change-passcode command
    lcli._cmd_change_passcode(model)  # noqa: SLF001

    # Verify vault decrypts with new passcode and not with old
    model2 = CryptoModel()
    salt2 = model2.get_salt()
    model2.derive_fernet_key("NewPass123!", salt2)
    assert model2.load_encrypted_data() == data

    with pytest.raises(ValueError):
        bad = CryptoModel()
        salt_bad = bad.get_salt()
        bad.derive_fernet_key(old_pass, salt_bad)
        bad.load_encrypted_data()
