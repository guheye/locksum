import io
import importlib
import os
from pathlib import Path

import pytest

from locksum import config
from locksum.model import CryptoModel
import locksum.cli as lcli


@pytest.fixture()
def cli_env(tmp_path, monkeypatch):
    """Redirect DATA_DIR to tmp and reload config for isolated CLI tests."""
    monkeypatch.setenv("LOCKSUM_DATA_DIR", str(tmp_path))
    importlib.reload(config)  # refresh paths based on new env var
    yield
    # Cleanup – restore global config to default state
    monkeypatch.delenv("LOCKSUM_DATA_DIR", raising=False)
    importlib.reload(config)


def _strong_pass() -> str:  # helper to avoid weak-pass exits
    return "Str0ngPassw0rd!"


# ---------------------------------------------------------------------------
# export / import round-trip
# ---------------------------------------------------------------------------


def test_cli_export_import_roundtrip(cli_env, tmp_path):  # noqa: D401 – test helper
    model = CryptoModel()

    passcode = _strong_pass()
    # Store one entry so we have something to export
    lcli._cmd_store(model, "alpha", passcode)  # noqa: SLF001

    export_path = tmp_path / "vault.lsvx"
    lcli._cmd_export(model, str(export_path), passcode)  # noqa: SLF001
    assert export_path.exists(), "Export file not created"

    # Simulate a fresh session by wiping artefacts on disk
    model.wipe_all_data()

    # Import back and verify contents
    lcli._cmd_import(model, str(export_path), passcode)  # noqa: SLF001

    # Derive key and load data to check round-trip
    salt = model.get_salt()
    model.derive_fernet_key(passcode, salt)
    restored = model.load_encrypted_data()
    assert restored == [("alpha", model.sha256_hash("alpha"))]


# ---------------------------------------------------------------------------
# wipe command
# ---------------------------------------------------------------------------


def test_cli_wipe_command(cli_env):  # noqa: D401 – test helper
    model = CryptoModel()
    passcode = _strong_pass()

    lcli._cmd_store(model, "beta", passcode)  # ensure artefacts exist
    assert os.path.exists(config.ENCRYPTED_DATA_FILE)

    lcli._cmd_wipe(model, "wipe all data")  # noqa: SLF001
    # Every artefact should be gone after wipe
    assert not os.path.exists(config.ENCRYPTED_DATA_FILE)
    assert not os.path.exists(config.PASS_HASH_FILE)


# ---------------------------------------------------------------------------
# cli.main dispatch paths (hash / store / list)
# ---------------------------------------------------------------------------


def test_cli_main_hash_store_list(cli_env, capsys, monkeypatch):
    passcode = _strong_pass()

    # Avoid interactive input by replacing _read_passcode helper
    monkeypatch.setattr(lcli, "_read_passcode", lambda: passcode)

    # "hash" command prints digest of argument
    lcli.main(["hash", "data"])
    digest = capsys.readouterr().out.strip()
    assert digest == CryptoModel().sha256_hash("data")

    # "store" followed by "list" should echo stored entry
    lcli.main(["store", "gamma"])
    lcli.main(["list"])
    listing_output = capsys.readouterr().out
    assert "gamma" in listing_output
