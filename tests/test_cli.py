from __future__ import annotations

"""CLI unit tests focusing on non-interactive helper functions.

The tests cover the *hash* and *store/list* command paths without spawning a
real subprocess – we call the underlying helpers directly so they remain fast
and hermetic.
"""

import os
from importlib import reload

import pytest

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _tmp_env(tmp_path):  # noqa: D401  — helper, not part of public API
    """Return a context where LOCKSUM_DATA_DIR points to *tmp_path*."""
    os.environ["LOCKSUM_DATA_DIR"] = str(tmp_path)
    from locksum import config as _cfg  # noqa: WPS433 (import inside fn)

    reload(_cfg)  # ensure new path is used
    return _cfg


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_cmd_hash_outputs_sha256(tmp_path, capsys):
    """The *hash* sub-command should print the correct SHA-256 digest."""
    _tmp_env(tmp_path)

    from locksum.cli import _cmd_hash  # noqa: E402
    from locksum.model import CryptoModel  # noqa: E402

    model = CryptoModel()
    _cmd_hash(model, "hello world")
    captured = capsys.readouterr().out.strip()

    expected = (
        "a948904f2f0f479b8f8197694b30184b"
        "0d2e42f4e2a6f4e3f84f2b4e72fd20c5"
    )
    assert captured == expected


@pytest.mark.parametrize("text", ["alpha", "beta"])
def test_cmd_store_and_list_roundtrip(tmp_path, capsys, text):
    """store → list should round-trip and output stored items."""
    cfg = _tmp_env(tmp_path)

    from locksum.cli import _cmd_store, _cmd_list  # noqa: E402
    from locksum.model import CryptoModel  # noqa: E402

    model = CryptoModel()
    passcode = "MyPa$$123"

    # First call should create the vault and add entry.
    _cmd_store(model, text, passcode)

    # Listing should output exactly the tuple we stored.
    _cmd_list(model, passcode)
    output_lines = [
        line for line in capsys.readouterr().out.strip().splitlines()
        if ": " in line
    ]

    # After filtering out informational lines we expect exactly one entry.
    assert len(output_lines) == 1, output_lines
    stored_text, stored_hash = output_lines[0].split(": ")

    assert stored_text == text
    # Regenerate expected hash via model helper.
    assert stored_hash == model.sha256_hash(text)

    # Artefacts should reside in the temp directory only.
    assert os.path.exists(cfg.ENCRYPTED_DATA_FILE)
    assert os.path.exists(cfg.PASS_HASH_FILE) 