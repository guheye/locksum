import os
from importlib import reload

import argon2
from locksum import config
from locksum.model import CryptoModel


def _tmp_env(tmp_path):
    os.environ["LOCKSUM_DATA_DIR"] = str(tmp_path)
    from locksum import config as _cfg

    reload(_cfg)  # type: ignore[arg-type]
    return _cfg


def test_argon2_auto_rehash(tmp_path):
    """Successful login should transparently upgrade weak Argon2 hashes."""
    cfg = _tmp_env(tmp_path)

    model = CryptoModel()
    passcode = "Sup3rS3cret!"

    # Create initial hash with the *current* hasher (time_cost=2).
    model.hash_new_passcode(passcode)
    with open(cfg.PASS_HASH_FILE) as f:
        original_hash = f.read()

    # Now tighten policy: increase time_cost so that the old hash needs rehash.
    model.pass_hasher = argon2.PasswordHasher(
        time_cost=config.ARGON2_TIME_COST + 1,
        memory_cost=config.ARGON2_MEMORY_COST,
        parallelism=config.ARGON2_PARALLELISM,
        hash_len=config.ARGON2_HASH_LEN,
        salt_len=config.ARGON2_SALT_BYTES,
    )

    # Verification should succeed and trigger rehash.
    assert model.verify_passcode(passcode) is True

    with open(cfg.PASS_HASH_FILE) as f:
        upgraded_hash = f.read()

    # Hash should have been rewritten.
    assert upgraded_hash != original_hash

    # And it should now meet policy (no rehash needed).
    assert model.pass_hasher.check_needs_rehash(upgraded_hash) is False 