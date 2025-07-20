import os
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from locksum import config
from locksum.model import CryptoModel

# -----------------------------------------------------------------------------
# Strategies
# -----------------------------------------------------------------------------

# Generate passcodes that do not contain the separator to keep things simple.
passcodes = st.text(min_size=6, max_size=20, alphabet=st.characters(blacklist_characters="|"))
# Text inputs must avoid the DATA_SEPARATOR characters.
texts = st.lists(
    st.text(min_size=1, max_size=40, alphabet=st.characters(blacklist_characters="|")),
    min_size=0,
    max_size=10,
)
algorithms = st.sampled_from(["pbkdf2", "scrypt"])


@pytest.fixture()
def tmp_cfg(tmp_path):
    """Redirect the LOCKSUM_DATA_DIR to an isolated temp directory."""
    original = os.environ.get("LOCKSUM_DATA_DIR")
    os.environ["LOCKSUM_DATA_DIR"] = str(tmp_path)
    # Re-import config so the module-level DATA_DIR picks up the new env var.
    import importlib

    importlib.reload(config)
    yield config  # caller can inspect paths if required
    # Teardown – restore env & reload config again for other tests
    if original is not None:
        os.environ["LOCKSUM_DATA_DIR"] = original
    else:
        os.environ.pop("LOCKSUM_DATA_DIR", None)
    importlib.reload(config)


@given(texts=texts, passcode=passcodes, algorithm=algorithms)
@settings(max_examples=25, deadline=None)
def test_encrypt_decrypt_roundtrip(tmp_cfg, texts, passcode, algorithm):
    """Saving then loading must round-trip exactly for arbitrary inputs."""
    model = CryptoModel()

    salt = model.get_salt()
    model.derive_fernet_key(passcode, salt, algorithm=algorithm)

    pairs = [(t, model.sha256_hash(t)) for t in texts]
    model.save_encrypted_data(pairs)
    loaded = model.load_encrypted_data()
    assert loaded == pairs


@given(texts=texts, passcode=passcodes)
@settings(max_examples=10, deadline=None)
def test_tampering_detection(tmp_cfg, texts, passcode):
    """Modifying even a single byte of the ciphertext or HMAC must be detected."""
    model = CryptoModel()

    salt = model.get_salt()
    model.derive_fernet_key(passcode, salt)

    pairs = [(t, model.sha256_hash(t)) for t in texts]
    model.save_encrypted_data(pairs)

    # Flip the first byte after the header to simulate tampering.
    data_file = Path(config.ENCRYPTED_DATA_FILE)
    raw = bytearray(data_file.read_bytes())
    header_len = len(config.FILE_MAGIC) + 1  # include alg byte
    if len(raw) > header_len + 1:  # Ensure we have something to flip
        raw[header_len] ^= 0xFF
    else:
        pytest.skip("Ciphertext too short for tampering flip – generated input empty")

    data_file.write_bytes(raw)

    with pytest.raises(ValueError, match="Data integrity check failed|Decryption failed"):
        model.load_encrypted_data() 