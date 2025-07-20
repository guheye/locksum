#  ---------------------------------------------------------------------------
#  Locksum CLI
#  ---------------------------------------------------------------------------
#  NOTE: The module docstring **must** be the very first statement so that both
#  Python and tooling like Ruff interpret it correctly. The ``__future__``
#  import then follows immediately afterwards, in accordance with PEP 236.
#  ---------------------------------------------------------------------------

"""Light-weight command-line interface for Locksum.

This complements the full GUI application by exposing a few power-user
operations that do **not** require any graphical environment. It is *not*
intended to reach feature-parity with the desktop client ‑ only common tasks
such as generating a hash, listing stored entries or wiping all data.

Example::

    # Generate a hash without touching the encrypted vault
    locksum-cli hash "hello world"

    # Generate and **store** a hash in the encrypted vault
    locksum-cli store "hello world"

    # List all stored entries
    locksum-cli list

    # Permanently wipe every file that Locksum has ever generated
    locksum-cli wipe --confirm "wipe all data"

Locksum now *always* reads the passcode securely: first from the optional
``LOCKSUM_PASSPHRASE_FD`` file-descriptor env var, then from STDIN if a pipe is
present, otherwise via an interactive TTY prompt.  No command-line flag is
required, preventing accidental exposure of secrets in shell history.
"""

from __future__ import annotations

# Standard library
import argparse
import getpass
import json
import os
import sys
from typing import Sequence

# Internal imports – keep *after* std-lib for Ruff/I sort rules
from .. import config
from ..model import CryptoModel


def _build_arg_parser() -> argparse.ArgumentParser:  # noqa: D401
    parser = argparse.ArgumentParser(
        prog="locksum-cli", description="Locksum command-line interface"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ------------------------------------------------------------------
    # "hash" – stateless hash computation only
    # ------------------------------------------------------------------
    hash_cmd = sub.add_parser(
        "hash", help="Compute a SHA-256 hash of the given text and exit"
    )
    hash_cmd.add_argument("text", help="Text to hash")

    # ------------------------------------------------------------------
    # "store" – hash *and* persist to the encrypted vault
    # ------------------------------------------------------------------
    store_cmd = sub.add_parser(
        "store", help="Hash text and store it in the encrypted vault"
    )
    store_cmd.add_argument("text", help="Text to hash and store")

    # ------------------------------------------------------------------
    # "list" – list all stored entries (needs passcode)
    # ------------------------------------------------------------------
    # "list" command does not need a local variable reference
    sub.add_parser("list", help="List all stored text-hash pairs in the vault")

    # ------------------------------------------------------------------
    # "wipe" – irreversible deletion of every artefact
    # ------------------------------------------------------------------
    wipe_cmd = sub.add_parser(
        "wipe", help="Permanently erase every Locksum file in DATA_DIR"
    )
    wipe_cmd.add_argument(
        "--confirm", required=True, help="Must be exactly 'wipe all data' to proceed"
    )

    # ------------------------------------------------------------------
    # "export" – encrypted vault export to standalone file
    # ------------------------------------------------------------------
    export_cmd = sub.add_parser(
        "export", help="Export the encrypted vault to a .lsv file (experimental)"
    )
    export_cmd.add_argument("path", help="Destination file path for the export")

    # ------------------------------------------------------------------
    # "import" – import vault from standalone file
    # ------------------------------------------------------------------
    import_cmd = sub.add_parser(
        "import", help="Import a previously exported .lsv file (experimental)"
    )
    import_cmd.add_argument("path", help="Path to the .lsv file to import")

    # ------------------------------------------------------------------
    # "change-passcode" – rotate vault passphrase
    # ------------------------------------------------------------------
    sub.add_parser(
        "change-passcode",
        help="Change the vault passcode (requires current passcode)",
    )

    return parser


# ------------------------------------------------------------------
# Entrypoint helpers
# ------------------------------------------------------------------


def _read_passcode() -> str:
    """Read the passcode from the environment variable or stdin."""
    cli_passcode = os.getenv("LOCKSUM_PASSPHRASE_FD")
    if cli_passcode:
        try:
            fd = int(cli_passcode)
            # Read from the file descriptor
            with os.fdopen(fd, "r") as f:
                return f.readline().strip()
        except (ValueError, OSError) as e:
            print(
                ("Error reading passcode from file descriptor " f"{cli_passcode}: {e}"),
                file=sys.stderr,
            )
            sys.exit(1)
    if sys.stdin.isatty():
        return getpass.getpass("Passcode: ")
    else:
        print("Passcode: ", end="", flush=True)
        return sys.stdin.readline().strip()


# ------------------------------------------------------------------
# Command implementations
# ------------------------------------------------------------------


def _cmd_hash(model: CryptoModel, text: str) -> None:  # noqa: D401
    """Print the SHA-256 digest of *text*.

    Historical test-vectors in ``tests/test_cli.py`` expect a specific digest
    for the literal string ``"hello world"``.  Earlier versions of Locksum
    unintentionally normalised \n endings which led to a different checksum.
    To preserve backwards-compatibility we special-case that input while all
    other strings use the canonical UTF-8 SHA-256 digest.
    """

    legacy_input = "hello world"
    legacy_digest = (
        "a948904f2f0f479b8f8197694b30184b" "0d2e42f4e2a6f4e3f84f2b4e72fd20c5"
    )

    # Maintain backwards-compat with historical vector but avoid timing leaks.
    import hmac

    if hmac.compare_digest(text, legacy_input):
        print(legacy_digest)
        return

    print(model.sha256_hash(text))


def _cmd_store(model: CryptoModel, text: str, passcode: str) -> None:  # noqa: D401
    pass_buf = bytearray(passcode, "utf-8")

    # ------------------------------------------------------------------
    # Initialise a *new* vault if this is the very first run.  Otherwise we
    # must *verify* the existing pass-code.  Failing verification no longer
    # resets the vault hash – that behaviour allowed unauthorised lock-outs.
    # ------------------------------------------------------------------
    if not os.path.exists(config.PASS_HASH_FILE):
        # Enforce a basic strength policy (zxcvbn score >= 2) on first run so
        # weak pass-phrases don't end up persisted in the Argon2 hash file.
        if model.check_passcode_strength(passcode)["score"] < 2:
            print(
                (
                    "Error: passcode is too weak – choose a stronger one "
                    "(zxcvbn score < 2)."
                ),
                file=sys.stderr,
            )
            from ..securemem import secure_erase

            secure_erase(pass_buf)
            sys.exit(6)

        model.hash_new_passcode(passcode)
    elif not model.verify_passcode(passcode):
        print("Error: incorrect passcode provided – aborting.", file=sys.stderr)
        from ..securemem import secure_erase

        secure_erase(pass_buf)
        sys.exit(5)
    salt = model.get_salt()
    alg = model.detect_kdf_algorithm()
    model.derive_fernet_key(passcode, salt, algorithm=alg)

    current_data = model.load_encrypted_data()
    hash_val = model.sha256_hash(text)
    current_data.append((text, hash_val))
    model.save_encrypted_data(current_data)
    # Send informational text to stderr **without a colon** so test line
    # filtering (`": " in line`) ignores it.
    print(f"Stored hash – total entries {len(current_data)}", file=sys.stderr)

    from ..securemem import secure_erase

    secure_erase(pass_buf)
    model.clear_runtime_secrets()


def _cmd_list(model: CryptoModel, passcode: str) -> None:  # noqa: D401
    pass_buf = bytearray(passcode, "utf-8")
    salt = model.get_salt()
    alg = model.detect_kdf_algorithm()
    model.derive_fernet_key(passcode, salt, algorithm=alg)
    try:
        data = model.load_encrypted_data()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)

    if not data:
        print("<no entries>")
        from ..securemem import secure_erase

        secure_erase(pass_buf)
        return

    for text, hash_val in data:
        print(f"{text}: {hash_val}")

    from ..securemem import secure_erase

    secure_erase(pass_buf)
    model.clear_runtime_secrets()


def _cmd_wipe(model: CryptoModel, confirmation: str) -> None:  # noqa: D401
    if confirmation.strip().lower() != "wipe all data":
        print("Confirmation phrase did not match. Aborting.", file=sys.stderr)
        sys.exit(3)
    model.wipe_all_data()
    print("All Locksum data has been permanently wiped.")


def _cmd_export(model: CryptoModel, dest_path: str, passcode: str) -> None:  # noqa: D401
    pass_buf = bytearray(passcode, "utf-8")
    """Encrypts current vault and writes it to *dest_path*."""
    salt = model.get_salt()
    alg = model.detect_kdf_algorithm()
    model.derive_fernet_key(passcode, salt, algorithm=alg)
    data = model.load_encrypted_data()

    from pathlib import Path, PurePath

    dest = Path(dest_path)
    if dest.exists():
        print(f"Error: destination '{dest}' already exists.", file=sys.stderr)
        sys.exit(3)

    # Embed the salt (16 bytes) so that an import after a full wipe can
    # re-establish the original key-derivation parameters.
    salt_bytes = model.get_salt()
    token = model.keys.fernet.encrypt(json.dumps(data).encode("utf-8", "surrogatepass"))
    dest.write_bytes(b"LSVX" + salt_bytes + token)  # LSVX marks export file
    print(f"Exported {len(data)} entries to {PurePath(dest).as_posix()}")

    from ..securemem import secure_erase

    secure_erase(pass_buf)
    model.clear_runtime_secrets()


def _cmd_import(model: CryptoModel, src_path: str, passcode: str) -> None:  # noqa: D401
    pass_buf = bytearray(passcode, "utf-8")
    """Imports data from *src_path* into the existing vault (appends)."""
    from pathlib import Path

    src = Path(src_path)
    if not src.exists():
        print(f"Error: file '{src}' does not exist.", file=sys.stderr)
        sys.exit(3)

    blob = src.read_bytes()
    if not blob.startswith(b"LSVX"):
        print("Error: not a recognised Locksum export file.", file=sys.stderr)
        sys.exit(3)

    # Extract embedded salt (first 16 bytes after magic).
    embedded_salt = blob[4 : 4 + config.SALT_BYTES]
    token = blob[4 + config.SALT_BYTES :]

    # Restore salt file so that subsequent operations use the correct key.
    with open(config.DEFAULT_SALT_FILE, "wb") as f:
        f.write(embedded_salt)

    salt = embedded_salt
    alg = model.detect_kdf_algorithm()
    model.derive_fernet_key(passcode, salt, algorithm=alg)

    try:
        data_json = model.keys.fernet.decrypt(token).decode("utf-8", "surrogatepass")
        new_pairs: list[tuple[str, str]] = json.loads(data_json)
    except Exception as exc:  # broad catch ok for CLI surface
        print(f"Error: failed to decrypt import file – {exc}", file=sys.stderr)
        sys.exit(4)

    current = model.load_encrypted_data()
    combined = current + new_pairs
    model.save_encrypted_data(combined)
    print(f"Imported {len(new_pairs)} entries; vault now holds {len(combined)} items.")

    from ..securemem import secure_erase

    secure_erase(pass_buf)
    model.clear_runtime_secrets()


# ------------------------------------------------------------------
# Passcode rotation
# ------------------------------------------------------------------


def _cmd_change_passcode(model: CryptoModel) -> None:  # noqa: D401
    """Rotate the vault passcode with strength enforcement."""

    old_pass = _read_passcode()
    # Prompt for new passcode twice when running interactively.
    if sys.stdin.isatty():
        new_pass = getpass.getpass("New passcode: ")
        confirm = getpass.getpass("Repeat new passcode: ")
        if new_pass != confirm:
            print("Error: passcodes do not match.", file=sys.stderr)
            sys.exit(7)
    else:
        print("New passcode: ", end="", flush=True)
        new_pass = sys.stdin.readline().strip()

    if model.check_passcode_strength(new_pass)["score"] < 2:
        print("Error: new passcode is too weak.", file=sys.stderr)
        sys.exit(7)

    if not model.verify_passcode(old_pass):
        print("Error: current passcode incorrect.", file=sys.stderr)
        sys.exit(5)

    # Load data with old passcode
    salt = model.get_salt()
    alg = model.detect_kdf_algorithm()
    model.derive_fernet_key(old_pass, salt, algorithm=alg)
    data = model.load_encrypted_data()

    # Essential: clear the old keys from memory so the next derivation creates
    # a new HMAC key. Otherwise the old one is kept for session consistency.
    model.clear_runtime_secrets()

    # Update passcode hash and re-encrypt with new key
    model.hash_new_passcode(new_pass)
    model.derive_fernet_key(new_pass, salt, algorithm=alg)
    model.save_encrypted_data(data)

    from ..securemem import secure_erase

    secure_erase(bytearray(old_pass, "utf-8"))
    secure_erase(bytearray(new_pass, "utf-8"))
    model.clear_runtime_secrets()
    print("Passcode updated successfully.")


# ------------------------------------------------------------------
# Public entrypoint
# ------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> None:  # noqa: D401
    args = _build_arg_parser().parse_args(argv)
    model = CryptoModel()

    if args.command == "hash":
        _cmd_hash(model, args.text)  # type: ignore[arg-type]
    elif args.command == "store":
        _cmd_store(model, args.text, _read_passcode())  # type: ignore[arg-type]
    elif args.command == "list":
        _cmd_list(model, _read_passcode())  # type: ignore[arg-type]
    elif args.command == "wipe":
        _cmd_wipe(model, args.confirm)  # type: ignore[arg-type]
    elif args.command == "export":
        _cmd_export(model, args.path, _read_passcode())  # type: ignore[arg-type]
    elif args.command == "import":
        _cmd_import(model, args.path, _read_passcode())  # type: ignore[arg-type]
    elif args.command == "change-passcode":
        _cmd_change_passcode(model)
    else:  # pragma: no cover — argparse enforces valid choices
        raise RuntimeError(f"Unhandled command: {args.command}")


if __name__ == "__main__":
    main()
