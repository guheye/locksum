"""Secure memory handling utilities.

Python does not guarantee that strings or bytes are removed from memory when
objects are garbage-collected.  Where feasible we convert secrets into a
*mutable* ``bytearray`` so we can overwrite its contents **in place** once no
longer needed.  This offers best-effort mitigation against secret leakage via
memory dumps or after-free reads.

Usage::

    from locksum.securemem import secure_erase

    buf = bytearray(b"super-secret")
    # ... use buf ...
    secure_erase(buf)  # buf is now all zero bytes
"""

from __future__ import annotations

import ctypes
import platform
from typing import Final

# Try to use libsodium's constant-time wipe if available (installed via PyNaCl).
# Some older (or stripped-down) PyNaCl wheels expose :pydata:`nacl.bindings` but
# **not** the ``sodium_memzero`` symbol.  Import failures must therefore catch
# both missing-module *and* missing-attribute scenarios so Locksum falls back to
# the (slower) ``ctypes.memset`` implementation instead of crashing at import
# time.
try:
    from nacl.bindings import sodium_memzero  # type: ignore

    _SODIUM_AVAILABLE: bool = True
except (
    ModuleNotFoundError,
    ImportError,
    AttributeError,
):  # pragma: no cover – optional dep
    _SODIUM_AVAILABLE = False


# Fallback value used to overwrite memory – zero byte keeps things simple.
_FILL: Final[int] = 0x00


def _ctypes_memset(buf: bytearray) -> None:  # noqa: D401
    """Low-level memset fallback used when libsodium is absent."""

    length = len(buf)
    if length == 0:
        return

    c_buf = (ctypes.c_char * length).from_buffer(buf)
    ctypes.memset(ctypes.addressof(c_buf), _FILL, length)

    # Remove handle so pointer cannot be reused accidentally.
    del c_buf  # noqa: WPS420 – explicitly free pointer in tight scope


def secure_erase(buffer: bytearray) -> None:  # noqa: D401
    """Best-effort in-place zeroisation of *buffer* contents.

    If PyNaCl / libsodium is present we call :pyfunc:`sodium_memzero` which
    compiles down to `explicit_bzero()` (or equivalent) and cannot be elided
    by the optimiser.  Otherwise we fall back to a plain ``ctypes.memset``.
    """

    if _SODIUM_AVAILABLE:
        # The sodium API works with ``ctypes.c_void_p`` but Python's buffer
        # protocol gives us a memoryview, which can be passed directly.
        # *No* length check needed – libsodium uses the Python buffer len.
        sodium_memzero(buffer)  # type: ignore[arg-type]
    else:
        _ctypes_memset(buffer)


# ---------------------------------------------------------------------------
# Best-effort memory locking helpers (mlock/munlock)
# ---------------------------------------------------------------------------

_LIBC_NAMES = {
    "Linux": "libc.so.6",
    "Darwin": "libc.dylib",
    "FreeBSD": "libc.so",
}


def _load_libc():  # pragma: no cover – OS-specific
    try:
        libc_name = _LIBC_NAMES.get(platform.system())
        if not libc_name:
            return None
        return ctypes.CDLL(libc_name)
    except Exception:  # noqa: BLE001 – broad: any failure disables mlock
        return None


_LIBC = _load_libc()


def mlock_bytes(buf: bytes | bytearray) -> None:  # noqa: D401
    """Lock the memory pages backing *buf* into RAM (best-effort).

    This uses the POSIX `mlock` syscall when available so the kernel avoids
    swapping secret pages to disk.  On unsupported platforms the call is a
    no-op.
    """

    if _LIBC is None:
        return

    addr = ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))
    _LIBC.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(len(buf)))


def munlock_bytes(buf: bytes | bytearray) -> None:  # noqa: D401
    if _LIBC is None:
        return

    addr = ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))
    _LIBC.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(len(buf)))
