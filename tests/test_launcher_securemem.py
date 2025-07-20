import importlib
from types import SimpleNamespace

from locksum.securemem import secure_erase


def test_secure_erase_zeroises():
    buf = bytearray(b"secret")
    secure_erase(buf)
    assert all(b == 0 for b in buf), "Buffer not zeroed by secure_erase"


def test_launcher_dispatch(monkeypatch):
    """launcher.main() should delegate to GUI when no args and CLI when args."""

    called = []

    def _fake_import(name):  # noqa: D401 – test stub
        dummy = SimpleNamespace()

        def _dummy_main(argv=None):  # noqa: D401 – test stub
            called.append(name)

        dummy.main = _dummy_main
        return dummy

    monkeypatch.setattr(importlib, "import_module", _fake_import)

    from locksum import launcher  # noqa: WPS433 (import after monkeypatch)

    # No arguments → GUI path
    launcher.main([])
    assert "locksum.gui.__main__" in called

    called.clear()
    # Some arguments → CLI path
    launcher.main(["hash", "text"])
    assert "locksum.cli" in called
