from __future__ import annotations

import os
from importlib import reload
from types import SimpleNamespace
from typing import Any

import pytest

from locksum import config as _config


class FakeVar:
    """A minimal replacement for tkinter's StringVar for testing."""

    def __init__(self, value: str = "") -> None:
        self._value = value

    def get(self) -> str:  # noqa: D401
        return self._value

    def set(self, value: str) -> None:  # noqa: D401
        self._value = value


class DummyView(SimpleNamespace):
    """Provides just enough surface for the Controller to interact with."""

    def setup_stored_data_ui(self, data: Any) -> None:  # noqa: D401
        # In real GUI this repopulates the tree widget – we don't need that here.
        self.latest_data = data

    def update_status(self, _: str) -> None:  # noqa: D401
        # Capture last status message if desired during assertions.
        pass


@pytest.fixture()
def controller(tmp_path):
    """Return a Controller wired to a DummyView and temp CryptoModel."""
    os.environ["LOCKSUM_DATA_DIR"] = str(tmp_path)

    # Reload config so it respects the temp path.
    from locksum import config as cfg  # noqa: WPS433  (import inside function)

    reload(cfg)
    globals()["_config"] = cfg  # update module ref if needed

    # Lazy import to ensure config reload propagates.
    from locksum.model import CryptoModel  # noqa: WPS433, E402
    from locksum.gui.controller import Controller  # noqa: WPS433, E402

    model = CryptoModel()
    dummy_view = DummyView()

    # Inject required placeholder attributes.
    dummy_view.delete_text_var = FakeVar()

    ctr = Controller(model=model, view=dummy_view)  # type: ignore[arg-type]
    dummy_view.controller = ctr  # bidirectional link mimicking real view
    return ctr


def test_delete_entry_success(controller):
    controller.stored_data = [("alpha", "hash1"), ("beta", "hash2")]
    controller.view.delete_text_var.set("alpha")

    # Monkeypatch save to no-op to avoid filesystem writes.
    controller.model.save_encrypted_data = lambda data: None  # type: ignore[assignment]

    controller.delete_entry_by_text()

    assert ("alpha", "hash1") not in controller.stored_data
    assert len(controller.stored_data) == 1


def test_delete_entry_not_found(controller):
    controller.stored_data = [("alpha", "hash1")]
    controller.view.delete_text_var.set("gamma")

    called = {}

    def fake_warn(title, msg):
        called["warning"] = (title, msg)

    # Patch messagebox.showwarning used inside controller.
    import importlib

    msgbox = importlib.import_module("tkinter.messagebox")
    original_warn = msgbox.showwarning
    msgbox.showwarning = fake_warn  # type: ignore[assignment]

    try:
        controller.delete_entry_by_text()
    finally:
        msgbox.showwarning = original_warn  # restore

    assert called.get("warning") is not None
