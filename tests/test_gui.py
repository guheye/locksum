from __future__ import annotations

"""Lightweight GUI smoke test.

Attempts to initialise the Tk-based GUI to ensure widgets can be constructed
without raising exceptions.  The test is skipped automatically when running
in headless environments where a display server is unavailable (common in CI
containers).
"""

import os

import pytest


@pytest.mark.skipif(os.name == "nt", reason="GUI smoke test unstable on Windows CI")
def test_gui_smoke():  # noqa: D401
    try:
        import tkinter as tk

        root = tk.Tk()
        root.withdraw()  # do not show window
    except Exception:  # noqa: BLE001
        # Either Tkinter is unavailable or no display is present – skip test.
        pytest.skip("Tkinter unavailable or headless environment – skipping GUI test")

    from locksum.gui.view import MainView  # noqa: E402

    view = MainView(root)
    assert view.root is root

    root.destroy()
