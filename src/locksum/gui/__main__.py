"""Locksum application entrypoint.

Run this file to launch the GUI.
"""

from __future__ import annotations

import ttkbootstrap as tb

from .. import config
from ..model import CryptoModel
from .controller import Controller
from .view import MainView


def main() -> None:  # noqa: D401
    """Application entrypoint."""
    root = tb.Window(themename="darkly")
    root.title(config.APP_TITLE)
    root.geometry(config.APP_GEOMETRY)
    root.resizable(False, False)

    model = CryptoModel()

    # First create the view without a controller instance.
    view = MainView(root)

    # Now wire up the controller and inject it into the view.
    controller = Controller(model=model, view=view)
    view.set_controller(controller)

    controller.start()
    root.mainloop()


if __name__ == "__main__":
    main()
