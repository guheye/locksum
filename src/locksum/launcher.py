from __future__ import annotations

# ruff: noqa: E402

"""Unified launcher for Locksum.

Running the *locksum* console-script without any arguments opens the themed
GUI.  As soon as at least one positional argument is supplied we delegate to
:pyfunc:`locksum.cli.main`, giving users a shorter command for everyday hash
operations while keeping the graphical client one keystroke away.
"""

import sys
from importlib import import_module


def main(argv: list[str] | None = None) -> None:  # noqa: D401
    """Dispatch to GUI or CLI depending on *argv* length.*"""

    args = sys.argv[1:] if argv is None else argv

    if not args:
        # No sub-command → launch desktop application.
        gui = import_module("locksum.gui.__main__")
        gui.main()
    else:
        cli = import_module("locksum.cli")
        cli.main([*args])


if __name__ == "__main__":
    main()
