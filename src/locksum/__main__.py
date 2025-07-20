"""Module entry-point so `python -m locksum` works after the src/ layout move.

It simply imports and executes :pymod:`locksum.launcher`, keeping the single
source of truth for runtime dispatch between GUI & CLI.
"""

from importlib import import_module


def main() -> None:  # noqa: D401
    """Entrypoint that forwards to :pymod:`locksum.launcher.main`."""

    launcher = import_module("locksum.launcher")
    launcher.main()


if __name__ == "__main__":
    main()
