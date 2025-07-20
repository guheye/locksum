"""Makes ``python -m locksum.cli`` behave like the command-line script.

It simply calls :pyfunc:`locksum.cli.main`.
"""

from importlib import import_module


def main() -> None:  # noqa: D401
    cli = import_module("locksum.cli")
    cli.main()


if __name__ == "__main__":
    main()
