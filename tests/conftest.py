"""Pytest configuration for Locksum test suite.

Ensures the project root is on *sys.path* so the *locksum* package can be
imported when running tests without installing the project into the active
virtual environment.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Prepend the project root (parent directory of *tests*) to sys.path so that
# `import locksum` works when the package has not been installed yet.
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Also add the *src* directory used by the new src-layout so tests can import
# the installed package even when Locksum has not been installed in editable
# mode yet.
SRC_DIR = ROOT_DIR / "src"
if SRC_DIR.exists() and str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
