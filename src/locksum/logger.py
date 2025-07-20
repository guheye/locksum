"""Project-wide logger helper.

Import `logger` and use standard levels (debug/info/warning/error).
"""

import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)

logger = logging.getLogger("locksum")
