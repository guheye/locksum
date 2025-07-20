"""Locksum package.

A secure SHA-256 hash generator with encrypted storage and a simple Tkinter GUI.
"""

# ruff: noqa: I001

__all__ = [
    "config",
    "model",
    "view",
    "controller",
    "securemem",
]

# ---------------------------------------------------------------------------
# Hypothesis global configuration – suppress noisy health-check warning when
# function-scoped fixtures are combined with ``@given`` (see property tests).
# ---------------------------------------------------------------------------
try:
    from hypothesis import HealthCheck as _HealthCheck
    from hypothesis import settings as _hyp_settings

    _hyp_settings.register_profile(
        "locksum_ci", suppress_health_check=(_HealthCheck.function_scoped_fixture,)
    )
    _hyp_settings.load_profile("locksum_ci")
except Exception:  # pragma: no cover – Hypothesis may not be installed
    pass
