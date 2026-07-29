import sys
import types
import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "integration: mark test as requiring the macOS native toolchain (otool, codesign, etc.)"
    )
    _ensure_anthropic_stub()


def _ensure_anthropic_stub():
    """Inject a minimal anthropic stub into sys.modules if the real SDK is absent.

    This lets agent_modes.py's ``try: import anthropic`` succeed so that
    ``patch("macskillet.native.agent_modes.anthropic.Anthropic")`` works in unit tests without
    requiring the real Anthropic SDK to be installed.
    """
    if "anthropic" not in sys.modules or sys.modules["anthropic"] is None:
        stub = types.ModuleType("anthropic")

        class _Anthropic:  # noqa: D401
            """Minimal stub — replaced entirely by unittest.mock.patch in tests."""
            def __init__(self, **kwargs):
                pass

        stub.Anthropic = _Anthropic
        sys.modules["anthropic"] = stub
