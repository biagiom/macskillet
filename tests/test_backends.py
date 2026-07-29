"""Tests for backend selection and the shared backend contract."""

import platform
from unittest.mock import patch

import pytest

from macskillet.backends import (
    DETECTOR,
    NATIVE,
    Backend,
    BackendUnavailable,
    available_backends,
    select_backend,
)


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------

def test_auto_prefers_native_on_macos():
    if platform.system() != "Darwin":
        pytest.skip("macOS-only expectation")
    assert select_backend().name == "native"


def test_native_unavailable_off_macos():
    with patch("macskillet.backends.platform.system", return_value="Linux"):
        reason = NATIVE.unavailable_reason()
    assert reason is not None
    assert "macOS" in reason


def test_auto_falls_back_to_detector_off_macos():
    with patch("macskillet.backends.platform.system", return_value="Linux"):
        if not DETECTOR.is_available():
            pytest.skip("LIEF not installed")
        assert select_backend().name == "detector"


def test_explicit_backend_is_never_silently_downgraded():
    """An explicit choice must raise rather than fall back.

    Swapping backends changes which signals are observable, so a silent
    downgrade would change what a verdict means without telling the caller.
    """
    with patch("macskillet.backends.platform.system", return_value="Linux"):
        with pytest.raises(BackendUnavailable) as exc:
            select_backend("native")
    assert "native" in str(exc.value)


def test_unknown_backend_name_rejected():
    with pytest.raises(BackendUnavailable) as exc:
        select_backend("nonsense")
    assert "unknown backend" in str(exc.value)


def test_no_backend_available_raises_with_reasons():
    # Backend is a frozen dataclass, so swap the registry rather than the fields.
    dead_native = _stub_backend(name="native", _check=lambda: "no macOS")
    dead_detector = _stub_backend(name="detector", _check=lambda: "no LIEF")
    with patch("macskillet.backends._ORDER", (dead_native, dead_detector)):
        with pytest.raises(BackendUnavailable) as exc:
            select_backend()
    message = str(exc.value)
    assert "no macOS" in message and "no LIEF" in message


def test_available_backends_returns_only_usable_ones():
    for backend in available_backends():
        assert backend.is_available()


# ---------------------------------------------------------------------------
# Contract
# ---------------------------------------------------------------------------

def _stub_backend(**overrides) -> Backend:
    defaults = dict(
        name="stub",
        description="test double",
        _extract=lambda path: {"sample": {"path": path}},
        _tools=lambda: [{"name": "get_feature"}],
        _dispatch=lambda features, name, payload: {"ok": name},
        _check=lambda: None,
    )
    defaults.update(overrides)
    return Backend(**defaults)


def test_extract_stamps_backend_name():
    features = _stub_backend().extract("/tmp/x")
    assert features["sample"]["backend"] == "stub"


def test_extract_stamps_backend_even_without_sample_key():
    backend = _stub_backend(_extract=lambda path: {})
    assert backend.extract("/tmp/x")["sample"]["backend"] == "stub"


def test_dispatch_converts_exceptions_into_error_results():
    """A raising tool must not kill the ReAct loop mid-analysis."""
    def boom(features, name, payload):
        raise RuntimeError("tool exploded")

    result = _stub_backend(_dispatch=boom).dispatch({}, "get_feature", {})
    assert "error" in result
    assert "tool exploded" in result["error"]
    assert "RuntimeError" in result["error"]


def test_unavailable_backend_refuses_to_extract():
    backend = _stub_backend(_check=lambda: "nope")
    with pytest.raises(BackendUnavailable):
        backend.extract("/tmp/x")


def test_both_backends_expose_named_tool_schemas():
    for backend in available_backends():
        tools = backend.tools
        assert isinstance(tools, list) and tools
        for tool in tools:
            assert "name" in tool
            assert "input_schema" in tool


# ---------------------------------------------------------------------------
# Mode dispatch
# ---------------------------------------------------------------------------

def test_run_mode_rejects_unknown_mode():
    from macskillet.native.agent_modes import run_mode

    with pytest.raises(ValueError) as exc:
        run_mode({}, mode="telepathy")
    assert "unknown mode" in str(exc.value)


def test_all_modes_registered():
    from macskillet.native.agent_modes import MODES

    assert set(MODES) == {"react", "one_shot", "hierarchical", "react_thinking"}
    for func in MODES.values():
        assert callable(func)
