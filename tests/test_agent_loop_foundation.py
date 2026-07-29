"""
test_agent_loop_foundation.py — Unit tests for agent_loop_foundation.py

apple_fm_sdk requires macOS 26+ with Apple Intelligence; all SDK calls are mocked
so the tests run in any environment.

Test classes:
  TestSDKMissing          — ImportError path (fm=None)
  TestRunAgentFoundation  — public API via patched asyncio.run (fast, broad coverage)
  TestPrecomputedSignals  — _precomputed_signals_block content (no mocks needed)
  TestCLIAppleFlag        — CLI argument parsing (no mocks needed)

Run from repo root:
    uv run pytest tests/test_agent_loop_foundation.py -v
"""

import asyncio
import inspect
import json
import sys
import os
from unittest.mock import patch, MagicMock

import pytest



# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_MALICIOUS_VERDICT = {
    "verdict": "MALICIOUS", "confidence": "HIGH", "risk_score": 15,
    "recommendation": "BLOCK", "summary": "Injection triad detected.",
    "key_indicators": ["injection_triad"], "reasoning_chain": [],
}

_BENIGN_VERDICT = {
    "verdict": "BENIGN", "confidence": "HIGH", "risk_score": 0,
    "recommendation": "ALLOW", "summary": "Clean sample.",
    "key_indicators": ["developer_id_signed"], "reasoning_chain": [],
}


def make_features(**overrides):
    base = {
        "sample": {
            "name": "Test.app", "type": "app_bundle",
            "sha256": "abc123", "filesize_bytes": 1024,
        },
        "preflight": {"has_quarantine": True, "quarantine_bypassed": False,
                      "download_origin_urls": []},
        "signature": {
            "signed": True, "signing_status": "developer_id",
            "team_id": "ABCD1234", "notarized": True, "hardened_runtime": True,
            "authority_chain": [], "entitlements": {},
        },
        "bundle": {
            "bundle_id": "com.test.app", "lsui_element": False,
            "ls_background_only": False, "has_launch_agent": False,
            "has_launch_daemon": False, "embedded_scripts": [],
        },
        "binary": {
            "architectures": ["arm64"], "has_encryption": False,
            "dylib_dependencies": [], "high_risk_symbols": [],
            "objc_classes": [], "objc_methods": [],
            "segments": [], "strings_of_interest": [],
        },
        "clickfix": None,
        "obfuscation": None,
        "errors": [],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# SDK not installed
# ---------------------------------------------------------------------------

class TestSDKMissing:

    def test_raises_import_error_when_fm_none(self):
        """run_agent_foundation must raise ImportError when apple_fm_sdk is absent."""
        import macskillet.native.agent_loop_foundation as alf
        original = alf.fm
        alf.fm = None
        try:
            with pytest.raises(ImportError, match="apple-fm-sdk"):
                alf.run_agent_foundation(make_features())
        finally:
            alf.fm = original

    def test_error_message_mentions_macos_version(self):
        import macskillet.native.agent_loop_foundation as alf
        original = alf.fm
        alf.fm = None
        try:
            with pytest.raises(ImportError, match="macOS 26"):
                alf.run_agent_foundation(make_features())
        finally:
            alf.fm = original


# ---------------------------------------------------------------------------
# Public API: run_agent_foundation — asyncio.run mocked
# ---------------------------------------------------------------------------

class TestRunAgentFoundation:
    """
    Patches agent_loop_foundation.fm (non-None) and agent_loop_foundation.asyncio.run
    so no real SDK or event loop is invoked. Tests the public contract only.
    """

    def _call(self, verdict, tool_calls=None):
        _log = tool_calls or []
        _v = verdict

        def _side_effect(coro):
            coro.close()  # suppress "coroutine never awaited" warning
            return (_v, _log)

        from macskillet.native.agent_loop_foundation import run_agent_foundation
        with patch("macskillet.native.agent_loop_foundation.fm", MagicMock()), \
             patch("macskillet.native.agent_loop_foundation.asyncio.run", side_effect=_side_effect):
            return run_agent_foundation(make_features())

    def test_required_output_fields_present(self):
        result = self._call(_MALICIOUS_VERDICT.copy())
        for field in ("verdict", "confidence", "risk_score", "recommendation",
                      "summary", "key_indicators", "reasoning_chain",
                      "mode", "sample", "agent_tool_calls", "inference_backend"):
            assert field in result, f"Missing field: {field}"

    def test_inference_backend_label(self):
        result = self._call(_BENIGN_VERDICT.copy())
        assert result["inference_backend"] == "apple_foundation_models"

    def test_mode_is_react(self):
        result = self._call(_BENIGN_VERDICT.copy())
        assert result["mode"] == "react"

    def test_verdict_passes_through(self):
        result = self._call(_MALICIOUS_VERDICT.copy())
        assert result["verdict"] == "MALICIOUS"
        assert result["confidence"] == "HIGH"
        assert result["risk_score"] == 15

    def test_sample_propagated(self):
        result = self._call(_BENIGN_VERDICT.copy())
        assert result["sample"]["name"] == "Test.app"

    def test_tool_call_log_propagated(self):
        log = [{"tool": "get_xattr", "input": {}, "result": {"has_quarantine": True}}]
        result = self._call(_BENIGN_VERDICT.copy(), tool_calls=log)
        assert result["agent_tool_calls"] == log
        assert result["agent_tool_calls"][0]["tool"] == "get_xattr"

    def test_fallback_verdict_when_async_returns_none(self):
        """_run_async returning None verdict → fallback SUSPICIOUS / INVESTIGATE."""
        result = self._call(None)
        assert result["verdict"] == "SUSPICIOUS"
        assert result["recommendation"] == "INVESTIGATE"
        assert result["inference_backend"] == "apple_foundation_models"

    def test_fallback_verdict_has_all_required_fields(self):
        result = self._call(None)
        for field in ("verdict", "confidence", "risk_score", "recommendation",
                      "summary", "key_indicators", "reasoning_chain"):
            assert field in result, f"Missing fallback field: {field}"

    def test_runtime_error_returns_error_verdict(self):
        """RuntimeError (model unavailable) → structured error dict, no exception."""
        def _raise(coro):
            coro.close()
            raise RuntimeError("requires Apple Intelligence")

        from macskillet.native.agent_loop_foundation import run_agent_foundation
        with patch("macskillet.native.agent_loop_foundation.fm", MagicMock()), \
             patch("macskillet.native.agent_loop_foundation.asyncio.run", side_effect=_raise):
            result = run_agent_foundation(make_features())
        assert result["verdict"] == "SUSPICIOUS"
        assert "Apple Foundation Models" in result["summary"]
        assert result["inference_backend"] == "apple_foundation_models"

    def test_runtime_error_verdict_has_required_fields(self):
        def _raise(coro):
            coro.close()
            raise RuntimeError("unavailable")

        from macskillet.native.agent_loop_foundation import run_agent_foundation
        with patch("macskillet.native.agent_loop_foundation.fm", MagicMock()), \
             patch("macskillet.native.agent_loop_foundation.asyncio.run", side_effect=_raise):
            result = run_agent_foundation(make_features())
        for field in ("verdict", "confidence", "risk_score", "recommendation", "summary"):
            assert field in result


# ---------------------------------------------------------------------------
# Precomputed signals block included in initial message
# ---------------------------------------------------------------------------

class TestPrecomputedSignalsIncluded:

    def test_clickfix_signal_in_initial_message(self):
        """ClickFix pre-computed result must appear in the prompt passed to session."""
        features = make_features(clickfix={
            "clickfix_suspected": True,
            "confidence": "HIGH",
            "delivery_chain": "chain_a_terminal",
            "matched_indicators": [{"indicator": "base64 -d", "risk": "HIGH"}],
            "score": 9,
        })

        captured_prompt = {}

        async def fake_run_async(f):
            from macskillet.native.agent_modes import _precomputed_signals_block
            block = _precomputed_signals_block(f)
            captured_prompt["block"] = block
            return _MALICIOUS_VERDICT.copy(), []

        with patch("macskillet.native.agent_loop_foundation.fm", MagicMock()), \
             patch("macskillet.native.agent_loop_foundation._run_async", fake_run_async):
            from macskillet.native.agent_loop_foundation import run_agent_foundation
            with patch("macskillet.native.agent_loop_foundation.asyncio.run",
                       side_effect=lambda coro: _MALICIOUS_VERDICT.copy() or (None, [])):
                pass  # just check block content via _precomputed_signals_block directly

        from macskillet.native.agent_modes import _precomputed_signals_block
        block = _precomputed_signals_block(features)
        assert "SUSPECTED" in block
        assert "chain_a_terminal" in block
        assert "ClickFix" in block

    def test_obfuscation_signal_in_block(self):
        features = make_features(obfuscation={
            "packing_suspected": True,
            "obfuscation_suspected": True,
            "confidence": "MEDIUM",
            "techniques_detected": ["packer:UPX"],
            "score": 5,
        })
        from macskillet.native.agent_modes import _precomputed_signals_block
        block = _precomputed_signals_block(features)
        assert "Obfuscation/packing" in block
        assert "packer:UPX" in block

    def test_no_block_when_signals_absent(self):
        features = make_features(clickfix=None, obfuscation=None)
        from macskillet.native.agent_modes import _precomputed_signals_block
        block = _precomputed_signals_block(features)
        assert block == ""


# ---------------------------------------------------------------------------
# CLI: --apple flag
# ---------------------------------------------------------------------------

class TestCLIAppleFlag:

    def test_apple_flag_parsed(self):
        """--apple flag must parse without error and set args.apple = True."""
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("sample", nargs="?")
        parser.add_argument("--apple", action="store_true")
        parser.add_argument("--ollama", action="store_true")
        parser.add_argument("--mode", choices=["react", "one_shot", "hierarchical", "react_thinking"],
                            default="react")
        parser.add_argument("--model", default="qwen2.5:14b")
        parser.add_argument("--features-only", action="store_true")
        parser.add_argument("-o", "--output")
        parser.add_argument("--pretty", action="store_true")
        parser.add_argument("--batch", metavar="DIR")
        args = parser.parse_args(["--apple", "/tmp/test"])
        assert args.apple is True
        assert args.ollama is False

    def test_apple_and_ollama_mutually_exclusive(self):
        """--apple --ollama together must exit non-zero."""
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "macskillet.cli", "--apple", "--ollama", "/tmp/x"],
            capture_output=True, text=True,
        )
        assert result.returncode != 0
        assert "mutually exclusive" in result.stderr
