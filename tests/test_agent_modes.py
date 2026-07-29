"""
test_agent_modes.py — Unit tests for agent_modes.py (mocked Anthropic API)

Run from repo root:
    PYTHONPATH=src/native python3 -m pytest tests/test_agent_modes.py -v
"""
import json
import sys
import os
from unittest.mock import patch, MagicMock


from macskillet.native.agent_modes import run_one_shot, run_hierarchical, run_react_thinking


def make_features(**overrides):
    """Minimal features dict for testing."""
    base = {
        "sample": {
            "name": "Test.app", "type": "app_bundle",
            "sha256": "abc123", "filesize_bytes": 1024,
        },
        "preflight": {
            "has_quarantine": True, "quarantine_bypassed": False,
            "download_origin_urls": [],
        },
        "signature": {
            "signed": True, "signing_status": "developer_id",
            "team_id": "ABCD1234", "notarized": True,
            "hardened_runtime": True, "authority_chain": [],
            "entitlements": {},
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
# Helpers
# ---------------------------------------------------------------------------

_BENIGN_VERDICT = json.dumps({
    "verdict": "BENIGN", "confidence": "HIGH", "risk_score": 0,
    "recommendation": "ALLOW", "summary": "Clean sample.",
    "key_indicators": ["developer_id_signed"], "reasoning_chain": [],
})

_MALICIOUS_VERDICT = json.dumps({
    "verdict": "MALICIOUS", "confidence": "HIGH", "risk_score": 15,
    "recommendation": "BLOCK", "summary": "Injection triad detected.",
    "key_indicators": ["injection_triad"], "reasoning_chain": [],
})

def _mock_response(text: str, input_tokens: int = 100, output_tokens: int = 50):
    """Build a mock anthropic response with a single text block."""
    content_block = MagicMock()
    content_block.text = text
    content_block.type = "text"
    resp = MagicMock()
    resp.content = [content_block]
    resp.stop_reason = "end_turn"
    resp.usage.input_tokens = input_tokens
    resp.usage.output_tokens = output_tokens
    return resp


# ---------------------------------------------------------------------------
# run_one_shot tests
# ---------------------------------------------------------------------------

def test_run_one_shot_returns_all_required_fields():
    with patch("macskillet.native.agent_modes.anthropic.Anthropic") as MockClient:
        MockClient.return_value.messages.create.return_value = _mock_response(_BENIGN_VERDICT)
        result = run_one_shot(make_features())

    assert result["verdict"] == "BENIGN"
    assert result["confidence"] == "HIGH"
    assert result["mode"] == "one_shot"
    assert result["sample"]["name"] == "Test.app"
    assert result["input_tokens"] == 100
    assert result["output_tokens"] == 50
    assert "reasoning_chain" in result
    assert "key_indicators" in result


def test_run_one_shot_fallback_on_unparseable_verdict():
    with patch("macskillet.native.agent_modes.anthropic.Anthropic") as MockClient:
        MockClient.return_value.messages.create.return_value = _mock_response("I cannot determine.")
        result = run_one_shot(make_features())

    assert result["verdict"] == "SUSPICIOUS"
    assert result["mode"] == "one_shot"
    assert "raw_output" in result


def test_run_one_shot_calls_api_once():
    with patch("macskillet.native.agent_modes.anthropic.Anthropic") as MockClient:
        MockClient.return_value.messages.create.return_value = _mock_response(_BENIGN_VERDICT)
        run_one_shot(make_features())

    assert MockClient.return_value.messages.create.call_count == 1


# ---------------------------------------------------------------------------
# run_hierarchical tests
# ---------------------------------------------------------------------------

def _make_end_turn_response(text: str):
    """Response that ends immediately (no tool calls)."""
    content_block = MagicMock()
    content_block.text = text
    content_block.type = "text"
    resp = MagicMock()
    resp.content = [content_block]
    resp.stop_reason = "end_turn"
    return resp


def test_run_hierarchical_early_exit_on_benign_high():
    """Stage 1 returns BENIGN/HIGH → Stage 2 must not run."""
    benign_triage = json.dumps({
        "verdict": "BENIGN", "confidence": "HIGH", "risk_score": 0,
        "recommendation": "ALLOW",
        "summary": "Properly signed, notarized, no packing.",
        "key_indicators": ["developer_id_signed", "notarized"],
        "reasoning_chain": [],
    })

    with patch("macskillet.native.agent_modes.anthropic.Anthropic") as MockClient:
        MockClient.return_value.messages.create.return_value = _make_end_turn_response(benign_triage)
        result = run_hierarchical(make_features())
        call_count = MockClient.return_value.messages.create.call_count

    assert result["verdict"] == "BENIGN"
    assert result["mode"] == "hierarchical_early_exit"
    assert call_count == 1  # Stage 2 never ran


def test_run_hierarchical_proceeds_to_stage2_when_suspicious():
    """Stage 1 returns SUSPICIOUS → Stage 2 full analysis must run."""
    suspicious_triage = json.dumps({
        "verdict": "SUSPICIOUS", "confidence": "MEDIUM", "risk_score": 3,
        "recommendation": "INVESTIGATE",
        "summary": "Not notarized.",
        "key_indicators": ["not_notarized"],
        "reasoning_chain": [],
    })
    malicious_full = json.dumps({
        "verdict": "MALICIOUS", "confidence": "HIGH", "risk_score": 15,
        "recommendation": "BLOCK",
        "summary": "Full analysis reveals injection triad.",
        "key_indicators": ["injection_triad"],
        "reasoning_chain": [],
    })

    with patch("macskillet.native.agent_modes.anthropic.Anthropic") as MockClient:
        MockClient.return_value.messages.create.side_effect = [
            _make_end_turn_response(suspicious_triage),
            _make_end_turn_response(malicious_full),
        ]
        result = run_hierarchical(make_features())
        call_count = MockClient.return_value.messages.create.call_count

    assert result["verdict"] == "MALICIOUS"
    assert result["mode"] == "hierarchical_full"
    assert result["triage_result"]["verdict"] == "SUSPICIOUS"
    assert call_count == 2  # Stage 1 + Stage 2


def test_run_hierarchical_benign_medium_confidence_proceeds_to_stage2():
    """BENIGN with MEDIUM confidence is not an early exit — needs full analysis."""
    benign_medium = json.dumps({
        "verdict": "BENIGN", "confidence": "MEDIUM", "risk_score": 1,
        "recommendation": "ALLOW",
        "summary": "Seems benign but missing notarization.",
        "key_indicators": [],
        "reasoning_chain": [],
    })
    benign_full = json.dumps({
        "verdict": "BENIGN", "confidence": "HIGH", "risk_score": 1,
        "recommendation": "ALLOW",
        "summary": "Full analysis confirms benign.",
        "key_indicators": ["developer_id_signed"],
        "reasoning_chain": [],
    })

    with patch("macskillet.native.agent_modes.anthropic.Anthropic") as MockClient:
        MockClient.return_value.messages.create.side_effect = [
            _make_end_turn_response(benign_medium),
            _make_end_turn_response(benign_full),
        ]
        result = run_hierarchical(make_features())

    assert result["mode"] == "hierarchical_full"


# ---------------------------------------------------------------------------
# run_react_thinking tests
# ---------------------------------------------------------------------------

def _make_thinking_response(verdict_text: str):
    """Response with a thinking block followed by a text block (end_turn)."""
    thinking_block = MagicMock()
    thinking_block.type = "thinking"
    thinking_block.thinking = "Let me reason carefully..."

    text_block = MagicMock()
    text_block.type = "text"
    text_block.text = verdict_text

    resp = MagicMock()
    resp.content = [thinking_block, text_block]
    resp.stop_reason = "end_turn"
    return resp


def test_run_react_thinking_returns_verdict_with_mode():
    with patch("macskillet.native.agent_modes.anthropic.Anthropic") as MockClient:
        MockClient.return_value.beta.messages.create.return_value = (
            _make_thinking_response(_MALICIOUS_VERDICT)
        )
        result = run_react_thinking(make_features())

    assert result["verdict"] == "MALICIOUS"
    assert result["mode"] == "react_thinking"
    assert result["sample"]["name"] == "Test.app"
    assert "agent_tool_calls" in result


def test_run_react_thinking_uses_beta_api():
    """Must call client.beta.messages.create (not client.messages.create)."""
    with patch("macskillet.native.agent_modes.anthropic.Anthropic") as MockClient:
        MockClient.return_value.beta.messages.create.return_value = (
            _make_thinking_response(_BENIGN_VERDICT)
        )
        run_react_thinking(make_features())

    assert MockClient.return_value.beta.messages.create.called
    assert not MockClient.return_value.messages.create.called


def test_run_react_thinking_fallback_on_bad_verdict():
    with patch("macskillet.native.agent_modes.anthropic.Anthropic") as MockClient:
        MockClient.return_value.beta.messages.create.return_value = (
            _make_thinking_response("No verdict yet.")
        )
        result = run_react_thinking(make_features())

    assert result["verdict"] == "SUSPICIOUS"
    assert result["mode"] == "react_thinking"
    assert "raw_output" in result
