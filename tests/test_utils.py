import sys
import os
import pytest


from macskillet.native.utils import _entropy, _parse_json_verdict


class TestEntropy:
    def test_uniform_bytes_max_entropy(self):
        assert abs(_entropy(bytes(range(256))) - 8.0) < 0.01

    def test_single_byte_zero_entropy(self):
        assert _entropy(bytes([0x41] * 1000)) == 0.0

    def test_empty_returns_zero(self):
        assert _entropy(b"") == 0.0

    def test_normal_range(self):
        e = _entropy(b"Hello World" * 100)
        assert 0.0 < e < 8.0


class TestParseJsonVerdict:
    def test_fenced_json_block(self):
        text = '```json\n{"verdict": "MALICIOUS", "confidence": "HIGH"}\n```'
        assert _parse_json_verdict(text)["verdict"] == "MALICIOUS"

    def test_plain_fenced_block(self):
        text = '```\n{"verdict": "MALICIOUS", "confidence": "HIGH"}\n```'
        assert _parse_json_verdict(text)["verdict"] == "MALICIOUS"

    def test_bare_json_object(self):
        text = '{"verdict": "BENIGN", "confidence": "LOW", "risk_score": 1}'
        assert _parse_json_verdict(text)["verdict"] == "BENIGN"

    def test_json_embedded_in_text(self):
        text = 'Conclusion:\n{"verdict": "SUSPICIOUS", "confidence": "MEDIUM"}\nDone.'
        result = _parse_json_verdict(text)
        assert result is not None
        assert result["verdict"] == "SUSPICIOUS"
        assert result["confidence"] == "MEDIUM"

    def test_empty_string_returns_none(self):
        assert _parse_json_verdict("") is None

    def test_non_json_returns_none(self):
        assert _parse_json_verdict("just plain text") is None
