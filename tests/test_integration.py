"""
test_integration.py — End-to-end smoke test using the live macOS toolchain.

Requires: macOS 12+, Xcode CLI tools (otool, codesign, nm, lipo).
Run:  pytest tests/test_integration.py -v -m integration
Skip: pytest tests/ -m "not integration"
"""

import sys
import os
import json

import pytest


FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')


class TestExtractIntegration:
    pytestmark = pytest.mark.integration
    def test_extract_ls_completes_without_errors(self):
        """`extract('/bin/ls')` must complete with no errors using native macOS tools."""
        from macskillet.native.feature_extractor import extract
        features = extract("/bin/ls")
        assert features["errors"] == [], f"Unexpected errors: {features['errors']}"

    def test_extract_ls_top_level_keys_present(self):
        """Feature dict must have all required top-level keys."""
        from macskillet.native.feature_extractor import extract
        features = extract("/bin/ls")
        for key in ("sample", "preflight", "signature", "binary", "obfuscation", "errors"):
            assert key in features, f"Missing key: {key}"

    def test_extract_ls_is_macho_binary(self):
        """/bin/ls must be identified as macho_binary, not app_bundle."""
        from macskillet.native.feature_extractor import extract
        features = extract("/bin/ls")
        assert features["sample"]["type"] == "macho_binary"

    def test_extract_ls_has_architectures(self):
        """/bin/ls must report at least one architecture."""
        from macskillet.native.feature_extractor import extract
        features = extract("/bin/ls")
        assert len(features["binary"]["architectures"]) > 0

    def test_extract_ls_has_imports(self):
        """/bin/ls must have at least a few imported symbols."""
        from macskillet.native.feature_extractor import extract
        features = extract("/bin/ls")
        syms = features["binary"]["symbols_imported"]
        assert len(syms) > 0
        assert any(s.startswith("_") for s in syms), f"No C symbols found in: {syms[:5]}"

    def test_extract_ls_is_signed(self):
        """/bin/ls must be code-signed (Apple system binary)."""
        from macskillet.native.feature_extractor import extract
        features = extract("/bin/ls")
        assert features["signature"]["signed"] is True


class TestFixturesLoadable:
    def test_clean_binary_fixture_loadable(self):
        """clean_binary.json must be valid JSON with the expected schema."""
        path = os.path.join(FIXTURES, 'clean_binary.json')
        assert os.path.exists(path), (
            "Generate with: cd src/native && "
            "python3 feature_extractor.py -f /bin/ls --pretty "
            "> ../../tests/fixtures/clean_binary.json"
        )
        with open(path) as f:
            data = json.load(f)
        assert data["sample"]["type"] == "macho_binary"
        assert data["binary"]["architectures"]
