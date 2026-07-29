import json
import plistlib
import sys
import os
from unittest.mock import patch


from macskillet.native.extract_features_native import analyze_preflight


def _hex_plist(data) -> str:
    """Binary plist → hex string, simulating `xattr -px` stdout."""
    raw = plistlib.dumps(data, fmt=plistlib.FMT_BINARY)
    return " ".join(f"{b:02x}" for b in raw)


def _make_run_mock(where_froms_hex: str | None = None):
    """Return a mock for extract_features_native.run that handles all calls."""
    def mock_run(cmd, timeout=30, input_data=None):
        if cmd[0] == "file":
            return ("Mach-O 64-bit executable arm64", "", 0)
        if cmd[0] == "xattr" and "-l" in cmd:
            return ("", "", 0)
        if cmd[0] == "xattr" and "quarantine" in " ".join(cmd):
            return ("", "", 1)       # no quarantine xattr
        if cmd[0] == "xattr" and "-px" in cmd and "kMDItemWhereFroms" in " ".join(cmd):
            if where_froms_hex:
                return (where_froms_hex, "", 0)
            return ("", "", 1)       # xattr absent
        if cmd[0] == "plutil" and input_data is not None:
            # Real decode: use Python's plistlib so we don't need a subprocess
            decoded = plistlib.loads(input_data)
            return (json.dumps(decoded), "", 0)
        if cmd[0] == "mdls":
            return ("(null)", "", 0)
        return ("", "", 0)
    return mock_run


class TestAnalyzePreflightUrls:
    def test_download_origin_urls_populated(self):
        """kMDItemWhereFroms binary plist should decode into download_origin_urls."""
        urls = ["https://cdn.example.com/Installer.dmg", "https://cdn.example.com/"]
        hex_data = _hex_plist(urls)

        with patch('macskillet.native.extract_features_native.run', side_effect=_make_run_mock(hex_data)):
            result = analyze_preflight("/fake/binary")

        assert result["download_origin_urls"] == urls

    def test_no_xattr_returns_empty_list(self):
        """When kMDItemWhereFroms is absent, download_origin_urls is []."""
        with patch('macskillet.native.extract_features_native.run', side_effect=_make_run_mock(None)):
            result = analyze_preflight("/fake/binary")

        assert result["download_origin_urls"] == []

    def test_non_http_strings_excluded(self):
        """Only http/https URLs should appear in download_origin_urls."""
        data = ["https://cdn.example.com/file.dmg", "file:///tmp/something", "ftp://old.server/"]
        hex_data = _hex_plist(data)

        with patch('macskillet.native.extract_features_native.run', side_effect=_make_run_mock(hex_data)):
            result = analyze_preflight("/fake/binary")

        assert result["download_origin_urls"] == ["https://cdn.example.com/file.dmg"]

    def test_plutil_failure_returns_empty_list(self):
        """If plutil fails to decode the plist, download_origin_urls must be []."""
        urls = ["https://cdn.example.com/Installer.dmg"]
        hex_data = _hex_plist(urls)

        def mock_run_plutil_fails(cmd, timeout=30, input_data=None):
            if cmd[0] == "file":
                return ("Mach-O 64-bit executable arm64", "", 0)
            if cmd[0] == "xattr" and "-l" in cmd:
                return ("", "", 0)
            if cmd[0] == "xattr" and "quarantine" in " ".join(cmd):
                return ("", "", 1)
            if cmd[0] == "xattr" and "-px" in cmd:
                return (hex_data, "", 0)
            if cmd[0] == "plutil":
                return ("", "error: not a plist", 1)  # plutil fails
            if cmd[0] == "mdls":
                return ("(null)", "", 0)
            return ("", "", 0)

        with patch('macskillet.native.extract_features_native.run', side_effect=mock_run_plutil_fails):
            result = analyze_preflight("/fake/binary")

        assert result["download_origin_urls"] == []
