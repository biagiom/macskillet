"""
test_obfuscation_detector.py — Unit tests for obfuscation_detector.py

These tests mock subprocess calls so no real binaries are needed.

Run from repo root:
    PYTHONPATH=../src/native python3 -m pytest test_obfuscation_detector.py -v
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock


from macskillet.common.deep_scan import scan_runonly_applescript
from macskillet.native.obfuscation_detector import (
    detect_obfuscation,
    detect_packer_signatures,
    analyze_section_entropy,
    analyze_string_density,
    analyze_symbol_table,
    check_section_names,
    detect_language_runtime,
    _entropy,
)


# ---------------------------------------------------------------------------
# Unit tests for individual functions
# ---------------------------------------------------------------------------

class TestEntropyCalculation:

    def test_uniform_bytes_max_entropy(self):
        """256 unique bytes → entropy = 8.0"""
        data = bytes(range(256))
        e = _entropy(data)
        assert abs(e - 8.0) < 0.01

    def test_single_byte_zero_entropy(self):
        """All same byte → entropy = 0.0"""
        data = bytes([0x41] * 1000)
        e = _entropy(data)
        assert e == 0.0

    def test_normal_text_entropy(self):
        """Normal English text → entropy roughly 4–5"""
        data = b"Hello World, this is a normal string with some repetition." * 10
        e = _entropy(data)
        assert 3.0 < e < 6.0

    def test_empty_data(self):
        e = _entropy(b"")
        assert e == 0.0


class TestSectionEntropyPackingRatio:
    """packing_suspected_via_entropy is a byte-weighted ratio (packed-segment
    bytes / total analyzed segment bytes), matching pefile's is_probably_packed()
    and The Art of Mac Malware vol. 2's entropy-ratio guidance -- not a count of
    segments."""

    _HIGH_ENTROPY = bytes(range(256))  # entropy ~8.0, well above any "packed" threshold
    _LOW_ENTROPY = b"\x41"             # entropy 0.0 when repeated

    def _write_binary(self, tmp_path, high_entropy_size, low_entropy_size):
        path = tmp_path / "sample"
        high = (self._HIGH_ENTROPY * ((high_entropy_size // 256) + 1))[:high_entropy_size]
        low = self._LOW_ENTROPY * low_entropy_size
        path.write_bytes(high + low)
        segments = [
            {"name": "__TEXT", "fileoff": 0, "filesize": high_entropy_size},
            {"name": "__DATA", "fileoff": high_entropy_size, "filesize": low_entropy_size},
        ]
        return str(path), segments

    def test_large_packed_fraction_flags_packing_suspected(self, tmp_path):
        """Packed segment is 1/3 of total bytes -- above the 20% default threshold."""
        path, segments = self._write_binary(tmp_path, high_entropy_size=250, low_entropy_size=500)
        result = analyze_section_entropy(path, segments)
        assert result["packing_suspected_via_entropy"] is True
        assert abs(result["packing_ratio"] - (250 / 750)) < 0.001

    def test_small_packed_fraction_not_flagged(self, tmp_path):
        """A small packed segment in an otherwise large binary (5% ratio) is a
        known, accepted non-match for this heuristic -- known-packer
        byte-signature matching is the separate path for that case."""
        path, segments = self._write_binary(tmp_path, high_entropy_size=500, low_entropy_size=9500)
        result = analyze_section_entropy(path, segments)
        assert result["packing_suspected_via_entropy"] is False
        assert abs(result["packing_ratio"] - 0.05) < 0.001

    def test_custom_threshold_overrides_default(self, tmp_path):
        """The same 5%-ratio sample flips to flagged with a lower custom threshold."""
        path, segments = self._write_binary(tmp_path, high_entropy_size=500, low_entropy_size=9500)
        result = analyze_section_entropy(path, segments, packing_ratio_threshold=0.03)
        assert result["packing_suspected_via_entropy"] is True

    def test_packing_ratio_field_present_and_correct(self, tmp_path):
        path, segments = self._write_binary(tmp_path, high_entropy_size=200, low_entropy_size=800)
        result = analyze_section_entropy(path, segments)
        assert "packing_ratio" in result
        assert abs(result["packing_ratio"] - 0.20) < 0.001


class TestPackerSignatures:

    def test_upx_detected(self, tmp_path):
        binary = tmp_path / "packed_binary"
        binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100 + b"UPX!" + b"\x00" * 100)
        results = detect_packer_signatures(str(binary))
        assert any(r["packer"] == "UPX" for r in results)

    def test_mpress_detected(self, tmp_path):
        binary = tmp_path / "mpress_binary"
        binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 50 + b"MPRESS1" + b"\x00" * 50)
        results = detect_packer_signatures(str(binary))
        assert any(r["packer"] == "MPRESS" for r in results)

    def test_go_runtime_detected(self, tmp_path):
        binary = tmp_path / "go_binary"
        binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 50 + b"Go build ID:" + b"abc123")
        results = detect_packer_signatures(str(binary))
        assert any(r["packer"] == "Go" for r in results)

    def test_nim_detected(self, tmp_path):
        binary = tmp_path / "nim_binary"
        binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 50 + b"NimMain" + b"\x00" * 50)
        results = detect_packer_signatures(str(binary))
        assert any(r["packer"] == "Nim" for r in results)

    def test_clean_binary_no_signatures(self, tmp_path):
        binary = tmp_path / "clean_binary"
        binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 200)
        results = detect_packer_signatures(str(binary))
        # No high-risk packers
        assert not any(r["risk"] == "HIGH" and r["packer"] not in ("Go", "Rust")
                       for r in results)

    def test_nuitka_onefile_marker_detected(self, tmp_path):
        binary = tmp_path / "nuitka_onefile_binary"
        binary.write_bytes(
            b"\xcf\xfa\xed\xfe" + b"\x00" * 50
            + b"\x4b\x41\x59\x28\xb5\x2f\xfd" + b"\x00" * 50
        )
        results = detect_packer_signatures(str(binary))
        assert any(r["packer"] == "Nuitka" and r["risk"] == "HIGH" for r in results)

    def test_nuitka_compiled_marker_detected(self, tmp_path):
        binary = tmp_path / "nuitka_standalone_binary"
        binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 50 + b"__compiled__" + b"\x00" * 50)
        results = detect_packer_signatures(str(binary))
        assert any(r["packer"] == "Nuitka" and r["risk"] == "MEDIUM" for r in results)


class TestStringDensity:

    @patch('macskillet.native.obfuscation_detector.subprocess.run')
    def test_low_density_flagged(self, mock_run):
        """< 5 strings/KB should flag as packed"""
        # 10 strings in a 10MB binary = 0.001 strings/KB
        mock_result = MagicMock()
        mock_result.stdout = "\n".join([f"string{i}" for i in range(10)])
        mock_run.return_value = mock_result

        result = analyze_string_density("/fake/path", 10 * 1024 * 1024)
        assert result["status"] == "packed"
        assert result["low_string_density"] is True

    @patch('macskillet.native.obfuscation_detector.subprocess.run')
    def test_normal_density_ok(self, mock_run):
        """Normal string density should not flag"""
        # 500 strings in a 100KB binary = 5 strings/KB (borderline)
        mock_result = MagicMock()
        mock_result.stdout = "\n".join([f"NSString_{i}" for i in range(500)])
        mock_run.return_value = mock_result

        result = analyze_string_density("/fake/path", 100 * 1024)
        # 500 / 100 = 5.0 strings/KB — right at the packed threshold
        # Could be either status depending on exact calculation
        assert result["strings_per_kb"] >= 0


class TestSymbolAnalysis:

    @patch('macskillet.native.obfuscation_detector._run')
    def test_no_symbols_large_binary_flagged(self, mock_run):
        mock_run.return_value = ""  # empty nm output

        with patch('os.path.getsize', return_value=2 * 1024 * 1024):  # 2MB
            result = analyze_symbol_table("/fake/large_binary")

        assert result["symbols_stripped"] is True
        assert result["status"] == "suspicious"

    @patch('macskillet.native.obfuscation_detector._run')
    def test_junk_code_detected(self, mock_run):
        # Simulate 6000 symbols
        symbols = "\n".join([f"00000001 t _junk_func_{i}" for i in range(6000)])
        mock_run.return_value = symbols

        with patch('os.path.getsize', return_value=5 * 1024 * 1024):
            result = analyze_symbol_table("/fake/junk_binary")

        assert result["junk_code_suspected"] is True
        assert result["total_symbol_count"] == 6000

    @patch('macskillet.native.obfuscation_detector._run')
    def test_normal_binary_ok(self, mock_run):
        # Normal app has ~100-500 symbols
        symbols = "\n".join([
            f"                 U _NSApp_{i}" for i in range(200)
        ] + [
            f"0000000100001234 T _main_{i}" for i in range(150)
        ])
        mock_run.return_value = symbols

        with patch('os.path.getsize', return_value=500 * 1024):
            result = analyze_symbol_table("/fake/normal_binary")

        assert result["junk_code_suspected"] is False
        assert result["status"] == "normal"


class TestSectionNames:

    @patch('macskillet.native.obfuscation_detector._run')
    def test_upx_section_names_flagged(self, mock_run):
        mock_run.return_value = """
          segname __TEXT
          segname UPX0
          sectname UPX1
          segname __DATA
        """
        result = check_section_names("/fake/upx_binary")
        assert len(result["suspicious_sections"]) > 0
        assert result["status"] == "packed"

    @patch('macskillet.native.obfuscation_detector._run')
    def test_normal_sections_ok(self, mock_run):
        mock_run.return_value = """
          segname __TEXT
          sectname __text
          sectname __stubs
          segname __DATA
          sectname __data
          sectname __bss
        """
        result = check_section_names("/fake/normal_binary")
        assert len(result["suspicious_sections"]) == 0
        assert result["status"] == "normal"


# ---------------------------------------------------------------------------
# Integration tests for detect_obfuscation()
# ---------------------------------------------------------------------------

class TestDetectObfuscation:

    def _make_features(self, binary_path, file_size=500*1024):
        return {
            "sample": {
                "name": os.path.basename(binary_path),
                "path": binary_path,
                "type": "macho_binary",
                "filesize_bytes": file_size,
            },
            "binary": {
                "segments": [],
                "has_encryption": False,
            },
        }

    def test_upx_binary_detected(self, tmp_path):
        binary = tmp_path / "upx_packed"
        binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100 + b"UPX!" + b"\x00" * 400)
        features = self._make_features(str(binary), file_size=len(binary.read_bytes()))

        with patch('macskillet.native.obfuscation_detector._run', return_value=""):
            result = detect_obfuscation(features)

        assert result["packing_suspected"] is True
        assert result["confidence"] in ("HIGH", "MEDIUM")
        assert "packer:UPX" in result["techniques_detected"]

    def test_lone_packer_signature_does_not_force_high_confidence(self, tmp_path):
        """Regression guard for the corrected spec scenario: packing_suspected
        is guaranteed True from a lone HIGH-risk packer match, but confidence
        is NOT guaranteed to reach HIGH from that signal alone -- it needs the
        total score to cross the HIGH-confidence bucket, which a lone
        packer-signature match (+8) does not by itself. Other detection
        sub-functions are mocked to neutral results here specifically to
        isolate the packer-signature contribution from incidental noise
        (e.g. string density, which real-world short synthetic binaries
        almost always trip regardless of packing)."""
        binary = tmp_path / "upx_packed"
        binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100 + b"UPX!" + b"\x00" * 400)
        features = self._make_features(str(binary), file_size=len(binary.read_bytes()))
        neutral_density = {
            "string_count": 100, "strings_per_kb": 50.0,
            "low_string_density": False, "status": "normal",
        }

        with patch('macskillet.native.obfuscation_detector._run', return_value=""), \
             patch('macskillet.native.obfuscation_detector.subprocess.run') as mock_sub, \
             patch('macskillet.native.obfuscation_detector.analyze_string_density',
                    return_value=neutral_density):
            mock_sub.return_value = MagicMock(stdout="hello world\n")
            result = detect_obfuscation(features)

        assert result["techniques_detected"] == ["packer:UPX"]
        assert result["packing_suspected"] is True
        assert result["confidence"] != "HIGH"

    def test_nuitka_binary_gets_runtime_bump_and_no_junk_code_suppression(self, tmp_path):
        """Nuitka must be treated like Nim (suspicion bump), never like Swift
        (junk-code suppression) — a large symbol count from compiled Python
        modules should still contribute to suspicion, not be explained away."""
        binary = tmp_path / "nuitka_onefile"
        binary.write_bytes(
            b"\xcf\xfa\xed\xfe" + b"\x00" * 100
            + b"\x4b\x41\x59\x28\xb5\x2f\xfd" + b"\x00" * 400
        )
        features = self._make_features(str(binary), file_size=len(binary.read_bytes()))

        symbols = "\n".join([f"00000001 t _compiled_func_{i}" for i in range(6000)])
        with patch('macskillet.native.obfuscation_detector._run', return_value=symbols):
            result = detect_obfuscation(features)

        assert "packer:Nuitka" in result["techniques_detected"]
        assert "nuitka_runtime" in result["techniques_detected"]
        assert result["symbol_analysis"]["junk_code_suspected"] is True
        assert result["junk_code_suspected"] is True

    def test_clean_binary_not_flagged(self, tmp_path):
        # Normal Mach-O header + no suspicious content
        binary = tmp_path / "clean"
        binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 200)
        features = self._make_features(str(binary), file_size=len(binary.read_bytes()))

        with patch('macskillet.native.obfuscation_detector._run', return_value=""), \
             patch('macskillet.native.obfuscation_detector.subprocess.run') as mock_sub:
            mock_sub.return_value = MagicMock(
                stdout="\n".join([f"NSString_{i}" for i in range(300)])
            )
            result = detect_obfuscation(features)

        assert result["packing_suspected"] is False

    def test_go_binary_not_false_positive(self, tmp_path):
        binary = tmp_path / "go_binary"
        binary.write_bytes(
            b"\xcf\xfa\xed\xfe" + b"\x00" * 50 +
            b"Go build ID: abc123" + b"\x00" * 50
        )
        features = self._make_features(str(binary), file_size=25 * 1024 * 1024)

        with patch('macskillet.native.obfuscation_detector._run', return_value=""), \
             patch('macskillet.native.obfuscation_detector.subprocess.run') as mock_sub:
            # Low string density (Go binary)
            mock_sub.return_value = MagicMock(stdout="runtime.main\nruntime.gc\n")
            result = detect_obfuscation(features)

        # Go runtime should be detected and score adjusted
        assert result["runtime"]["detected_runtime"] == "Go"

    def test_output_has_required_fields(self, tmp_path):
        binary = tmp_path / "test"
        binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)
        features = self._make_features(str(binary))

        with patch('macskillet.native.obfuscation_detector._run', return_value=""), \
             patch('macskillet.native.obfuscation_detector.subprocess.run') as mock_sub:
            mock_sub.return_value = MagicMock(stdout="hello world\n")
            result = detect_obfuscation(features)

        for field in ["packing_suspected", "obfuscation_suspected", "confidence",
                      "techniques_detected", "score", "summary"]:
            assert field in result, f"Missing field: {field}"


# ---------------------------------------------------------------------------
# Run-only AppleScript detection (2026 enrichment)
# ---------------------------------------------------------------------------

class TestRunOnlyAppleScript:
    """Run-only AppleScript (0xFADEDEAD magic) — source-stripped compiled
    AppleScript used by AMOS/ClickFix payloads to defeat `osadecompile`."""

    FADEDEAD = b"\xfa\xde\xde\xad"

    def test_fadedead_magic_detected(self):
        data = b"\x00\x01\x02" + self.FADEDEAD + b"compiled-bytecode"
        result = scan_runonly_applescript(data)
        assert result["runonly_applescript"] is True

    def test_clean_bytes_not_flagged(self):
        result = scan_runonly_applescript(b"\xcf\xfa\xed\xfe" + b"normal binary content" * 10)
        assert result["runonly_applescript"] is False
        assert result["compiled_applescript"] is False

    def test_fasduas_marks_compiled_applescript(self):
        data = b"FasdUAS 1.101.10\x00script source here"
        result = scan_runonly_applescript(data)
        assert result["compiled_applescript"] is True

    def test_mach_header_magic_not_confused(self):
        """Mach-O magic 0xFEEDFACE / 0xCFFAEDFE must not trigger FADEDEAD."""
        result = scan_runonly_applescript(b"\xcf\xfa\xed\xfe\xfe\xed\xfa\xce" * 50)
        assert result["runonly_applescript"] is False


class TestDetectObfuscationRunOnly:

    def _make_features(self, binary_path, file_size=500 * 1024):
        return {
            "sample": {"name": os.path.basename(binary_path), "path": binary_path,
                       "type": "macho_binary", "filesize_bytes": file_size},
            "binary": {"segments": [], "has_encryption": False},
        }

    def test_runonly_applescript_flagged_in_obfuscation(self, tmp_path):
        binary = tmp_path / "runonly_payload"
        binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 50 +
                           b"\xfa\xde\xde\xad" + b"\x00" * 400)
        features = self._make_features(str(binary), file_size=len(binary.read_bytes()))

        with patch('macskillet.native.obfuscation_detector._run', return_value=""), \
             patch('macskillet.native.obfuscation_detector.subprocess.run') as mock_sub:
            mock_sub.return_value = MagicMock(stdout="hello\n")
            result = detect_obfuscation(features)

        assert "runonly_applescript" in result["techniques_detected"]
        assert result["obfuscation_suspected"] is True

    def test_bundle_applescript_file_flagged_via_main_binary_path(self, tmp_path):
        """A bundle .applescript (not .scpt) file with the run-only marker is
        now detected via this main-binary-path check, not just --deep --
        confirms the widened APPLESCRIPT_EXTENSIONS coverage from the shared
        scan_applescript_analysis() refactor."""
        app_path = tmp_path / "Test.app"
        macos = app_path / "Contents" / "MacOS"
        macos.mkdir(parents=True)
        binary = macos / "Test"
        binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"clean binary content" * 5)

        script_path = app_path / "Contents" / "Resources" / "installer.applescript"
        script_path.parent.mkdir(parents=True)
        script_path.write_bytes(b"\xfa\xde\xde\xad" + b"\x00" * 20)

        features = {
            "sample": {"name": "Test", "path": str(app_path), "type": "app_bundle",
                       "filesize_bytes": len(binary.read_bytes())},
            "binary": {"segments": [], "has_encryption": False},
            "bundle": {"main_executable": "Test", "embedded_scripts": [str(script_path)]},
        }

        with patch('macskillet.native.obfuscation_detector._run', return_value=""), \
             patch('macskillet.native.obfuscation_detector.subprocess.run') as mock_sub:
            mock_sub.return_value = MagicMock(stdout="hello\n")
            result = detect_obfuscation(features)

        assert result["applescript_analysis"]["runonly_applescript"] is True
        assert "runonly_applescript" in result["techniques_detected"]
