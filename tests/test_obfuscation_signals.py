"""
test_obfuscation_signals.py — Unit tests for the shared obfuscation-scoring core.

Pure-data tests: every function here takes plain lists/counts, no binary
files or subprocess calls, so both native's and portable's collectors are
covered indirectly by testing the shared math once.

Run from repo root:
    python3 -m pytest tests/test_obfuscation_signals.py -v
"""

from macskillet.common.obfuscation_signals import (
    detect_runtime_markers,
    is_swift_binary,
    score_obfuscation,
    score_section_names,
    score_segment_entropy,
    score_string_density,
    score_symbol_anomalies,
)


class TestScoreSegmentEntropy:

    def test_packed_segment_flagged(self):
        segments = [{"name": "__TEXT", "filesize": 1000, "entropy": 7.6}]
        result = score_segment_entropy(segments)
        assert result["segments"][0]["status"] == "packed"
        assert result["packing_ratio"] == 1.0
        assert result["packing_suspected_via_entropy"] is True

    def test_small_packed_fraction_not_flagged(self):
        segments = [
            {"name": "__TEXT", "filesize": 500, "entropy": 7.6},
            {"name": "__DATA", "filesize": 9500, "entropy": 3.0},
        ]
        result = score_segment_entropy(segments)
        assert result["packing_ratio"] == 0.05
        assert result["packing_suspected_via_entropy"] is False

    def test_unknown_segment_uses_default_thresholds(self):
        segments = [{"name": "__WEIRD", "filesize": 100, "entropy": 7.6}]
        result = score_segment_entropy(segments)
        assert result["segments"][0]["status"] == "packed"

    def test_custom_ratio_threshold(self):
        segments = [
            {"name": "__TEXT", "filesize": 500, "entropy": 7.6},
            {"name": "__DATA", "filesize": 9500, "entropy": 3.0},
        ]
        result = score_segment_entropy(segments, ratio_threshold=0.01)
        assert result["packing_suspected_via_entropy"] is True

    def test_zero_filesize_segment_skipped(self):
        segments = [{"name": "__TEXT", "filesize": 0, "entropy": 8.0}]
        result = score_segment_entropy(segments)
        assert result["segments"] == []
        assert result["packing_ratio"] == 0.0


class TestScoreStringDensity:

    def test_low_density_flagged_packed(self):
        result = score_string_density(string_count=2, file_size_bytes=10240)
        assert result["status"] == "packed"
        assert result["low_string_density"] is True

    def test_normal_density(self):
        result = score_string_density(string_count=500, file_size_bytes=10240)
        assert result["status"] == "normal"

    def test_zero_file_size_returns_default(self):
        result = score_string_density(string_count=10, file_size_bytes=0)
        assert result["status"] == "normal"
        assert result["strings_per_kb"] == 0.0


class TestScoreSymbolAnomalies:

    def test_stripped_symbol_table(self):
        result = score_symbol_anomalies(
            import_count=0, export_count=0, total_symbol_count=0, file_size_bytes=600_000,
        )
        assert result["symbols_stripped"] is True

    def test_suspiciously_few_imports(self):
        result = score_symbol_anomalies(
            import_count=1, export_count=0, total_symbol_count=50, file_size_bytes=300_000,
        )
        assert result["suspiciously_few_imports"] is True

    def test_junk_code_suspected(self):
        result = score_symbol_anomalies(
            import_count=10, export_count=5, total_symbol_count=6000, file_size_bytes=1_000_000,
        )
        assert result["junk_code_suspected"] is True

    def test_normal_binary_no_flags(self):
        result = score_symbol_anomalies(
            import_count=50, export_count=10, total_symbol_count=500, file_size_bytes=300_000,
        )
        assert result["symbols_stripped"] is False
        assert result["suspiciously_few_imports"] is False
        assert result["junk_code_suspected"] is False


class TestScoreSectionNames:

    def test_known_packer_section_flagged(self):
        result = score_section_names(["__TEXT", "UPX0", "__DATA"])
        assert result["status"] == "packed"
        assert any(s["name"] == "UPX0" for s in result["suspicious_sections"])

    def test_clean_sections_no_flags(self):
        result = score_section_names(["__TEXT", "__DATA", "__LINKEDIT"])
        assert result["suspicious_sections"] == []
        assert result["status"] == "normal"


class TestDetectRuntimeMarkers:

    def test_packer_signature_wins_over_substring_search(self):
        result = detect_runtime_markers(
            text_sample="Go build ID: abc", packer_signatures=[
                {"packer": "Nuitka", "detail": "Nuitka onefile marker", "risk": "MEDIUM"},
            ],
        )
        assert result["detected_runtime"] == "Nuitka"

    def test_nim_detected_via_substring(self):
        result = detect_runtime_markers(text_sample="...NimMain...", packer_signatures=[])
        assert result["detected_runtime"] == "Nim"

    def test_go_detected_via_build_id(self):
        result = detect_runtime_markers(text_sample="Go build ID: xyz", packer_signatures=[])
        assert result["detected_runtime"] == "Go"

    def test_rust_detected_via_marker(self):
        result = detect_runtime_markers(text_sample="__rustc_debug_gdb", packer_signatures=[])
        assert result["detected_runtime"] == "Rust"

    def test_no_runtime_detected(self):
        result = detect_runtime_markers(text_sample="plain text", packer_signatures=[])
        assert result["detected_runtime"] is None

    def test_large_binary_flag(self):
        result = detect_runtime_markers(
            text_sample="", packer_signatures=[], file_size_bytes=25 * 1024 * 1024,
        )
        assert result["is_large_binary"] is True


class TestIsSwiftBinary:

    def test_swift_section_name(self):
        assert is_swift_binary(["__swift5_proto"], []) is True

    def test_swift_mangled_symbol(self):
        assert is_swift_binary([], ["_$s10Foundation4DataV"]) is True

    def test_non_swift(self):
        assert is_swift_binary(["__TEXT"], ["_main"]) is False

    def test_swift_symbol_beyond_sample_window_not_detected(self):
        symbols = ["_normal"] * 200 + ["_$sSwiftMarker"]
        assert is_swift_binary([], symbols) is False


class TestScoreObfuscation:

    def _score(self, **overrides):
        """Build pre-scored sub-results (as a real collector would, via this
        module's own scoring functions) with normal/clean defaults, then call
        score_obfuscation() with any overridden sub-result."""
        defaults = dict(
            entropy_analysis=score_segment_entropy([]),
            string_density=score_string_density(5000, 300_000),
            symbol_analysis=score_symbol_anomalies(50, 10, 500, 300_000),
            section_analysis=score_section_names([]),
            runtime=detect_runtime_markers("", []),
            is_swift=False,
            has_encryption=False,
            packer_signatures=[],
            applescript_analysis={},
        )
        defaults.update(overrides)
        return score_obfuscation(**defaults)

    def test_clean_binary_no_confidence(self):
        result = self._score()
        assert result["confidence"] == "NONE"
        assert result["packing_suspected"] is False

    def test_lone_high_risk_packer_signature_does_not_force_high_confidence(self):
        packer_signatures = [{"packer": "UPX", "risk": "HIGH", "detail": "UPX magic"}]
        result = self._score(
            packer_signatures=packer_signatures,
            runtime=detect_runtime_markers("", packer_signatures),
        )
        assert result["techniques_detected"] == ["packer:UPX"]
        assert result["packing_suspected"] is True
        assert result["confidence"] != "HIGH"

    def test_runonly_applescript_contributes_to_score_and_confidence(self):
        result = self._score(
            applescript_analysis={"runonly_applescript": True, "compiled_applescript": False},
        )
        assert "runonly_applescript" in result["techniques_detected"]
        assert result["obfuscation_suspected"] is True

    def test_encryption_flag_recorded(self):
        result = self._score(has_encryption=True)
        assert result["has_encryption"] is True
        assert "lc_encryption_info" in result["techniques_detected"]

    def test_swift_suppresses_junk_code_heuristic(self):
        result = self._score(
            symbol_analysis=score_symbol_anomalies(50, 10, 6000, 300_000),
            is_swift=True,
        )
        assert result["junk_code_suspected"] is False
        assert "swift_binary" in result["techniques_detected"]

    def test_non_swift_junk_code_flagged(self):
        result = self._score(symbol_analysis=score_symbol_anomalies(50, 10, 6000, 300_000))
        assert result["junk_code_suspected"] is True

    def test_go_runtime_reduces_entropy_score(self):
        segments = [{"name": "__TEXT", "filesize": 1000, "entropy": 7.6}]
        result = self._score(
            entropy_analysis=score_segment_entropy(segments),
            runtime=detect_runtime_markers("Go build ID: abc", []),
        )
        assert result["runtime"]["detected_runtime"] == "Go"
        # entropy contributes 5, then Go reduces it by 3 -> net 2
        assert result["score"] == 2

    def test_nuitka_runtime_increases_score_and_no_symbol_suppression(self):
        packer_signatures = [{"packer": "Nuitka", "risk": "MEDIUM", "detail": "onefile marker"}]
        result = self._score(
            symbol_analysis=score_symbol_anomalies(50, 10, 6000, 300_000),
            packer_signatures=packer_signatures,
            runtime=detect_runtime_markers("", packer_signatures),
        )
        assert result["runtime"]["detected_runtime"] == "Nuitka"
        assert result["junk_code_suspected"] is True
        assert "nuitka_runtime" in result["techniques_detected"]

    def test_high_confidence_when_score_threshold_reached(self):
        packer_signatures = [{"packer": "UPX", "risk": "HIGH", "detail": "UPX magic"}]
        segments = [{"name": "__TEXT", "filesize": 1000, "entropy": 7.6}]
        result = self._score(
            packer_signatures=packer_signatures,
            entropy_analysis=score_segment_entropy(segments),
            runtime=detect_runtime_markers("", packer_signatures),
        )
        assert result["score"] >= 12
        assert result["confidence"] == "HIGH"
        assert result["packing_suspected"] is True
