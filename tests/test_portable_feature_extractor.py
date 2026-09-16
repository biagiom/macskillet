"""
test_portable_feature_extractor.py — Unit tests for portable/feature_extractor.py's
new packer-signature detection on the main binary.
"""

import shutil

import pytest


@pytest.mark.integration
def test_portable_extract_populates_packer_signatures_for_bare_binary(tmp_path):
    from macskillet.portable.feature_extractor import extract

    binary_path = tmp_path / "nuitka_like_binary"
    shutil.copy("/bin/ls", binary_path)
    # Append a Nuitka onefile marker after the valid Mach-O structure — the
    # packer-signature scan is a whole-file byte search, independent of the
    # LIEF-based Mach-O parsing that still needs a structurally valid binary.
    with open(binary_path, "ab") as f:
        f.write(b"\x4b\x41\x59\x28\xb5\x2f\xfd")

    features = extract(str(binary_path))
    assert any(m["packer"] == "Nuitka" for m in features["packer_signatures"])


@pytest.mark.integration
def test_portable_extract_no_high_risk_packers_for_clean_binary():
    """/bin/ls legitimately matches the benign LOW-risk LLVM marker (standard
    compiler section, not a packer) — only HIGH-risk packer matches would
    indicate an actual packed/wrapped binary."""
    from macskillet.portable.feature_extractor import extract

    features = extract("/bin/ls")
    assert not any(m["risk"] == "HIGH" for m in features["packer_signatures"])


@pytest.mark.integration
def test_portable_extract_flags_bundle_applescript_without_deep(tmp_path):
    """Run-only AppleScript detection on the main-binary path (not just --deep)
    -- a clean main binary but a bundle .applescript file carrying the
    0xFADEDEAD marker must be caught by plain (non-`--deep`) extract()."""
    from macskillet.portable.feature_extractor import extract

    app_path = tmp_path / "Test.app"
    macos = app_path / "Contents" / "MacOS"
    resources = app_path / "Contents" / "Resources"
    macos.mkdir(parents=True)
    resources.mkdir(parents=True)

    (app_path / "Contents" / "Info.plist").write_text(
        "<?xml version='1.0'?><plist><dict>"
        "<key>CFBundleExecutable</key><string>Test</string>"
        "</dict></plist>"
    )
    shutil.copy("/bin/ls", macos / "Test")

    script_path = resources / "installer.applescript"
    script_path.write_bytes(b"\xfa\xde\xde\xad" + b"\x00" * 20)

    features = extract(str(app_path))

    assert features["applescript_analysis"]["runonly_applescript"] is True


@pytest.mark.integration
def test_portable_extract_populates_obfuscation_field():
    """features["obfuscation"] must be populated (not left absent/empty) on
    the portable pipeline now — closing the bulk of the previously
    acknowledged gap."""
    from macskillet.portable.feature_extractor import extract

    features = extract("/bin/ls")
    assert features["obfuscation"]
    for field in ("packing_suspected", "confidence", "techniques_detected",
                  "entropy_analysis", "symbol_analysis", "section_analysis",
                  "string_density", "runtime", "has_encryption", "score", "summary"):
        assert field in features["obfuscation"], f"Missing field: {field}"


class TestDetectObfuscationPortable:
    """Direct unit tests for detect_obfuscation_portable(features), the LIEF-based
    obfuscation collector — mirrors native's test_obfuscation_detector.py
    coverage for the same shared scoring core. Same single-features-dict
    signature as native's detect_obfuscation(features)."""

    def _arch_data(self, **overrides):
        arch_data = {
            "segments": [{"segment_name": "__TEXT", "filesize": 1000, "entropy": 3.0}],
            "import_count": 50, "export_count": 10, "total_symbol_count": 500,
            "section_names": ["__text", "__data"],
            "symbol_names_sample": ["_main"],
            "has_encryption": False,
        }
        arch_data.update(overrides)
        return arch_data

    def _features(self, macho_result, packer_signatures=None, applescript_analysis=None):
        return {
            "sample": {"type": "macho_binary", "path": "/bin/ls"},
            "macho": macho_result,
            "packer_signatures": packer_signatures or [],
            "applescript_analysis": applescript_analysis or {},
        }

    def test_high_entropy_segment_flags_packing_ratio(self):
        from macskillet.portable.feature_extractor import detect_obfuscation_portable

        macho_result = {"arm64": self._arch_data(
            segments=[{"segment_name": "__TEXT", "filesize": 1000, "entropy": 7.6}],
        )}
        result = detect_obfuscation_portable(self._features(macho_result))
        assert result["entropy_analysis"]["packing_suspected_via_entropy"] is True
        assert result["packing_suspected"] is True

    def test_encryption_flag_detected(self):
        from macskillet.portable.feature_extractor import detect_obfuscation_portable

        macho_result = {"arm64": self._arch_data(has_encryption=True)}
        result = detect_obfuscation_portable(self._features(macho_result))
        assert result["has_encryption"] is True
        assert "lc_encryption_info" in result["techniques_detected"]

    def test_swift_binary_does_not_false_positive_junk_code(self):
        from macskillet.portable.feature_extractor import detect_obfuscation_portable

        macho_result = {"arm64": self._arch_data(
            total_symbol_count=6000,
            section_names=["__swift5_proto"],
            symbol_names_sample=["_$s4main3AppV3runyyF"],
        )}
        result = detect_obfuscation_portable(self._features(macho_result))
        assert result["junk_code_suspected"] is False
        assert "swift_binary" in result["techniques_detected"]

    def test_non_swift_junk_code_still_flagged(self):
        from macskillet.portable.feature_extractor import detect_obfuscation_portable

        macho_result = {"arm64": self._arch_data(total_symbol_count=6000)}
        result = detect_obfuscation_portable(self._features(macho_result))
        assert result["junk_code_suspected"] is True

    def test_malformed_macho_result_returns_empty_scoring_inputs(self):
        from macskillet.portable.feature_extractor import detect_obfuscation_portable

        macho_result = {"error": "parse failed"}
        result = detect_obfuscation_portable(self._features(macho_result))
        assert result["confidence"] in ("NONE", "LOW")
        assert result["entropy_analysis"]["segments"] == []

    def test_unresolvable_binary_path_returns_empty_result(self):
        from macskillet.portable.feature_extractor import detect_obfuscation_portable

        features = {"sample": {"type": "unknown", "path": "/nonexistent"}}
        result = detect_obfuscation_portable(features)
        assert result["confidence"] == "NONE"
        assert result["summary"] == "Could not locate binary for obfuscation analysis"
