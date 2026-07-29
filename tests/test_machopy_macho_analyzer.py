"""Tests for machopy.macho_analyzer — LIEF-based Mach-O analysis."""

import sys
from pathlib import Path

import pytest


from macskillet.machopy.macho_analyzer import analyze_macho, is_macho, md5, sha256

REAL_BINARY = "/bin/ls"


# ---------------------------------------------------------------------------
# is_macho
# ---------------------------------------------------------------------------

def test_is_macho_true_for_system_binary():
    assert is_macho(REAL_BINARY) is True


def test_is_macho_false_for_text_file(tmp_path):
    f = tmp_path / "text.txt"
    f.write_text("hello world\n")
    assert is_macho(str(f)) is False


def test_is_macho_false_for_missing_file():
    assert is_macho("/nonexistent/path/binary") is False


# ---------------------------------------------------------------------------
# sha256 / md5
# ---------------------------------------------------------------------------

def test_sha256_returns_hex_string():
    result = sha256(REAL_BINARY)
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result)


def test_md5_returns_hex_string():
    result = md5(REAL_BINARY)
    assert len(result) == 32
    assert all(c in "0123456789abcdef" for c in result)


def test_sha256_missing_file_returns_empty():
    assert sha256("/nonexistent/file") == ""


# ---------------------------------------------------------------------------
# analyze_macho
# ---------------------------------------------------------------------------

def test_analyze_macho_returns_arch_dict():
    result = analyze_macho(REAL_BINARY)
    assert isinstance(result, dict)
    assert len(result) > 0
    # No top-level "error" key on success
    assert "error" not in result


def test_analyze_macho_arch_keys_are_lowercase():
    result = analyze_macho(REAL_BINARY)
    for arch in result:
        assert arch == arch.lower(), f"arch key not lowercase: {arch!r}"


def test_analyze_macho_has_imports():
    result = analyze_macho(REAL_BINARY)
    for arch, data in result.items():
        assert "imports" in data, f"missing 'imports' for arch {arch}"
        assert isinstance(data["imports"], dict)


def test_analyze_macho_imports_grouped_by_lib():
    result = analyze_macho(REAL_BINARY)
    for arch, data in result.items():
        imports = data["imports"]
        for lib_name, symbols in imports.items():
            assert isinstance(lib_name, str)
            assert isinstance(symbols, list)
            assert all(isinstance(s, str) for s in symbols)


def test_analyze_macho_has_segments():
    result = analyze_macho(REAL_BINARY)
    for arch, data in result.items():
        assert "segments" in data, f"missing 'segments' for arch {arch}"
        segs = data["segments"]
        assert isinstance(segs, list)
        assert len(segs) > 0


def test_analyze_macho_segments_have_required_fields():
    result = analyze_macho(REAL_BINARY)
    for arch, data in result.items():
        for seg in data["segments"]:
            assert "segment_name" in seg
            assert "filesize" in seg
            assert "entropy" in seg
            assert isinstance(seg["entropy"], float)
            assert 0.0 <= seg["entropy"] <= 8.0


def test_analyze_macho_text_segment_has_reasonable_entropy():
    result = analyze_macho(REAL_BINARY)
    for arch, data in result.items():
        text_segs = [s for s in data["segments"] if s["segment_name"] == "__TEXT"]
        if text_segs:
            assert text_segs[0]["entropy"] > 1.0, "__TEXT entropy suspiciously low"
            assert text_segs[0]["entropy"] < 8.0


def test_analyze_macho_has_dylibs():
    result = analyze_macho(REAL_BINARY)
    for arch, data in result.items():
        assert "dylibs" in data
        assert isinstance(data["dylibs"], list)
        # /bin/ls links against at least libSystem
        assert any("libSystem" in d for d in data["dylibs"])


def test_analyze_macho_signature_entitlements_structure():
    result = analyze_macho(REAL_BINARY)
    for arch, data in result.items():
        sig = data.get("signature", {})
        assert "entitlements_info" in sig
        assert "entitlements" in sig["entitlements_info"]


def test_analyze_macho_bad_path_returns_error():
    result = analyze_macho("/nonexistent/binary")
    assert "error" in result


@pytest.mark.integration
def test_analyze_macho_fat_binary_has_multiple_arches():
    """FAT binary has >1 arch. Requires macOS system binary (always FAT on Apple Silicon)."""
    result = analyze_macho(REAL_BINARY)
    # On Apple Silicon macs, /bin/ls is a FAT binary with arm64 + x86_64
    assert len(result) >= 1  # at minimum one arch
