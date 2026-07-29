import sys
import os
from unittest.mock import patch, MagicMock



class TestIsSwiftBinary:
    def test_detected_via_swift5_proto_section(self):
        """Returns True when __swift5_proto appears in otool -l output."""
        with patch('macskillet.native.obfuscation_detector._run') as mock_run:
            mock_run.return_value = (
                "segname __TEXT\n"
                "  sectname __text\n"
                "  sectname __swift5_proto\n"
                "segname __DATA\n"
            )
            from macskillet.native.obfuscation_detector import _is_swift_binary
            assert _is_swift_binary("/fake/swift_binary") is True

    def test_detected_via_swift5_types_section(self):
        """Returns True when __swift5_types appears in otool -l output."""
        with patch('macskillet.native.obfuscation_detector._run') as mock_run:
            mock_run.return_value = "sectname __swift5_types\n"
            from macskillet.native.obfuscation_detector import _is_swift_binary
            assert _is_swift_binary("/fake/swift_binary") is True

    def test_detected_via_mangled_nm_symbols(self):
        """Returns True when _$s mangled Swift symbols appear in nm output."""
        def side_effect(cmd, timeout=30):
            if cmd[0] == "otool":
                return "segname __TEXT\nsectname __text\n"   # no Swift sections
            if cmd[0] == "nm":
                return "_$sBoWV\n_$s4main3AppV3runyyF\n_NSApplication\n"
            return ""

        with patch('macskillet.native.obfuscation_detector._run', side_effect=side_effect):
            from macskillet.native.obfuscation_detector import _is_swift_binary
            assert _is_swift_binary("/fake/swift_binary") is True

    def test_plain_objc_binary_returns_false(self):
        """Returns False for a binary with no Swift markers."""
        with patch('macskillet.native.obfuscation_detector._run') as mock_run:
            mock_run.return_value = (
                "segname __TEXT\n  sectname __text\n  sectname __stubs\n"
                "segname __DATA\n  sectname __data\n"
            )
            from macskillet.native.obfuscation_detector import _is_swift_binary
            assert _is_swift_binary("/fake/objc_binary") is False


class TestSwiftNoJunkCodeFalsePositive:
    """Swift binary with >5000 symbols must not trigger junk_code_suspected."""

    def _make_features(self, binary_path: str, file_size: int = 500 * 1024) -> dict:
        return {
            "sample": {
                "name": os.path.basename(binary_path),
                "path": binary_path,
                "type": "macho_binary",
                "filesize_bytes": file_size,
            },
            "binary": {"segments": [], "has_encryption": False},
        }

    def test_swift_binary_junk_code_not_flagged(self, tmp_path):
        """6000 Swift symbols should NOT set junk_code_suspected=True."""
        binary = tmp_path / "MyApp"
        binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 200)
        features = self._make_features(str(binary))

        symbols_6000 = "\n".join(
            [f"0000000100001234 T _$s4main{i:04d}VyF" for i in range(6000)]
        )

        def mock_run_fn(cmd, timeout=30):
            if cmd[0] == "otool" and "-l" in cmd:
                return "sectname __swift5_proto\n"     # triggers Swift detection
            return symbols_6000

        with patch('macskillet.native.obfuscation_detector._run', side_effect=mock_run_fn), \
             patch('macskillet.native.obfuscation_detector.subprocess.run') as mock_sub:
            mock_sub.return_value = MagicMock(
                stdout="\n".join([f"NSString_{i}" for i in range(300)])
            )
            from macskillet.native.obfuscation_detector import detect_obfuscation
            result = detect_obfuscation(features)

        assert result["junk_code_suspected"] is False
        assert "swift_binary" in result["techniques_detected"]
        assert "junk_code_padding" not in result["techniques_detected"]

    def test_non_swift_junk_code_still_flagged(self, tmp_path):
        """6000 symbols in an ObjC binary SHOULD still set junk_code_suspected=True."""
        binary = tmp_path / "malware"
        binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 200)
        features = self._make_features(str(binary))

        symbols_6000 = "\n".join(
            [f"0000000100001234 T _junk_func_{i:04d}" for i in range(6000)]
        )

        def mock_run_fn(cmd, timeout=30):
            if cmd[0] == "otool" and "-l" in cmd:
                return "segname __TEXT\n  sectname __text\n"  # no Swift sections
            return symbols_6000

        with patch('macskillet.native.obfuscation_detector._run', side_effect=mock_run_fn), \
             patch('macskillet.native.obfuscation_detector.subprocess.run') as mock_sub:
            mock_sub.return_value = MagicMock(stdout="hello\nworld\n")
            from macskillet.native.obfuscation_detector import detect_obfuscation
            result = detect_obfuscation(features)

        assert result["junk_code_suspected"] is True
        assert "junk_code_padding" in result["techniques_detected"]
