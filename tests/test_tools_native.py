"""
test_tools_native.py — Unit tests for native/tools.py.

First test coverage for this module (none existed before this change). Focuses
on the fixes/additions from the align-native-portable-agent-tools change:
get_segment_entropy reading the unified entropy analysis, the shared
entitlement/dylib risk tables, and check_injection_triad's shape.

Run from repo root:
    python3 -m pytest tests/test_tools_native.py -v
"""

from macskillet.native.tools import (
    dispatch_tool,
    tool_check_injection_triad,
    tool_get_dylibs,
    tool_get_entitlements,
    tool_get_segment_entropy,
)


class TestGetSegmentEntropy:

    def test_reads_unified_entropy_analysis(self):
        features = {
            "obfuscation": {
                "entropy_analysis": {
                    "segments": [
                        {"name": "__TEXT", "filesize": 1000, "entropy": 4.0, "status": "normal"},
                        {"name": "__DATA_CONST", "filesize": 500, "entropy": 6.6, "status": "suspicious"},
                    ],
                    "packing_suspected_via_entropy": False,
                }
            }
        }
        result = tool_get_segment_entropy(features)
        assert len(result["segments"]) == 2
        assert len(result["high_entropy_segments"]) == 1
        assert result["high_entropy_segments"][0]["name"] == "__DATA_CONST"
        assert result["packing_suspected"] is False

    def test_packed_status_counts_as_high_entropy(self):
        features = {
            "obfuscation": {
                "entropy_analysis": {
                    "segments": [{"name": "__TEXT", "filesize": 1000, "entropy": 7.8, "status": "packed"}],
                    "packing_suspected_via_entropy": True,
                }
            }
        }
        result = tool_get_segment_entropy(features)
        assert result["packing_suspected"] is True
        assert len(result["high_entropy_segments"]) == 1

    def test_no_obfuscation_data_returns_error(self):
        result = tool_get_segment_entropy({})
        assert "error" in result


class TestCheckInjectionTriad:

    def test_complete_triad(self):
        features = {"binary": {"symbols_imported": [
            "_mach_vm_allocate", "_mach_vm_write", "_thread_create_running",
        ]}}
        result = tool_check_injection_triad(features)
        assert result["triad_complete"] is True
        assert result["core_triad_count"] == "3/3"
        assert "CRITICAL" in result["verdict"]

    def test_extra_components_do_not_count_toward_triad(self):
        features = {"binary": {"symbols_imported": [
            "_mach_vm_allocate", "_mach_vm_protect", "_task_for_pid",
        ]}}
        result = tool_check_injection_triad(features)
        assert result["components"]["mach_vm_protect"] is True
        assert result["components"]["task_for_pid"] is True
        assert result["triad_complete"] is False
        assert result["core_triad_count"] == "1/3"

    def test_no_binary_data_returns_error(self):
        result = tool_check_injection_triad({})
        assert "error" in result


class TestGetEntitlements:

    def test_private_entitlement_flagged_once_not_twice(self):
        """Regression test: the shared ENTITLEMENT_RISK_DB no longer has a
        'com.apple.private' entry (removed during reconciliation), since the
        explicit substring check below already flags it -- having both used
        to double-count a private entitlement in risk_flags."""
        features = {"signature": {"entitlements": {
            "com.apple.private.foo": True,
        }}}
        result = tool_get_entitlements(features)
        matches = [f for f in result["risk_flags"] if f["key"] == "com.apple.private.foo"]
        assert len(matches) == 1
        assert matches[0]["risk"] == "HIGH"

    def test_sandboxed_flag(self):
        features = {"signature": {"entitlements": {
            "com.apple.security.app-sandbox": True,
        }}}
        result = tool_get_entitlements(features)
        assert result["sandboxed"] is True

    def test_no_entitlements(self):
        result = tool_get_entitlements({"signature": {"signed": True, "entitlements": {}}})
        assert result["count"] == 0


class TestGetDylibs:

    def test_suspicious_path_flagged(self):
        features = {"binary": {"dylib_dependencies": ["/tmp/evil.dylib"], "rpath_entries": []}}
        result = tool_get_dylibs(features)
        assert result["dylibs"][0]["risk"] == "CRITICAL"
        assert result["suspicious_count"] == 1

    def test_system_library_low_risk(self):
        features = {"binary": {"dylib_dependencies": ["/usr/lib/libSystem.B.dylib"], "rpath_entries": []}}
        result = tool_get_dylibs(features)
        assert result["dylibs"][0]["risk"] == "LOW"

    def test_no_binary_data_returns_error(self):
        result = tool_get_dylibs({})
        assert "error" in result


class TestDispatchTool:

    def test_unknown_tool_returns_error(self):
        result = dispatch_tool({}, "not_a_real_tool", {})
        assert "error" in result

    def test_exception_inside_tool_caught(self):
        # get_symbols with a deliberately invalid regex should be caught by the
        # tool itself and returned as {"error": ...}, not raise out of dispatch_tool.
        features = {"binary": {"symbols_imported": ["_main"], "symbols_exported": []}}
        result = dispatch_tool(features, "get_symbols", {"filter": "("})
        assert "error" in result
