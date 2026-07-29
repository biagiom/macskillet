#!/usr/bin/env python3
"""
tools_native.py — Agent tool implementations backed entirely by macOS native tools.

Each tool wraps codesign / otool / nm / lipo / strings / xattr / mdls / spctl.
No third-party libraries required.
"""

import json
import re
import subprocess
from typing import Any


# ---------------------------------------------------------------------------
# Tool schema for Claude API
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "get_signature_info",
        "description": (
            "Get full code signature information using codesign and spctl. "
            "Returns signing status, team ID, authority chain, notarization, "
            "Gatekeeper verdict, hardened runtime flag, and flags."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "get_entitlements",
        "description": (
            "Extract and assess entitlements using codesign. "
            "Returns all entitlement key-value pairs with risk assessment for each."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "get_dylibs",
        "description": (
            "Get dynamic library dependencies using otool -L. "
            "Returns dylib paths with risk assessment (suspicious paths flagged)."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "get_load_commands",
        "description": "Get the list of Mach-O load commands using otool -l.",
        "input_schema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "get_symbols",
        "description": (
            "Get imported and exported symbols using nm. "
            "Also checks for high-risk symbols (injection, credential theft, shell execution)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "filter": {
                    "type": "string",
                    "description": "Optional regex filter to narrow results",
                }
            },
            "required": []
        }
    },
    {
        "name": "get_objc_info",
        "description": (
            "Extract Objective-C class names and method names using otool. "
            "Very useful — ObjC names are often not stripped and reveal behavior directly."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "get_segment_entropy",
        "description": (
            "Get entropy values for each Mach-O segment. "
            "High entropy (>7.0) in __TEXT suggests packing or obfuscation."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "get_strings",
        "description": (
            "Search extracted strings for a pattern using the strings tool. "
            "Returns matching strings with category labels."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regex or substring to search for"
                }
            },
            "required": ["pattern"]
        }
    },
    {
        "name": "get_xattr",
        "description": (
            "Get extended attributes (xattr) including quarantine flag and download origin. "
            "Critical for understanding if Gatekeeper was bypassed."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "get_bundle_info",
        "description": (
            "Get Info.plist fields and bundle structure details. "
            "Checks for LSUIElement, LSBackgroundOnly, persistence directories, "
            "embedded scripts, and interesting plist keys."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "check_injection_triad",
        "description": (
            "Check for the macOS process injection triad using nm: "
            "mach_vm_allocate + mach_vm_write + thread_create_running. "
            "Also checks for task_for_pid and mach_vm_protect."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "get_lipo_info",
        "description": "Get architecture information for FAT/Universal binaries using lipo.",
        "input_schema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "lookup_api_risk",
        "description": (
            "Look up the risk level and capability description for a specific API symbol. "
            "Returns CRITICAL/HIGH/MEDIUM/LOW risk with explanation."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "symbol": {
                    "type": "string",
                    "description": "Symbol name, e.g. 'mach_vm_write', 'dlopen'"
                }
            },
            "required": ["symbol"]
        }
    },
]


# ---------------------------------------------------------------------------
# Inline API risk DB (same as detector/tools.py)
# ---------------------------------------------------------------------------

API_RISK_DB = {
    "mach_vm_allocate": ("HIGH", "Allocate VM in target process — injection primitive"),
    "mach_vm_write": ("HIGH", "Write to target process memory — injection primitive"),
    "mach_vm_protect": ("HIGH", "Change memory permissions — makes injected code executable"),
    "thread_create_running": ("CRITICAL", "Create thread in target — completes injection triad"),
    "task_for_pid": ("HIGH", "Get task port for inter-process manipulation"),
    "processor_set_tasks": ("CRITICAL", "Get all task ports — access all processes"),
    "ptrace": ("HIGH", "Anti-debugging via PT_DENY_ATTACH"),
    "dlopen": ("MEDIUM", "Load dynamic library at runtime — hides capabilities"),
    "dlsym": ("MEDIUM", "Dynamic symbol lookup — hides API usage"),
    "system": ("HIGH", "Shell command execution"),
    "popen": ("HIGH", "Shell execution + output capture"),
    "posix_spawn": ("MEDIUM", "Process spawning"),
    "fork": ("MEDIUM", "Fork process"),
    "execve": ("MEDIUM", "Execute program"),
    "SecKeychainFindGenericPassword": ("MEDIUM", "Read keychain passwords"),
    "SecKeychainFindInternetPassword": ("MEDIUM", "Read internet passwords"),
    "SecKeychainItemCopyAttributesAndData": ("HIGH", "Dump full keychain item"),
    "SecKeychainSearchCreateFromAttributes": ("HIGH", "Enumerate/harvest keychain"),
    "CCCrypt": ("MEDIUM", "Symmetric encryption — check for ransomware context"),
    "NSClassFromString": ("MEDIUM", "Dynamic ObjC class lookup — hides class usage"),
    "NSSelectorFromString": ("MEDIUM", "Dynamic method lookup — hides method calls"),
    "chmod": ("MEDIUM", "Change file permissions"),
    "chroot": ("HIGH", "Change root filesystem"),
}

ENTITLEMENT_RISK_DB = {
    "com.apple.security.app-sandbox": ("LOW", "Sandboxed app — restricted"),
    "get-task-allow": ("HIGH", "Debug entitlement in release app"),
    "com.apple.system-task-ports": ("CRITICAL", "Access to all process task ports"),
    "com.apple.security.cs.disable-library-validation": ("MEDIUM", "Can load unsigned dylibs"),
    "com.apple.security.cs.allow-unsigned-executable-memory": ("MEDIUM", "JIT or injection"),
    "com.apple.security.automation.apple-events": ("LOW", "Can send Apple Events"),
    "com.apple.security.network.server": ("MEDIUM", "Can listen for connections"),
    "com.apple.security.files.all": ("HIGH", "Full filesystem access"),
    "com.apple.private": ("HIGH", "Private Apple entitlement — not for 3rd parties"),
}

SUSPICIOUS_DYLIB_PATTERNS = [
    (r"^/tmp/", "CRITICAL", "Loads from /tmp/ — staging path"),
    (r"^/var/folders/", "HIGH", "Loads from temp folder"),
    (r"~/", "HIGH", "Loads from user home (unusual for distribution)"),
    (r"@executable_path/\.", "MEDIUM", "Loads from executable dir (check for hijacking)"),
    (r"(inject|hook|patch|swizzle)", "HIGH", "Dylib name suggests hooking/injection"),
    (r"[a-z]{8,}\.(dylib|framework)", "MEDIUM", "Random-looking dylib name"),
]


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def tool_get_signature_info(features: dict) -> dict:
    sig = features.get("signature", {})
    if not sig:
        return {"error": "No signature data available"}
    out = {
        "signed": sig.get("signed"),
        "signing_status": sig.get("signing_status"),
        "detail": sig.get("signing_status_detail"),
        "hardened_runtime": sig.get("hardened_runtime"),
        "team_id": sig.get("team_id"),
        "identifier": sig.get("identifier"),
        "authority_chain": sig.get("authority_chain", []),
        "notarized": sig.get("notarized"),
        "stapled": sig.get("stapled"),
        "gatekeeper_verdict": sig.get("gatekeeper_verdict", "")[:200],
        "gatekeeper_source": sig.get("gatekeeper_source"),
        "flags": sig.get("flags_raw"),
        "verify_output": sig.get("codesign_verify_output", "")[:300],
    }
    # "notarized != safe": surface the deterministic trust assessment so the
    # agent does not over-trust a signed/notarized sample that behaves badly.
    trust = features.get("signature_trust")
    if trust:
        out["trust_assessment"] = {
            "trust_level": trust.get("trust_level"),
            "risk_adjustment": trust.get("adjustment"),
            "credit_revoked": trust.get("override_applied"),
            "reasons": trust.get("reasons", []),
        }
    return out


def tool_get_entitlements(features: dict) -> dict:
    sig = features.get("signature", {})
    if not sig:
        return {"error": "No signature data"}
    ents = sig.get("entitlements", {})
    if not ents:
        return {"count": 0, "entitlements": {}, "risk_flags": []}

    risk_flags = []
    for key, value in ents.items():
        for risk_key, (risk, note) in ENTITLEMENT_RISK_DB.items():
            if risk_key in key:
                risk_flags.append({"key": key, "value": value, "risk": risk, "note": note})
                break
        # Check for any private entitlement
        if "com.apple.private" in key:
            risk_flags.append({
                "key": key, "value": value, "risk": "HIGH",
                "note": "Private Apple entitlement not meant for 3rd-party apps"
            })

    return {
        "count": len(ents),
        "entitlements": ents,
        "risk_flags": risk_flags,
        "sandboxed": ents.get("com.apple.security.app-sandbox", False),
        "has_private_entitlements": any("com.apple.private" in k for k in ents),
    }


def tool_get_dylibs(features: dict) -> dict:
    binary = features.get("binary", {})
    if not binary:
        return {"error": "No binary data"}
    dylibs = binary.get("dylib_dependencies", [])
    rpaths = binary.get("rpath_entries", [])

    assessed = []
    for dylib in dylibs:
        risk = "LOW"
        note = "System library"
        if dylib.startswith("/usr/lib/") or dylib.startswith("/System/"):
            risk, note = "LOW", "Apple system library"
        elif dylib.startswith("@executable_path/../Frameworks"):
            risk, note = "LOW", "Embedded framework (normal)"
        elif dylib.startswith("@executable_path") or dylib.startswith("@loader_path"):
            risk, note = "LOW", "Relative path (normal for embedded frameworks)"
        else:
            for pattern, r, n in SUSPICIOUS_DYLIB_PATTERNS:
                if re.search(pattern, dylib, re.IGNORECASE):
                    risk, note = r, n
                    break
            else:
                risk, note = "MEDIUM", "Non-standard dylib path"

        assessed.append({"path": dylib, "risk": risk, "note": note})

    return {
        "count": len(dylibs),
        "dylibs": assessed,
        "rpath_entries": rpaths,
        "suspicious_count": sum(1 for d in assessed if d["risk"] in ("HIGH", "CRITICAL")),
    }


def tool_get_load_commands(features: dict) -> dict:
    binary = features.get("binary", {})
    if not binary:
        return {"error": "No binary data"}
    cmds = binary.get("load_commands", [])
    interesting = [c for c in cmds if any(x in c for x in [
        "DYLIB", "RPATH", "CODE_SIG", "ENCRYPT", "MAIN", "THREAD",
        "DYLD", "SEGMENT", "SYMTAB", "DYSYMTAB"
    ])]
    return {
        "all_commands": cmds,
        "interesting_commands": interesting,
        "has_code_signature": "LC_CODE_SIGNATURE" in cmds,
        "has_encryption": any("ENCRYPT" in c for c in cmds),
        "dyld_info_type": next((c for c in cmds if "DYLD_INFO" in c or "CHAINED" in c), None),
    }


def tool_get_symbols(features: dict, filter_pattern: str = None) -> dict:
    binary = features.get("binary", {})
    if not binary:
        return {"error": "No binary data"}

    imports = binary.get("symbols_imported", [])
    exports = binary.get("symbols_exported", [])
    high_risk = binary.get("high_risk_symbols", [])

    if filter_pattern:
        try:
            regex = re.compile(filter_pattern, re.IGNORECASE)
            imports = [s for s in imports if regex.search(s)]
            exports = [s for s in exports if regex.search(s)]
        except re.error:
            return {"error": f"Invalid regex: {filter_pattern}"}

    return {
        "import_count": len(imports),
        "export_count": len(exports),
        "imports_sample": imports[:50],
        "exports_sample": exports[:50],
        "high_risk_symbols": high_risk,
        "has_dlopen": any("dlopen" in s for s in imports),
        "has_dlsym": any("dlsym" in s for s in imports),
        "has_shell_exec": any(s.lstrip("_") in ("system", "popen") for s in imports),
    }


def tool_get_objc_info(features: dict) -> dict:
    binary = features.get("binary", {})
    if not binary:
        return {"error": "No binary data"}
    classes = binary.get("objc_classes", [])
    methods = binary.get("objc_methods", [])
    suspicious_classes = [c for c in classes if any(
        x in c.lower() for x in ["inject", "hook", "swizzle", "steal", "exfil", "keylog", "screen"]
    )]
    suspicious_methods = [m for m in methods if any(
        x in m.lower() for x in ["inject", "hook", "steal", "keychain", "password", "exfil", "upload"]
    )]
    return {
        "class_count": len(classes),
        "method_count": len(methods),
        "classes": classes[:50],
        "methods_sample": methods[:50],
        "suspicious_classes": suspicious_classes,
        "suspicious_methods": suspicious_methods,
    }


def tool_get_segment_entropy(features: dict) -> dict:
    binary = features.get("binary", {})
    if not binary:
        return {"error": "No binary data"}
    segments = binary.get("segments", [])
    high_entropy = [s for s in segments if s.get("high_entropy")]
    return {
        "segments": segments,
        "high_entropy_segments": high_entropy,
        "packing_suspected": len(high_entropy) > 0,
    }


def tool_get_strings(features: dict, pattern: str) -> dict:
    strings = features.get("binary", {}).get("strings_of_interest", [])
    try:
        regex = re.compile(pattern, re.IGNORECASE)
        matches = [s for s in strings if isinstance(s, dict) and regex.search(s.get("value", ""))]
    except re.error:
        return {"error": f"Invalid regex: {pattern}"}
    return {"pattern": pattern, "match_count": len(matches), "matches": matches[:20]}


def tool_get_xattr(features: dict) -> dict:
    pf = features.get("preflight", {})
    if not pf:
        return {"error": "No preflight data"}
    return {
        "has_quarantine": pf.get("has_quarantine"),
        "quarantine_xattr": pf.get("quarantine_xattr"),
        "quarantine_bypassed": pf.get("quarantine_bypassed"),
        "download_origin_urls": pf.get("download_origin_urls", []),
        "downloaded_date": pf.get("downloaded_date"),
        "all_xattrs": pf.get("all_xattrs", []),
        "spotlight_metadata": pf.get("spotlight_metadata", {}),
        "risk_note": (
            "CRITICAL: No quarantine xattr — arrived without Gatekeeper check (USB/script/archive)"
            if not pf.get("has_quarantine")
            else "Quarantine present — was subject to Gatekeeper check"
        )
    }


def tool_get_bundle_info(features: dict) -> dict:
    bundle = features.get("bundle", {})
    if not bundle:
        return {"error": "No bundle data (may be a bare binary, not an .app)"}
    return {
        "bundle_id": bundle.get("bundle_id"),
        "version": bundle.get("bundle_version"),
        "main_executable": bundle.get("main_executable"),
        "lsui_element": bundle.get("lsui_element"),
        "ls_background_only": bundle.get("ls_background_only"),
        "has_launch_agent": bundle.get("has_launch_agent"),
        "has_launch_daemon": bundle.get("has_launch_daemon"),
        "has_login_items": bundle.get("has_login_items"),
        "embedded_scripts": bundle.get("embedded_scripts", []),
        "hidden_files": bundle.get("hidden_files", []),
        "binary_count": len(bundle.get("all_binaries", [])),
        "interesting_plist_keys": bundle.get("info_plist_keys", {}),
        "all_plists": bundle.get("all_plists", []),
    }


def tool_check_injection_triad(features: dict) -> dict:
    binary = features.get("binary", {})
    if not binary:
        return {"error": "No binary data"}
    imports = binary.get("symbols_imported", [])
    all_syms = " ".join(imports).lower()

    components = {
        "mach_vm_allocate": "mach_vm_allocate" in all_syms,
        "mach_vm_write": "mach_vm_write" in all_syms,
        "mach_vm_protect": "mach_vm_protect" in all_syms,
        "thread_create_running": "thread_create_running" in all_syms,
        "task_for_pid": "task_for_pid" in all_syms,
    }
    core_triad_count = sum([
        components["mach_vm_allocate"],
        components["mach_vm_write"],
        components["thread_create_running"],
    ])
    return {
        "components": components,
        "core_triad_count": f"{core_triad_count}/3",
        "triad_complete": core_triad_count == 3,
        "verdict": (
            "CRITICAL — Complete injection triad detected" if core_triad_count == 3
            else f"{core_triad_count}/3 core injection components — partial capability"
        )
    }


def tool_get_lipo_info(features: dict) -> dict:
    binary = features.get("binary", {})
    if not binary:
        return {"error": "No binary data"}
    return {
        "is_fat": binary.get("is_fat"),
        "architectures": binary.get("architectures", []),
        "arch_count": len(binary.get("architectures", [])),
        "note": (
            "Universal binary (x86_64 + arm64) — normal for modern macOS apps"
            if "x86_64" in binary.get("architectures", []) and "arm64" in binary.get("architectures", [])
            else "Single architecture binary"
        )
    }


def tool_lookup_api_risk(features: dict, symbol: str) -> dict:
    clean = symbol.lstrip("_")
    if clean in API_RISK_DB:
        risk, note = API_RISK_DB[clean]
        return {"symbol": symbol, "found": True, "risk": risk, "notes": note}
    for key, (risk, note) in API_RISK_DB.items():
        if clean.lower() in key.lower() or key.lower() in clean.lower():
            return {"symbol": symbol, "found": True, "risk": risk, "notes": note, "matched_key": key}
    return {"symbol": symbol, "found": False, "risk": "UNKNOWN", "notes": "Not in risk database"}


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def dispatch_tool(features: dict, tool_name: str, tool_input: dict) -> dict:
    dispatch = {
        "get_signature_info": lambda: tool_get_signature_info(features),
        "get_entitlements": lambda: tool_get_entitlements(features),
        "get_dylibs": lambda: tool_get_dylibs(features),
        "get_load_commands": lambda: tool_get_load_commands(features),
        "get_symbols": lambda: tool_get_symbols(features, tool_input.get("filter")),
        "get_objc_info": lambda: tool_get_objc_info(features),
        "get_segment_entropy": lambda: tool_get_segment_entropy(features),
        "get_strings": lambda: tool_get_strings(features, tool_input.get("pattern", ".")),
        "get_xattr": lambda: tool_get_xattr(features),
        "get_bundle_info": lambda: tool_get_bundle_info(features),
        "check_injection_triad": lambda: tool_check_injection_triad(features),
        "get_lipo_info": lambda: tool_get_lipo_info(features),
        "lookup_api_risk": lambda: tool_lookup_api_risk(features, tool_input.get("symbol", "")),
    }
    fn = dispatch.get(tool_name)
    if fn is None:
        return {"error": f"Unknown tool: {tool_name}"}
    try:
        return fn()
    except Exception as e:
        return {"error": f"Tool failed: {e}"}
