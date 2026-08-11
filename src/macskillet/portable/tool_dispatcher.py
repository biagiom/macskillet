#!/usr/bin/env python3
"""
tool_dispatcher.py — Tool implementations for the macOS App Classifier agent.

These tools are called by the agent during its reasoning loop.
Each tool accepts a features dict (from feature_extractor.py) and a query argument,
and returns a structured result the agent can reason about.
"""

import json
import re
from typing import Any


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "get_feature",
        "description": (
            "Retrieve a specific extracted feature from the sample. "
            "Use dot-notation for nested fields, e.g. 'signature.signing_status', "
            "'macho.x86_64.imports', 'bundle.lsui_element'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "feature_path": {
                    "type": "string",
                    "description": "Dot-notation path to feature, e.g. 'signature.signing_status'"
                }
            },
            "required": ["feature_path"]
        }
    },
    {
        "name": "search_strings",
        "description": (
            "Search the extracted strings of interest for a pattern. "
            "Returns all matching strings with their category and risk level."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regex or substring to search for in extracted strings"
                }
            },
            "required": ["pattern"]
        }
    },
    {
        "name": "lookup_api_risk",
        "description": (
            "Look up the risk level and capability description for an imported API symbol. "
            "Returns risk level (CRITICAL/HIGH/MEDIUM/LOW) and notes."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "symbol": {
                    "type": "string",
                    "description": "API symbol name, e.g. 'mach_vm_write', 'dlopen', 'system'"
                }
            },
            "required": ["symbol"]
        }
    },
    {
        "name": "check_entitlement",
        "description": (
            "Check whether a specific entitlement key is present and assess its risk. "
            "Returns whether present, value, and risk assessment."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "key": {
                    "type": "string",
                    "description": "Entitlement key, e.g. 'com.apple.security.app-sandbox'"
                }
            },
            "required": ["key"]
        }
    },
    {
        "name": "get_all_imports",
        "description": (
            "Get all imported symbols grouped by library. "
            "Returns the full import table so you can assess capabilities."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "arch": {
                    "type": "string",
                    "description": "Architecture to query (e.g. 'arm64', 'x86_64'). Use 'all' for all arches.",
                    "default": "all"
                }
            },
            "required": []
        }
    },
    {
        "name": "check_injection_triad",
        "description": (
            "Check for the classic macOS process injection triad: "
            "mach_vm_allocate + mach_vm_write + thread_create_running. "
            "Returns which components are present."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "get_segment_entropy",
        "description": (
            "Get entropy values for all Mach-O segments. "
            "High entropy (>7.0 for __TEXT) suggests packing or obfuscation."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "arch": {
                    "type": "string",
                    "description": "Architecture to query. Use 'all' for all.",
                    "default": "all"
                }
            },
            "required": []
        }
    },
]


# ---------------------------------------------------------------------------
# Inline API risk database (subset — agent can ask about specific symbols)
# ---------------------------------------------------------------------------

API_RISK_DB = {
    "mach_vm_allocate": ("HIGH", "Allocate VM in target process — core injection primitive"),
    "mach_vm_write": ("HIGH", "Write to target process memory — core injection primitive"),
    "mach_vm_protect": ("HIGH", "Change memory permissions — makes injected code executable"),
    "thread_create_running": ("CRITICAL", "Create thread in target — completes injection triad"),
    "task_for_pid": ("HIGH", "Get task port — required for inter-process manipulation"),
    "processor_set_tasks": ("CRITICAL", "Get all task ports — can access all processes"),
    "ptrace": ("HIGH", "Process tracing / anti-debug — used in anti-analysis"),
    "dlopen": ("MEDIUM", "Load dynamic library at runtime — can hide capabilities"),
    "dlsym": ("MEDIUM", "Look up symbol dynamically — can hide API usage"),
    "system": ("HIGH", "Execute shell command — common in droppers/backdoors"),
    "popen": ("HIGH", "Execute shell + capture output"),
    "posix_spawn": ("MEDIUM", "Spawn new process"),
    "fork": ("MEDIUM", "Fork process"),
    "execve": ("MEDIUM", "Execute program"),
    "NSTask": ("MEDIUM", "Objective-C subprocess execution"),
    "NSClassFromString": ("MEDIUM", "Dynamic class lookup — can hide class usage"),
    "NSSelectorFromString": ("MEDIUM", "Dynamic method lookup — can hide method calls"),
    "SecKeychainFindGenericPassword": ("MEDIUM", "Read keychain passwords"),
    "SecKeychainFindInternetPassword": ("MEDIUM", "Read internet passwords"),
    "SecKeychainItemCopyAttributesAndData": ("HIGH", "Dump keychain item data"),
    "SecKeychainSearchCreateFromAttributes": ("HIGH", "Search/harvest entire keychain"),
    "CCCrypt": ("MEDIUM", "Symmetric encryption — check context for ransomware"),
    "SecKeyEncrypt": ("MEDIUM", "Asymmetric encryption"),
    "chmod": ("MEDIUM", "Change file permissions"),
    "chown": ("MEDIUM", "Change file ownership"),
    "chroot": ("HIGH", "Change root filesystem — almost never in apps"),
}

ENTITLEMENT_RISK_DB = {
    "com.apple.security.app-sandbox": ("LOW", "Sandboxed — constrained environment, reduces risk"),
    "get-task-allow": ("HIGH", "Debug entitlement — should NOT be in release apps"),
    "com.apple.system-task-ports": ("CRITICAL", "Can access all process task ports"),
    "com.apple.security.cs.disable-library-validation": ("MEDIUM", "Can load arbitrary dylibs"),
    "com.apple.security.cs.allow-unsigned-executable-memory": ("MEDIUM", "Allows JIT/injection"),
    "com.apple.security.automation.apple-events": ("LOW", "Can send Apple Events to other apps"),
    "com.apple.security.network.client": ("LOW", "Outbound network access"),
    "com.apple.security.network.server": ("MEDIUM", "Can listen for incoming connections"),
    "com.apple.security.files.all": ("HIGH", "Access all files on system"),
    "com.apple.security.personal-information.contacts": ("MEDIUM", "Read contacts"),
    "com.apple.security.personal-information.location": ("MEDIUM", "Location access"),
}


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def _get_nested(d: dict, path: str) -> Any:
    """Navigate dot-notation path in nested dict."""
    parts = path.split(".")
    current = d
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _collect_all_imports(macho_data: dict) -> dict:
    """Flatten imports from all architectures."""
    if not macho_data:
        return {}
    all_imports = {}
    for arch, data in macho_data.items():
        if not isinstance(data, dict):
            continue
        imports = data.get("imports", {})
        if isinstance(imports, dict):
            for lib, symbols in imports.items():
                if lib not in all_imports:
                    all_imports[lib] = []
                if isinstance(symbols, list):
                    all_imports[lib].extend(symbols)
    return all_imports


def tool_get_feature(features: dict, feature_path: str) -> dict:
    value = _get_nested(features, feature_path)
    if value is None:
        return {"found": False, "path": feature_path, "value": None}
    return {"found": True, "path": feature_path, "value": value}


def tool_search_strings(features: dict, pattern: str) -> dict:
    strings = features.get("strings_of_interest", [])
    matches = []
    try:
        regex = re.compile(pattern, re.IGNORECASE)
        for s in strings:
            if isinstance(s, dict) and "value" in s:
                if regex.search(s["value"]):
                    matches.append(s)
    except re.error as e:
        return {"error": f"Invalid regex: {e}", "matches": []}
    return {"pattern": pattern, "match_count": len(matches), "matches": matches[:20]}


def tool_lookup_api_risk(features: dict, symbol: str) -> dict:
    # Check exact match
    if symbol in API_RISK_DB:
        risk, notes = API_RISK_DB[symbol]
        return {"symbol": symbol, "found": True, "risk": risk, "notes": notes}
    # Fuzzy match (symbol might be prefixed with _ or have variant)
    clean = symbol.lstrip("_")
    for key, (risk, notes) in API_RISK_DB.items():
        if clean.lower() in key.lower() or key.lower() in clean.lower():
            return {"symbol": symbol, "found": True, "risk": risk, "notes": notes, "matched_key": key}
    return {
        "symbol": symbol,
        "found": False,
        "risk": "UNKNOWN",
        "notes": "Symbol not in risk database. Consider looking it up manually."
    }


def tool_check_entitlement(features: dict, key: str) -> dict:
    # Check entitlements in machopy output or signature entitlements XML
    macho = features.get("macho", {})
    all_entitlements = {}

    for arch, data in macho.items():
        if not isinstance(data, dict):
            continue
        ent = data.get("signature", {}).get("entitlements_info", {}).get("entitlements", {})
        if isinstance(ent, dict):
            all_entitlements.update(ent)

    # Also check raw entitlements XML from codesign
    ent_xml = features.get("signature", {}).get("entitlements_xml", "")
    if key in ent_xml:
        present = True
        value = True  # Can't easily parse XML here
    else:
        present = key in all_entitlements
        value = all_entitlements.get(key)

    risk, notes = ENTITLEMENT_RISK_DB.get(key, ("UNKNOWN", "Not in entitlement risk database"))

    return {
        "key": key,
        "present": present,
        "value": value,
        "risk": risk,
        "notes": notes,
    }


def tool_get_all_imports(features: dict, arch: str = "all") -> dict:
    macho = features.get("macho", {})
    if not macho:
        return {"error": "No Mach-O data available"}

    if arch == "all":
        imports = _collect_all_imports(macho)
    else:
        arch_data = macho.get(arch, {})
        imports = arch_data.get("imports", {}) if isinstance(arch_data, dict) else {}

    # Compute total symbol count
    total = sum(len(v) for v in imports.values() if isinstance(v, list))
    return {"arch": arch, "total_symbols": total, "by_library": imports}


def tool_check_injection_triad(features: dict) -> dict:
    """Check for mach_vm_allocate + mach_vm_write + thread_create_running."""
    triad = {
        "mach_vm_allocate": False,
        "mach_vm_write": False,
        "thread_create_running": False,
    }
    macho = features.get("macho", {})
    all_imports = _collect_all_imports(macho)

    all_symbols = []
    for symbols in all_imports.values():
        if isinstance(symbols, list):
            all_symbols.extend(str(s).lower() for s in symbols)

    for key in triad:
        triad[key] = any(key.lower() in sym for sym in all_symbols)

    present_count = sum(1 for v in triad.values() if v)
    return {
        "components": triad,
        "present_count": present_count,
        "triad_complete": present_count == 3,
        "verdict": "CRITICAL — full injection triad detected" if present_count == 3
                   else f"{present_count}/3 components present — partial injection capability"
    }


def tool_get_segment_entropy(features: dict, arch: str = "all") -> dict:
    macho = features.get("macho", {})
    if not macho:
        return {"error": "No Mach-O data available"}

    results = {}
    archs_to_check = [arch] if arch != "all" else list(macho.keys())

    for a in archs_to_check:
        arch_data = macho.get(a, {})
        if not isinstance(arch_data, dict):
            continue
        segments = arch_data.get("segments", [])
        if isinstance(segments, list):
            results[a] = [
                {
                    "name": seg.get("segment_name") or seg.get("name", "?"),
                    "entropy": seg.get("entropy"),
                    "size": seg.get("filesize") or seg.get("size"),
                    "high_entropy": (seg.get("entropy") or 0) > 7.0,
                }
                for seg in segments
                if isinstance(seg, dict)
            ]

    return {"arch": arch, "segments": results}


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def dispatch_tool(features: dict, tool_name: str, tool_input: dict) -> dict:
    """Route tool calls from the agent to the correct implementation."""
    dispatch = {
        "get_feature": lambda: tool_get_feature(features, tool_input.get("feature_path", "")),
        "search_strings": lambda: tool_search_strings(features, tool_input.get("pattern", "")),
        "lookup_api_risk": lambda: tool_lookup_api_risk(features, tool_input.get("symbol", "")),
        "check_entitlement": lambda: tool_check_entitlement(features, tool_input.get("key", "")),
        "get_all_imports": lambda: tool_get_all_imports(features, tool_input.get("arch", "all")),
        "check_injection_triad": lambda: tool_check_injection_triad(features),
        "get_segment_entropy": lambda: tool_get_segment_entropy(features, tool_input.get("arch", "all")),
    }

    fn = dispatch.get(tool_name)
    if fn is None:
        return {"error": f"Unknown tool: {tool_name}"}
    try:
        return fn()
    except Exception as e:
        return {"error": f"Tool execution failed: {e}"}
