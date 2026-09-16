#!/usr/bin/env python3
"""
tools.py — Tool implementations for the macOS App Classifier agent.

These tools are called by the agent during its reasoning loop.
Each tool accepts a features dict (from feature_extractor.py) and a query argument,
and returns a structured result the agent can reason about.
"""

import json
import re
from typing import Any

from macskillet.common.obfuscation_signals import score_segment_entropy
from macskillet.common.tool_risk_tables import ENTITLEMENT_RISK_DB, SUSPICIOUS_DYLIB_PATTERNS


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
        "name": "get_strings",
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
        "name": "get_dylibs",
        "description": (
            "Get all linked dynamic libraries with a per-path risk assessment "
            "(staging paths, hijack-prone relative paths, hooking/injection-suggestive names)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "get_entitlements",
        "description": (
            "Get the full entitlements dict with a substring-matched risk assessment. "
            "Returns risk_flags, sandboxed status, and whether any private Apple "
            "entitlements are present."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
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
            "Get entropy values for all Mach-O segments, classified against a "
            "per-segment-type threshold table. High-entropy segments suggest packing."
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


def tool_get_strings(features: dict, pattern: str) -> dict:
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


def _collect_all_entitlements(macho: dict) -> dict:
    all_entitlements = {}
    for arch, data in macho.items():
        if not isinstance(data, dict):
            continue
        ent = data.get("signature", {}).get("entitlements_info", {}).get("entitlements", {})
        if isinstance(ent, dict):
            all_entitlements.update(ent)
    return all_entitlements


def tool_check_entitlement(features: dict, key: str) -> dict:
    # Check entitlements in machopy output or signature entitlements XML
    macho = features.get("macho", {})
    all_entitlements = _collect_all_entitlements(macho)

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


def tool_get_entitlements(features: dict) -> dict:
    """Bulk entitlement risk assessment — same contract as native's get_entitlements:
    full entitlements dict, substring-matched risk_flags against the shared
    ENTITLEMENT_RISK_DB, sandboxed, and has_private_entitlements."""
    macho = features.get("macho", {})
    ents = _collect_all_entitlements(macho)
    if not ents:
        return {"count": 0, "entitlements": {}, "risk_flags": []}

    risk_flags = []
    for key, value in ents.items():
        for risk_key, (risk, note) in ENTITLEMENT_RISK_DB.items():
            if risk_key in key:
                risk_flags.append({"key": key, "value": value, "risk": risk, "note": note})
                break
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


def _collect_all_dylibs(macho: dict) -> list:
    dylibs = []
    seen = set()
    for arch, data in macho.items():
        if not isinstance(data, dict):
            continue
        for d in data.get("dylibs", []):
            if d not in seen:
                seen.add(d)
                dylibs.append(d)
    return dylibs


def tool_get_dylibs(features: dict) -> dict:
    """Linked-dylib risk assessment — same contract as native's get_dylibs, against
    the shared SUSPICIOUS_DYLIB_PATTERNS table."""
    macho = features.get("macho", {})
    if not macho:
        return {"error": "No Mach-O data available"}
    dylibs = _collect_all_dylibs(macho)

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
        "suspicious_count": sum(1 for d in assessed if d["risk"] in ("HIGH", "CRITICAL")),
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
    all_symbols = [s for v in imports.values() if isinstance(v, list) for s in v]
    return {
        "arch": arch,
        "total_symbols": total,
        "by_library": imports,
        "has_dlopen": any("dlopen" in s for s in all_symbols),
        "has_dlsym": any("dlsym" in s for s in all_symbols),
        "has_shell_exec": any(s.lstrip("_") in ("system", "popen") for s in all_symbols),
    }


def tool_check_injection_triad(features: dict) -> dict:
    """Check for mach_vm_allocate + mach_vm_write + thread_create_running (the core
    3-of-3 threshold), plus mach_vm_protect/task_for_pid as informational-only extra
    signals — same component set and response shape as native's check_injection_triad."""
    components = {
        "mach_vm_allocate": False,
        "mach_vm_write": False,
        "mach_vm_protect": False,
        "thread_create_running": False,
        "task_for_pid": False,
    }
    macho = features.get("macho", {})
    all_imports = _collect_all_imports(macho)

    all_symbols = []
    for symbols in all_imports.values():
        if isinstance(symbols, list):
            all_symbols.extend(str(s).lower() for s in symbols)

    for key in components:
        components[key] = any(key.lower() in sym for sym in all_symbols)

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


def tool_get_segment_entropy(features: dict, arch: str = "all") -> dict:
    """Classifies each segment via the shared common/obfuscation_signals.py scoring
    core (the same per-segment-type ENTROPY_THRESHOLDS table and packing-ratio logic
    native's get_segment_entropy reads from features["obfuscation"]["entropy_analysis"]),
    rather than an independent flat entropy threshold."""
    macho = features.get("macho", {})
    if not macho:
        return {"error": "No Mach-O data available"}

    results = {}
    archs_to_check = [arch] if arch != "all" else list(macho.keys())

    for a in archs_to_check:
        arch_data = macho.get(a, {})
        if not isinstance(arch_data, dict):
            continue
        raw_segments = arch_data.get("segments", [])
        if not isinstance(raw_segments, list):
            continue
        segments = [
            {
                "name": seg.get("segment_name") or seg.get("name", "?"),
                "filesize": seg.get("filesize") or seg.get("size") or 0,
                "entropy": seg.get("entropy") or 0.0,
            }
            for seg in raw_segments if isinstance(seg, dict)
        ]
        scored = score_segment_entropy(segments)
        results[a] = {
            "segments": scored["segments"],
            "high_entropy_segments": scored["high_entropy_segments"],
            "packing_suspected": scored["packing_suspected_via_entropy"],
        }

    return {"arch": arch, "segments": results}


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def dispatch_tool(features: dict, tool_name: str, tool_input: dict) -> dict:
    """Route tool calls from the agent to the correct implementation."""
    dispatch = {
        "get_feature": lambda: tool_get_feature(features, tool_input.get("feature_path", "")),
        "get_strings": lambda: tool_get_strings(features, tool_input.get("pattern", "")),
        "lookup_api_risk": lambda: tool_lookup_api_risk(features, tool_input.get("symbol", "")),
        "check_entitlement": lambda: tool_check_entitlement(features, tool_input.get("key", "")),
        "get_entitlements": lambda: tool_get_entitlements(features),
        "get_dylibs": lambda: tool_get_dylibs(features),
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
