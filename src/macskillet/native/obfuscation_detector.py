#!/usr/bin/env python3
"""
obfuscation_detector.py — Static packing and obfuscation detection for macOS Mach-O binaries.

Detection methods:
  1. Entropy analysis — per-segment and per-section entropy
  2. UPX / known packer signature bytes
  3. Symbol table anomalies — too few imports, too many functions (junk code)
  4. String density ratio — packed binaries have very few readable strings
  5. Section name anomalies — non-standard or renamed sections
  6. Stripped symbol table — no symbols at all in a large binary
  7. LLVM obfuscator indicators — specific section names, split basic blocks
  8. Go/Rust/Nim runtime indicators — large statically-linked binaries
  9. LC_ENCRYPTION_INFO — App Store DRM or custom encryptor
 10. Import count anomaly — packed binaries have almost no imports
"""

import os
import re
import subprocess
from typing import Any

from macskillet.native.utils import _entropy


# ---------------------------------------------------------------------------
# Thresholds (tuned from empirical macOS malware research)
# ---------------------------------------------------------------------------

# Entropy thresholds per segment
ENTROPY_THRESHOLDS = {
    "__TEXT":       {"normal_max": 6.5, "suspicious": 7.0, "packed": 7.5},
    "__DATA":       {"normal_max": 5.5, "suspicious": 6.8, "packed": 7.2},
    "__LINKEDIT":   {"normal_max": 7.5, "suspicious": 7.8, "packed": 7.95},
    "__DATA_CONST": {"normal_max": 5.5, "suspicious": 6.5, "packed": 7.0},
    "__TEXT_EXEC":  {"normal_max": 6.5, "suspicious": 7.0, "packed": 7.5},
    "DEFAULT":      {"normal_max": 6.5, "suspicious": 7.0, "packed": 7.5},
}

# String density: strings/KB in legitimate vs packed binaries
# Legitimate: ~20-80 strings/KB  |  Packed: <5 strings/KB
STRING_DENSITY_PACKED_THRESHOLD = 5.0   # strings per KB
STRING_DENSITY_SUSPICIOUS_THRESHOLD = 10.0

# Symbol count anomalies
MIN_IMPORTS_FOR_FUNCTIONAL_BINARY = 3   # anything less in a large binary = suspect
JUNK_CODE_FUNCTION_THRESHOLD = 5000     # >5000 functions = likely junk code padding

# File size thresholds
LARGE_BINARY_THRESHOLD_MB = 20.0  # >20MB binary warrants Go/Rust/Nim check


# ---------------------------------------------------------------------------
# Packer signatures (binary patterns)
# ---------------------------------------------------------------------------

PACKER_SIGNATURES = [
    # UPX — most common macOS packer
    (b"UPX!", "UPX", "HIGH",
     "UPX packer magic bytes — binary is compressed and self-unpacking"),
    (b"UPX0", "UPX", "HIGH",
     "UPX section name (UPX0) — confirms UPX packing"),
    (b"UPX1", "UPX", "HIGH",
     "UPX section name (UPX1)"),
    # MPRESS
    (b"MPRESS1", "MPRESS", "HIGH",
     "MPRESS packer section name"),
    (b"MPRESS2", "MPRESS", "HIGH",
     "MPRESS packer section name"),
    # Generic packed section markers
    (b".upxsig", "UPX", "HIGH",
     "UPX signature section"),
    # Themida/VMProtect (rare on macOS but seen in some samples)
    (b"VMProtect", "VMProtect", "HIGH",
     "VMProtect obfuscator marker"),
    # Golang runtime (not a packer but large binary, distinct markers)
    (b"Go build ID:", "Go", "LOW",
     "Go runtime — large binary expected, not malicious by itself"),
    (b"runtime.main", "Go", "LOW",
     "Go runtime marker"),
    # Rust runtime
    (b"__rustc", "Rust", "LOW",
     "Rust compiler marker — statically linked runtime"),
    # Nim
    (b"NimMain", "Nim", "MEDIUM",
     "Nim language runtime — sometimes used in macOS malware (Sliver, etc.)"),
    (b"nimGC", "Nim", "MEDIUM",
     "Nim GC marker"),
    # PyInstaller / py2app wrapped Python
    (b"PKG_BASE", "PyInstaller", "MEDIUM",
     "PyInstaller embedded package marker"),
    (b"pyi-", "PyInstaller", "MEDIUM",
     "PyInstaller marker prefix"),
    (b"py2app", "py2app", "LOW",
     "py2app wrapper — Python app bundle"),
    # LLVM Obfuscator / Hikari / o-llvm
    (b"__cstring\x00", "LLVM", "LOW",
     "Standard LLVM section (normal, but check with entropy)"),
    # Custom/unknown — high-entropy section with no readable strings
    # (handled via entropy analysis, not byte signatures)
]

# Section names that are suspicious when present
SUSPICIOUS_SECTION_NAMES = {
    "UPX0", "UPX1", "UPX2",         # UPX
    "MPRESS1", "MPRESS2",            # MPRESS
    ".pack",                          # Generic packer
    "__vmtext", "__vmdata",          # VMProtect-style
    ".__obfuscated",
}

# Section names used by LLVM obfuscators (not suspicious alone, but flag)
LLVM_OBFUSCATOR_SECTIONS = {
    "__llvm_prf_cnts", "__llvm_prf_data", "__llvm_prf_names",  # PGO (legit)
    "__swift5_proto", "__swift5_types",  # Swift (legit)
    # Hikari/o-llvm specific — harder to detect statically
}


def _run(cmd: list, timeout: int = 30) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Detection functions
# ---------------------------------------------------------------------------

def detect_packer_signatures(binary_path: str) -> list:
    """Scan binary bytes for known packer signatures."""
    matches = []
    try:
        with open(binary_path, "rb") as f:
            data = f.read()
        for sig, packer, risk, detail in PACKER_SIGNATURES:
            if sig in data:
                matches.append({
                    "packer": packer,
                    "signature": sig.decode("utf-8", errors="replace"),
                    "risk": risk,
                    "detail": detail,
                })
    except Exception:
        pass
    return matches


def analyze_section_entropy(binary_path: str, segments: list) -> dict:
    """
    Compute per-segment entropy and flag anomalies.
    segments: list of dicts from extract_features_native with name/fileoff/filesize.
    """
    result = {
        "segments": [],
        "high_entropy_segments": [],
        "packing_suspected_via_entropy": False,
        "max_entropy": 0.0,
        "suspicious_segment": None,
    }

    try:
        with open(binary_path, "rb") as f:
            binary_data = f.read()
    except Exception:
        return result

    for seg in segments:
        name = seg.get("name", "UNKNOWN")
        fileoff = seg.get("fileoff", 0)
        filesize = seg.get("filesize", 0)
        if filesize <= 0:
            continue

        chunk = binary_data[fileoff:fileoff + filesize]
        ent = _entropy(chunk)

        thresholds = ENTROPY_THRESHOLDS.get(name, ENTROPY_THRESHOLDS["DEFAULT"])

        status = "normal"
        if ent >= thresholds["packed"]:
            status = "packed"
        elif ent >= thresholds["suspicious"]:
            status = "suspicious"

        seg_result = {
            "name": name,
            "filesize": filesize,
            "entropy": round(ent, 4),
            "status": status,
            "threshold_suspicious": thresholds["suspicious"],
            "threshold_packed": thresholds["packed"],
        }
        result["segments"].append(seg_result)

        if ent > result["max_entropy"]:
            result["max_entropy"] = ent
            result["suspicious_segment"] = name

        if status in ("suspicious", "packed"):
            result["high_entropy_segments"].append(seg_result)

    if any(s["status"] == "packed" for s in result["segments"]):
        result["packing_suspected_via_entropy"] = True
    elif len(result["high_entropy_segments"]) >= 2:
        result["packing_suspected_via_entropy"] = True

    return result


def analyze_string_density(binary_path: str, file_size_bytes: int) -> dict:
    """
    Compute string density. Packed binaries have very few readable strings.
    """
    result = {
        "string_count": 0,
        "strings_per_kb": 0.0,
        "low_string_density": False,
        "status": "normal",
    }

    if file_size_bytes <= 0:
        return result

    try:
        r = subprocess.run(
            ["strings", "-n", "6", binary_path],
            capture_output=True, text=True, timeout=20
        )
        strings = [s for s in r.stdout.splitlines() if s.strip()]
        result["string_count"] = len(strings)
        file_kb = file_size_bytes / 1024.0
        result["strings_per_kb"] = round(len(strings) / file_kb, 2) if file_kb > 0 else 0

        if result["strings_per_kb"] < STRING_DENSITY_PACKED_THRESHOLD:
            result["low_string_density"] = True
            result["status"] = "packed"
        elif result["strings_per_kb"] < STRING_DENSITY_SUSPICIOUS_THRESHOLD:
            result["status"] = "suspicious"
    except Exception:
        pass

    return result


def analyze_symbol_table(binary_path: str) -> dict:
    """
    Analyze symbol table for anomalies:
    - Very few imports in a large binary = stripped/packed
    - Huge number of symbols = junk code padding (e.g. OSX.Zuru pattern)
    - No symbols at all = fully stripped (common in malware)
    """
    result = {
        "import_count": 0,
        "export_count": 0,
        "total_symbol_count": 0,
        "symbols_stripped": False,
        "suspiciously_few_imports": False,
        "junk_code_suspected": False,
        "status": "normal",
        "detail": "",
    }

    # Imports
    nm_u = _run(["nm", "-u", binary_path], timeout=20)
    imports = [l.strip() for l in nm_u.splitlines() if l.strip()]
    result["import_count"] = len(imports)

    # All symbols
    nm_all = _run(["nm", binary_path], timeout=20)
    all_syms = [l for l in nm_all.splitlines() if l.strip()]
    result["total_symbol_count"] = len(all_syms)

    # Exports
    nm_g = _run(["nm", "-g", "-U", binary_path], timeout=20)
    result["export_count"] = len([l for l in nm_g.splitlines() if l.strip()])

    file_size = 0
    try:
        file_size = os.path.getsize(binary_path)
    except Exception:
        pass

    # No symbols at all
    if result["total_symbol_count"] == 0 and file_size > 500_000:
        result["symbols_stripped"] = True
        result["status"] = "suspicious"
        result["detail"] = "Fully stripped symbol table in a large binary"

    # Very few imports for binary size
    elif result["import_count"] < MIN_IMPORTS_FOR_FUNCTIONAL_BINARY and file_size > 200_000:
        result["suspiciously_few_imports"] = True
        result["status"] = "suspicious"
        result["detail"] = (
            f"Only {result['import_count']} import(s) in a {file_size//1024}KB binary — "
            "suggests packing or statically linked payload"
        )

    # Junk code: thousands of symbols (OSX.Zuru / Cobalt Strike padding pattern)
    if result["total_symbol_count"] > JUNK_CODE_FUNCTION_THRESHOLD:
        result["junk_code_suspected"] = True
        result["status"] = "obfuscated"
        result["detail"] += (
            f" | {result['total_symbol_count']} symbols detected — "
            "possible junk code injection (OSX.Zuru/Cobalt Strike obfuscation pattern)"
        )

    return result


def check_section_names(binary_path: str) -> dict:
    """Check for non-standard or suspicious section names via otool -l."""
    result = {
        "suspicious_sections": [],
        "section_names": [],
        "status": "normal",
    }

    otool_out = _run(["otool", "-l", binary_path], timeout=20)
    section_names = re.findall(r"sectname\s+(\S+)", otool_out)
    segment_names = re.findall(r"segname\s+(\S+)", otool_out)
    result["section_names"] = list(set(section_names + segment_names))

    for name in result["section_names"]:
        clean = name.strip()
        if clean in SUSPICIOUS_SECTION_NAMES:
            result["suspicious_sections"].append({
                "name": clean,
                "risk": "HIGH",
                "detail": f"Known packer section name: {clean}",
            })
            result["status"] = "packed"

    return result


def detect_language_runtime(binary_path: str, packer_signatures: list) -> dict:
    """
    Identify compiler/language runtime. Some (Go, Nim, Rust) produce large
    statically-linked binaries that may be misidentified as packed.
    """
    result = {
        "detected_runtime": None,
        "is_large_binary": False,
        "detail": "",
    }

    try:
        file_size_mb = os.path.getsize(binary_path) / (1024 * 1024)
        result["is_large_binary"] = file_size_mb > LARGE_BINARY_THRESHOLD_MB
    except Exception:
        pass

    for sig_result in packer_signatures:
        if sig_result["packer"] in ("Go", "Rust", "Nim", "py2app", "PyInstaller"):
            result["detected_runtime"] = sig_result["packer"]
            result["detail"] = sig_result["detail"]
            break

    # Also check via strings
    if result["detected_runtime"] is None:
        strings_sample = _run(["strings", "-n", "8", binary_path], timeout=15)[:50000]
        if "NimMain" in strings_sample or "nimGC" in strings_sample:
            result["detected_runtime"] = "Nim"
            result["detail"] = "Nim runtime detected via strings"
        elif "Go build ID:" in strings_sample:
            result["detected_runtime"] = "Go"
            result["detail"] = "Go runtime detected via build ID"
        elif "__rustc" in strings_sample:
            result["detected_runtime"] = "Rust"
            result["detail"] = "Rust compiler marker"

    return result


# ---------------------------------------------------------------------------
# Swift runtime detection
# ---------------------------------------------------------------------------

def _is_swift_binary(binary_path: str) -> bool:
    """Return True if the binary contains Swift runtime markers.

    Checks __swift5_proto/__swift5_types sections (otool) and _$s mangled
    symbols (nm). Swift apps legitimately produce thousands of symbols, so
    callers use this to avoid false positives in the junk-code heuristic.
    """
    otool_out = _run(["otool", "-l", binary_path], timeout=20)
    if "__swift5_proto" in otool_out or "__swift5_types" in otool_out:
        return True
    nm_out = _run(["nm", binary_path], timeout=20)
    return any("_$s" in sym for sym in nm_out.splitlines()[:200])


# ---------------------------------------------------------------------------
# Run-only AppleScript detection
# ---------------------------------------------------------------------------

# 0xFADEDEAD — marker in run-only (source-stripped) AppleScript script data.
_APPLESCRIPT_RUNONLY_MAGIC = b"\xfa\xde\xde\xad"
# Header of compiled AppleScript (.scpt) data.
_APPLESCRIPT_COMPILED_MAGIC = b"FasdUAS"


def scan_runonly_applescript(data: bytes) -> dict:
    """Detect run-only / compiled AppleScript embedded in a byte blob.

    Run-only AppleScript has its source stripped and carries the 0xFADEDEAD
    marker; `osadecompile` cannot recover it. AMOS/ClickFix payloads ship
    run-only applets to hide their logic from static analysis, so the marker
    itself is a high-value obfuscation signal.
    """
    runonly = _APPLESCRIPT_RUNONLY_MAGIC in data
    compiled = _APPLESCRIPT_COMPILED_MAGIC in data
    indicators = []
    if runonly:
        indicators.append(
            "0xFADEDEAD run-only AppleScript marker — source stripped, osadecompile fails"
        )
    if compiled:
        indicators.append("FasdUAS compiled-AppleScript header")
    return {
        "runonly_applescript": runonly,
        "compiled_applescript": compiled,
        "indicators": indicators,
        "detail": "; ".join(indicators) if indicators else "no AppleScript script data found",
    }


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------

def detect_obfuscation(features: dict) -> dict:
    """
    Run all obfuscation/packing detection checks.
    Returns structured result with verdict.
    """
    result = {
        "obfuscation_suspected": False,
        "packing_suspected": False,
        "confidence": "NONE",
        "techniques_detected": [],
        "packer_signatures": [],
        "entropy_analysis": {},
        "string_density": {},
        "symbol_analysis": {},
        "section_analysis": {},
        "runtime": {},
        "has_encryption": False,
        "runonly_applescript": {},
        "score": 0,
        "summary": "",
    }

    # Resolve binary path
    binary_path = None
    sample = features.get("sample", {})
    if sample.get("type") == "macho_binary":
        binary_path = sample.get("path")
    elif sample.get("type") == "app_bundle":
        bundle = features.get("bundle") or {}
        main_exec = bundle.get("main_executable")
        app_path = sample.get("path", "")
        if main_exec:
            binary_path = f"{app_path}/Contents/MacOS/{main_exec}"

    if not binary_path or not os.path.exists(binary_path):
        result["summary"] = "Could not locate binary for obfuscation analysis"
        return result

    file_size = sample.get("filesize_bytes") or os.path.getsize(binary_path)
    is_swift = _is_swift_binary(binary_path)

    # ── 1. Packer signatures ───────────────────────────────────────────────
    packer_sigs = detect_packer_signatures(binary_path)
    result["packer_signatures"] = packer_sigs
    high_risk_packers = [p for p in packer_sigs if p["risk"] == "HIGH"]
    if high_risk_packers:
        result["packing_suspected"] = True
        result["score"] += 8 * len(high_risk_packers)
        for p in high_risk_packers:
            result["techniques_detected"].append(f"packer:{p['packer']}")

    # ── 2. Entropy analysis ────────────────────────────────────────────────
    segments = (features.get("binary") or {}).get("segments", [])
    ent_result = analyze_section_entropy(binary_path, segments)
    result["entropy_analysis"] = ent_result
    if ent_result["packing_suspected_via_entropy"]:
        result["packing_suspected"] = True
        result["score"] += 5
        result["techniques_detected"].append("high_entropy_segments")
    elif ent_result["high_entropy_segments"]:
        result["score"] += 2
        result["techniques_detected"].append("elevated_entropy")

    # ── 3. String density ─────────────────────────────────────────────────
    density = analyze_string_density(binary_path, file_size)
    result["string_density"] = density
    if density["status"] == "packed":
        result["packing_suspected"] = True
        result["score"] += 5
        result["techniques_detected"].append("low_string_density")
    elif density["status"] == "suspicious":
        result["score"] += 2

    # ── 4. Symbol table anomalies ─────────────────────────────────────────
    sym_analysis = analyze_symbol_table(binary_path)
    result["symbol_analysis"] = sym_analysis
    # Swift apps legitimately exceed the symbol threshold; suppress for Swift.
    # Trade-off: Swift malware using junk-code padding would be missed here.
    junk_code_active = sym_analysis["junk_code_suspected"] and not is_swift
    result["junk_code_suspected"] = junk_code_active
    if junk_code_active:
        result["obfuscation_suspected"] = True
        result["score"] += 6
        result["techniques_detected"].append("junk_code_padding")
    if sym_analysis["symbols_stripped"]:
        result["score"] += 3
        result["techniques_detected"].append("stripped_symbol_table")
    if sym_analysis["suspiciously_few_imports"]:
        result["score"] += 4
        result["techniques_detected"].append("suspiciously_few_imports")
    if is_swift:
        result["techniques_detected"].append("swift_binary")

    # ── 5. Section name anomalies ─────────────────────────────────────────
    sect_analysis = check_section_names(binary_path)
    result["section_analysis"] = sect_analysis
    if sect_analysis["suspicious_sections"]:
        result["packing_suspected"] = True
        result["score"] += 6
        result["techniques_detected"].append("suspicious_section_names")

    # ── 6. Encryption flag ────────────────────────────────────────────────
    binary_features = features.get("binary") or {}
    result["has_encryption"] = binary_features.get("has_encryption", False)
    if result["has_encryption"]:
        result["score"] += 3
        result["techniques_detected"].append("lc_encryption_info")

    # ── 6b. Run-only / compiled AppleScript ───────────────────────────────
    ra = {"runonly_applescript": False, "compiled_applescript": False, "indicators": []}
    try:
        blobs = []
        with open(binary_path, "rb") as f:
            blobs.append(f.read(2_000_000))
        # Also scan embedded .scpt files inside an app bundle (run-only applets
        # keep their script in Contents/Resources, not the Mach-O).
        sample_path = features.get("sample", {}).get("path", "")
        if sample_path.endswith(".app") and os.path.isdir(sample_path):
            for root, _, files in os.walk(os.path.join(sample_path, "Contents")):
                for fn in files:
                    if fn.endswith(".scpt"):
                        try:
                            with open(os.path.join(root, fn), "rb") as sf:
                                blobs.append(sf.read(1_000_000))
                        except Exception:
                            pass
        for blob in blobs:
            r = scan_runonly_applescript(blob)
            ra["runonly_applescript"] = ra["runonly_applescript"] or r["runonly_applescript"]
            ra["compiled_applescript"] = ra["compiled_applescript"] or r["compiled_applescript"]
            ra["indicators"].extend(i for i in r["indicators"] if i not in ra["indicators"])
    except Exception:
        pass
    result["runonly_applescript"] = ra
    if ra["runonly_applescript"]:
        result["obfuscation_suspected"] = True
        result["score"] += 5
        result["techniques_detected"].append("runonly_applescript")
    elif ra["compiled_applescript"]:
        result["score"] += 2
        result["techniques_detected"].append("compiled_applescript")

    # ── 7. Language runtime detection ─────────────────────────────────────
    runtime = detect_language_runtime(binary_path, packer_sigs)
    result["runtime"] = runtime
    # If it's a known large runtime (Go/Rust), reduce suspicion for entropy/string density
    if runtime["detected_runtime"] in ("Go", "Rust"):
        if "high_entropy_segments" in result["techniques_detected"]:
            result["score"] = max(0, result["score"] - 3)
        if "low_string_density" in result["techniques_detected"]:
            result["score"] = max(0, result["score"] - 2)
    elif runtime["detected_runtime"] == "Nim":
        result["score"] += 2  # Nim is more commonly seen in malware
        result["techniques_detected"].append("nim_runtime")

    # ── Final verdict ──────────────────────────────────────────────────────
    if result["score"] >= 12:
        result["obfuscation_suspected"] = True
        result["packing_suspected"] = True
        result["confidence"] = "HIGH"
    elif result["score"] >= 7:
        result["obfuscation_suspected"] = True
        result["confidence"] = "MEDIUM"
    elif result["score"] >= 4:
        result["confidence"] = "LOW"
        result["obfuscation_suspected"] = (
            result["packing_suspected"]
            or "runonly_applescript" in result["techniques_detected"]
        )

    # ── Summary ─────────────────────────────────────────────────────────
    techniques = ", ".join(result["techniques_detected"]) or "none"
    runtime_str = f" (runtime: {runtime['detected_runtime']})" if runtime["detected_runtime"] else ""
    if result["packing_suspected"]:
        result["summary"] = (
            f"Packing/obfuscation DETECTED ({result['confidence']} confidence). "
            f"Techniques: {techniques}{runtime_str}. Score: {result['score']}."
        )
    elif result["obfuscation_suspected"]:
        result["summary"] = (
            f"Obfuscation indicators present ({result['confidence']} confidence). "
            f"Techniques: {techniques}{runtime_str}."
        )
    else:
        result["summary"] = (
            f"No significant packing or obfuscation detected{runtime_str}. Score: {result['score']}."
        )

    return result
