#!/usr/bin/env python3
"""
obfuscation_signals.py — Shared, pure-data obfuscation/packing scoring core.

Each scoring function takes already-collected plain data (segment
name/filesize/entropy triples, symbol counts, section-name lists, string
counts, a joined text sample) rather than a binary path or subprocess output
— zero macOS dependency, zero LIEF dependency. Pipeline-specific collectors
(``native/obfuscation_detector.py`` via otool/nm/strings,
``portable/feature_extractor.py`` via LIEF) gather that data however fits
their platform, then call these functions, so a scoring formula or threshold
can never drift between pipelines. Same pattern already used for
``common/packer_signatures.py`` and ``common/deep_scan.py``.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Thresholds (tuned from empirical macOS malware research)
# ---------------------------------------------------------------------------

# Entropy thresholds per segment type.
ENTROPY_THRESHOLDS = {
    "__TEXT":       {"normal_max": 6.5, "suspicious": 7.0, "packed": 7.5},
    "__DATA":       {"normal_max": 5.5, "suspicious": 6.8, "packed": 7.2},
    "__LINKEDIT":   {"normal_max": 7.5, "suspicious": 7.8, "packed": 7.95},
    "__DATA_CONST": {"normal_max": 5.5, "suspicious": 6.5, "packed": 7.0},
    "__TEXT_EXEC":  {"normal_max": 6.5, "suspicious": 7.0, "packed": 7.5},
    "DEFAULT":      {"normal_max": 6.5, "suspicious": 7.0, "packed": 7.5},
}

# Byte-weighted packing-ratio threshold: fraction of total analyzed segment
# bytes that must fall in "packed"-status segments before the whole binary is
# flagged as packed via entropy. Matches pefile's is_probably_packed() (entropy
# > 7.4, summed high-entropy section bytes over 20% of file size — verified
# against its actual source) and the entropy-ratio heuristic family The Art of
# Mac Malware vol. 2 documents for Mach-O. A byte-weighted percentage of the
# binary, not a count of segments — a small, localized high-entropy region
# (e.g. a small encrypted payload blob) is a known, accepted non-match for
# this specific heuristic; known-packer byte-signature matching is a separate,
# independent path for exactly that case.
PACKING_RATIO_THRESHOLD = 0.20

# String density: strings/KB in legitimate vs packed binaries
# Legitimate: ~20-80 strings/KB  |  Packed: <5 strings/KB
STRING_DENSITY_PACKED_THRESHOLD = 5.0   # strings per KB
STRING_DENSITY_SUSPICIOUS_THRESHOLD = 10.0

# Symbol count anomalies
MIN_IMPORTS_FOR_FUNCTIONAL_BINARY = 3   # anything less in a large binary = suspect
JUNK_CODE_FUNCTION_THRESHOLD = 5000     # >5000 functions = likely junk code padding

# File size thresholds
LARGE_BINARY_THRESHOLD_MB = 20.0  # >20MB binary warrants Go/Rust/Nim check

# Section names that are suspicious when present.
SUSPICIOUS_SECTION_NAMES = {
    "UPX0", "UPX1", "UPX2",         # UPX
    "MPRESS1", "MPRESS2",            # MPRESS
    ".pack",                          # Generic packer
    "__vmtext", "__vmdata",          # VMProtect-style
    ".__obfuscated",
}


# ---------------------------------------------------------------------------
# Scoring functions
# ---------------------------------------------------------------------------

def score_segment_entropy(
    segments: list,
    thresholds: dict = ENTROPY_THRESHOLDS,
    ratio_threshold: float = PACKING_RATIO_THRESHOLD,
) -> dict:
    """Score already-computed per-segment entropy against the threshold table.

    ``segments``: list of ``{"name": str, "filesize": int, "entropy": float}``.
    Entropy itself must already be computed by the caller (native reads a
    byte slice of the binary; portable reads it from LIEF's segment content)
    — this function only classifies and aggregates.
    """
    result = {
        "segments": [],
        "high_entropy_segments": [],
        "packing_suspected_via_entropy": False,
        "packing_ratio": 0.0,
        "max_entropy": 0.0,
        "suspicious_segment": None,
    }

    for seg in segments:
        name = seg.get("name", "UNKNOWN")
        filesize = seg.get("filesize", 0)
        if filesize <= 0:
            continue
        ent = seg.get("entropy", 0.0)

        seg_thresholds = thresholds.get(name, thresholds["DEFAULT"])

        status = "normal"
        if ent >= seg_thresholds["packed"]:
            status = "packed"
        elif ent >= seg_thresholds["suspicious"]:
            status = "suspicious"

        seg_result = {
            "name": name,
            "filesize": filesize,
            "entropy": round(ent, 4),
            "status": status,
            "threshold_suspicious": seg_thresholds["suspicious"],
            "threshold_packed": seg_thresholds["packed"],
        }
        result["segments"].append(seg_result)

        if ent > result["max_entropy"]:
            result["max_entropy"] = ent
            result["suspicious_segment"] = name

        if status in ("suspicious", "packed"):
            result["high_entropy_segments"].append(seg_result)

    total_segment_bytes = sum(s["filesize"] for s in result["segments"])
    packed_bytes = sum(s["filesize"] for s in result["segments"] if s["status"] == "packed")
    if total_segment_bytes:
        result["packing_ratio"] = packed_bytes / total_segment_bytes
        if result["packing_ratio"] > ratio_threshold:
            result["packing_suspected_via_entropy"] = True

    return result


def score_string_density(
    string_count: int,
    file_size_bytes: int,
    packed_threshold: float = STRING_DENSITY_PACKED_THRESHOLD,
    suspicious_threshold: float = STRING_DENSITY_SUSPICIOUS_THRESHOLD,
) -> dict:
    """Score an already-counted number of printable strings against file size."""
    result = {
        "string_count": string_count,
        "strings_per_kb": 0.0,
        "low_string_density": False,
        "status": "normal",
    }

    if file_size_bytes <= 0:
        return result

    file_kb = file_size_bytes / 1024.0
    result["strings_per_kb"] = round(string_count / file_kb, 2) if file_kb > 0 else 0

    if result["strings_per_kb"] < packed_threshold:
        result["low_string_density"] = True
        result["status"] = "packed"
    elif result["strings_per_kb"] < suspicious_threshold:
        result["status"] = "suspicious"

    return result


def score_symbol_anomalies(
    import_count: int,
    export_count: int,
    total_symbol_count: int,
    file_size_bytes: int,
    min_imports: int = MIN_IMPORTS_FOR_FUNCTIONAL_BINARY,
    junk_code_threshold: int = JUNK_CODE_FUNCTION_THRESHOLD,
) -> dict:
    """Score already-counted symbol-table statistics for anomalies:
    - Very few imports in a large binary = stripped/packed
    - Huge number of symbols = junk code padding (e.g. OSX.Zuru pattern)
    - No symbols at all = fully stripped (common in malware)
    """
    result = {
        "import_count": import_count,
        "export_count": export_count,
        "total_symbol_count": total_symbol_count,
        "symbols_stripped": False,
        "suspiciously_few_imports": False,
        "junk_code_suspected": False,
        "status": "normal",
        "detail": "",
    }

    # No symbols at all
    if total_symbol_count == 0 and file_size_bytes > 500_000:
        result["symbols_stripped"] = True
        result["status"] = "suspicious"
        result["detail"] = "Fully stripped symbol table in a large binary"

    # Very few imports for binary size
    elif import_count < min_imports and file_size_bytes > 200_000:
        result["suspiciously_few_imports"] = True
        result["status"] = "suspicious"
        result["detail"] = (
            f"Only {import_count} import(s) in a {file_size_bytes // 1024}KB binary — "
            "suggests packing or statically linked payload"
        )

    # Junk code: thousands of symbols (OSX.Zuru / Cobalt Strike padding pattern)
    if total_symbol_count > junk_code_threshold:
        result["junk_code_suspected"] = True
        result["status"] = "obfuscated"
        result["detail"] += (
            f" | {total_symbol_count} symbols detected — "
            "possible junk code injection (OSX.Zuru/Cobalt Strike obfuscation pattern)"
        )

    return result


def score_section_names(
    section_names: list,
    suspicious_names: set = SUSPICIOUS_SECTION_NAMES,
) -> dict:
    """Check an already-collected list of section/segment names for known
    packer-specific names."""
    result = {
        "suspicious_sections": [],
        "section_names": list(set(section_names)),
        "status": "normal",
    }

    for name in result["section_names"]:
        clean = name.strip()
        if clean in suspicious_names:
            result["suspicious_sections"].append({
                "name": clean,
                "risk": "HIGH",
                "detail": f"Known packer section name: {clean}",
            })
            result["status"] = "packed"

    return result


def detect_runtime_markers(
    text_sample: str,
    packer_signatures: list,
    file_size_bytes: int = 0,
    large_binary_threshold_mb: float = LARGE_BINARY_THRESHOLD_MB,
) -> dict:
    """Identify compiler/language runtime from an already-detected
    packer-signature list, falling back to substring search over an
    already-collected printable-text sample. Some runtimes (Go, Nim, Rust)
    produce large statically-linked binaries that may be misidentified as
    packed.
    """
    result = {
        "detected_runtime": None,
        "is_large_binary": False,
        "detail": "",
    }

    if file_size_bytes:
        result["is_large_binary"] = (file_size_bytes / (1024 * 1024)) > large_binary_threshold_mb

    for sig_result in packer_signatures:
        if sig_result["packer"] in ("Go", "Rust", "Nim", "py2app", "PyInstaller", "Nuitka"):
            result["detected_runtime"] = sig_result["packer"]
            result["detail"] = sig_result["detail"]
            break

    if result["detected_runtime"] is None:
        if "NimMain" in text_sample or "nimGC" in text_sample:
            result["detected_runtime"] = "Nim"
            result["detail"] = "Nim runtime detected via strings"
        elif "Go build ID:" in text_sample:
            result["detected_runtime"] = "Go"
            result["detail"] = "Go runtime detected via build ID"
        elif "__rustc" in text_sample:
            result["detected_runtime"] = "Rust"
            result["detail"] = "Rust compiler marker"

    return result


def is_swift_binary(section_names: list, symbol_names: list) -> bool:
    """Return True if already-collected section/symbol names show Swift
    runtime markers.

    Checks __swift5_proto/__swift5_types section names and _$s mangled
    symbol names (raw, not demangled — the mangled prefix is what identifies
    Swift, and demangling could strip or alter it). Swift apps legitimately
    produce thousands of symbols, so callers use this to avoid false
    positives in the junk-code heuristic.
    """
    if any(name in ("__swift5_proto", "__swift5_types") for name in section_names):
        return True
    return any("_$s" in name for name in symbol_names[:200])


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def score_obfuscation(
    entropy_analysis: dict,
    string_density: dict,
    symbol_analysis: dict,
    section_analysis: dict,
    runtime: dict,
    is_swift: bool,
    has_encryption: bool,
    packer_signatures: list,
    applescript_analysis: dict | None = None,
) -> dict:
    """Aggregate every already-scored sub-signal into the same
    score/confidence/summary shape ``detect_obfuscation()`` has always
    produced.

    Each argument is the output of one of this module's own scoring
    functions (``score_segment_entropy``, ``score_string_density``,
    ``score_symbol_anomalies``, ``score_section_names``,
    ``detect_runtime_markers``, ``is_swift_binary``) or of
    ``common/packer_signatures.py``/``common/deep_scan.py`` — this function
    only combines already-computed results, it does not gather or score raw
    data itself, so each pipeline's collector stays free to gather that data
    however fits its platform (native: otool/nm/strings; portable: LIEF).

    ``applescript_analysis`` is accepted here purely as a scoring input — its
    own dict is stored and owned by each pipeline's top-level
    ``features["applescript_analysis"]`` field (shared schema, see
    ``macskillet-signature-trust``), not duplicated in this function's output.
    """
    applescript = applescript_analysis or {}
    result = {
        "obfuscation_suspected": False,
        "packing_suspected": False,
        "confidence": "NONE",
        "techniques_detected": [],
        "packer_signatures": packer_signatures,
        "entropy_analysis": entropy_analysis,
        "string_density": string_density,
        "symbol_analysis": symbol_analysis,
        "section_analysis": section_analysis,
        "runtime": {},
        "has_encryption": has_encryption,
        "score": 0,
        "summary": "",
    }

    # ── 1. Packer signatures ───────────────────────────────────────────────
    high_risk_packers = [p for p in packer_signatures if p["risk"] == "HIGH"]
    if high_risk_packers:
        result["packing_suspected"] = True
        result["score"] += 8 * len(high_risk_packers)
        for p in high_risk_packers:
            result["techniques_detected"].append(f"packer:{p['packer']}")

    # ── 2. Entropy analysis ────────────────────────────────────────────────
    if entropy_analysis.get("packing_suspected_via_entropy"):
        result["packing_suspected"] = True
        result["score"] += 5
        result["techniques_detected"].append("high_entropy_segments")
    elif entropy_analysis.get("high_entropy_segments"):
        result["score"] += 2
        result["techniques_detected"].append("elevated_entropy")

    # ── 3. String density ─────────────────────────────────────────────────
    if string_density.get("status") == "packed":
        result["packing_suspected"] = True
        result["score"] += 5
        result["techniques_detected"].append("low_string_density")
    elif string_density.get("status") == "suspicious":
        result["score"] += 2

    # ── 4. Symbol table anomalies ─────────────────────────────────────────
    # Swift apps legitimately exceed the symbol threshold; suppress for Swift.
    # Trade-off: Swift malware using junk-code padding would be missed here.
    junk_code_active = symbol_analysis.get("junk_code_suspected") and not is_swift
    result["junk_code_suspected"] = junk_code_active
    if junk_code_active:
        result["obfuscation_suspected"] = True
        result["score"] += 6
        result["techniques_detected"].append("junk_code_padding")
    if symbol_analysis.get("symbols_stripped"):
        result["score"] += 3
        result["techniques_detected"].append("stripped_symbol_table")
    if symbol_analysis.get("suspiciously_few_imports"):
        result["score"] += 4
        result["techniques_detected"].append("suspiciously_few_imports")
    if is_swift:
        result["techniques_detected"].append("swift_binary")

    # ── 5. Section name anomalies ─────────────────────────────────────────
    if section_analysis.get("suspicious_sections"):
        result["packing_suspected"] = True
        result["score"] += 6
        result["techniques_detected"].append("suspicious_section_names")

    # ── 6. Encryption flag ────────────────────────────────────────────────
    if result["has_encryption"]:
        result["score"] += 3
        result["techniques_detected"].append("lc_encryption_info")

    # ── 6b. Run-only / compiled AppleScript ───────────────────────────────
    if applescript.get("runonly_applescript"):
        result["obfuscation_suspected"] = True
        result["score"] += 5
        result["techniques_detected"].append("runonly_applescript")
    elif applescript.get("compiled_applescript"):
        result["score"] += 2
        result["techniques_detected"].append("compiled_applescript")

    # ── 7. Language runtime detection ─────────────────────────────────────
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
    elif runtime["detected_runtime"] == "Nuitka":
        # Unlike Go/Rust/Swift, Nuitka isn't yet a common legitimate macOS
        # distribution target, and the only documented case (Infiniti Stealer,
        # March 2026) is malicious — so its symbol-count signal is NOT
        # suppressed the way Swift's junk-code heuristic is (see is_swift
        # check above); detecting the runtime instead increases suspicion,
        # same direction as Nim.
        result["score"] += 2
        result["techniques_detected"].append("nuitka_runtime")

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
