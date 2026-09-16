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

from macskillet.common.obfuscation_signals import (
    PACKING_RATIO_THRESHOLD,
    detect_runtime_markers,
    is_swift_binary,
    score_obfuscation,
    score_section_names,
    score_segment_entropy,
    score_string_density,
    score_symbol_anomalies,
)
from macskillet.common.packer_signatures import PACKER_SIGNATURES, detect_packer_signatures
from macskillet.common.utils import _entropy

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

def _collect_segment_entropy_data(binary_path: str, segments: list) -> list:
    """Read binary bytes and compute per-segment entropy (collector only, no
    scoring). segments: list of dicts with name/fileoff/filesize."""
    try:
        with open(binary_path, "rb") as f:
            binary_data = f.read()
    except Exception:
        return []

    segments_with_entropy = []
    for seg in segments:
        filesize = seg.get("filesize", 0)
        if filesize <= 0:
            continue
        fileoff = seg.get("fileoff", 0)
        chunk = binary_data[fileoff:fileoff + filesize]
        segments_with_entropy.append({
            "name": seg.get("name", "UNKNOWN"),
            "filesize": filesize,
            "entropy": _entropy(chunk),
        })
    return segments_with_entropy


def analyze_section_entropy(
    binary_path: str, segments: list, packing_ratio_threshold: float = PACKING_RATIO_THRESHOLD,
) -> dict:
    """
    Compute per-segment entropy (collector) and score it against the shared
    threshold table (scoring core, see common/obfuscation_signals.py).
    segments: list of dicts from feature_extractor with name/fileoff/filesize.
    """
    segments_with_entropy = _collect_segment_entropy_data(binary_path, segments)
    return score_segment_entropy(segments_with_entropy, ratio_threshold=packing_ratio_threshold)


def _collect_string_count(binary_path: str) -> int:
    try:
        r = subprocess.run(
            ["strings", "-n", "6", binary_path],
            capture_output=True, text=True, timeout=20,
        )
        return len([s for s in r.stdout.splitlines() if s.strip()])
    except Exception:
        return 0


def analyze_string_density(binary_path: str, file_size_bytes: int) -> dict:
    """
    Count printable strings via the ``strings`` CLI (collector) and score
    density against file size (scoring core, see
    common/obfuscation_signals.py).
    """
    if file_size_bytes <= 0:
        return {
            "string_count": 0, "strings_per_kb": 0.0,
            "low_string_density": False, "status": "normal",
        }

    return score_string_density(_collect_string_count(binary_path), file_size_bytes)


def _collect_symbol_counts(binary_path: str) -> tuple:
    """Gather import/export/total symbol counts via nm and the file size
    (collector only, no scoring). Returns (import_count, export_count,
    total_symbol_count, file_size_bytes)."""
    nm_u = _run(["nm", "-u", binary_path], timeout=20)
    import_count = len([l for l in nm_u.splitlines() if l.strip()])

    nm_all = _run(["nm", binary_path], timeout=20)
    total_symbol_count = len([l for l in nm_all.splitlines() if l.strip()])

    nm_g = _run(["nm", "-g", "-U", binary_path], timeout=20)
    export_count = len([l for l in nm_g.splitlines() if l.strip()])

    try:
        file_size = os.path.getsize(binary_path)
    except Exception:
        file_size = 0

    return import_count, export_count, total_symbol_count, file_size


def analyze_symbol_table(binary_path: str) -> dict:
    """
    Gather symbol counts via nm (collector) and score anomalies (scoring
    core, see common/obfuscation_signals.py):
    - Very few imports in a large binary = stripped/packed
    - Huge number of symbols = junk code padding (e.g. OSX.Zuru pattern)
    - No symbols at all = fully stripped (common in malware)
    """
    import_count, export_count, total_symbol_count, file_size = _collect_symbol_counts(binary_path)
    return score_symbol_anomalies(import_count, export_count, total_symbol_count, file_size)


def _collect_section_names(binary_path: str) -> list:
    otool_out = _run(["otool", "-l", binary_path], timeout=20)
    section_names = re.findall(r"sectname\s+(\S+)", otool_out)
    segment_names = re.findall(r"segname\s+(\S+)", otool_out)
    return section_names + segment_names


def check_section_names(binary_path: str) -> dict:
    """Gather section/segment names via otool -l (collector) and check them
    against known packer section names (scoring core, see
    common/obfuscation_signals.py)."""
    return score_section_names(_collect_section_names(binary_path))


def _collect_runtime_text_sample(binary_path: str) -> str:
    return _run(["strings", "-n", "8", binary_path], timeout=15)[:50000]


def detect_language_runtime(binary_path: str, packer_signatures: list) -> dict:
    """
    Identify compiler/language runtime. Some (Go, Nim, Rust) produce large
    statically-linked binaries that may be misidentified as packed. Gathers a
    printable-string sample via the ``strings`` CLI (collector) and matches
    it against known runtime markers (scoring core, see
    common/obfuscation_signals.py).
    """
    try:
        file_size_bytes = os.path.getsize(binary_path)
    except Exception:
        file_size_bytes = 0

    text_sample = _collect_runtime_text_sample(binary_path)
    return detect_runtime_markers(text_sample, packer_signatures, file_size_bytes)


# ---------------------------------------------------------------------------
# Swift runtime detection
# ---------------------------------------------------------------------------

def _collect_swift_data(binary_path: str) -> tuple:
    """Gather section names (otool) and the first 200 raw symbol names (nm)
    (collector only, no scoring). Returns (section_names, symbol_names)."""
    section_names = _collect_section_names(binary_path)
    nm_out = _run(["nm", binary_path], timeout=20)
    symbol_names = nm_out.splitlines()[:200]
    return section_names, symbol_names


def _is_swift_binary(binary_path: str) -> bool:
    """Return True if the binary contains Swift runtime markers.

    Gathers section names (otool) and the first 200 raw symbol names (nm) —
    the collector — and checks them for __swift5_proto/__swift5_types
    sections or _$s mangled symbols via the shared scoring core (see
    common/obfuscation_signals.py). Swift apps legitimately produce
    thousands of symbols, so callers use this to avoid false positives in
    the junk-code heuristic.
    """
    section_names, symbol_names = _collect_swift_data(binary_path)
    return is_swift_binary(section_names, symbol_names)


# ---------------------------------------------------------------------------
# Run-only AppleScript detection
# ---------------------------------------------------------------------------

# Pure byte-matching, no macOS calls — lives in common/deep_scan.py so both
# pipelines' AppleScript scanning (--deep and this main-binary check) reuse
# the same functions rather than duplicating them.
from macskillet.common.deep_scan import (  # noqa: E402
    APPLESCRIPT_EXTENSIONS,
    scan_applescript_analysis,
)


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------

def detect_obfuscation(features: dict) -> dict:
    """
    Collect every obfuscation/packing sub-signal via macOS CLI tools
    (otool/nm/strings), then delegate all scoring/aggregation to the shared
    common/obfuscation_signals.py::score_obfuscation() — the same scoring
    core the portable pipeline's LIEF-based collector uses, so a scoring
    formula or threshold can never drift between pipelines.
    Returns structured result with verdict.
    """
    empty_result = {
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
        "applescript_analysis": {},
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
        empty_result["summary"] = "Could not locate binary for obfuscation analysis"
        return empty_result

    file_size = sample.get("filesize_bytes") or os.path.getsize(binary_path)
    is_swift = _is_swift_binary(binary_path)

    # ── Collection + per-signal scoring (each already delegates to the
    # shared common/obfuscation_signals.py scoring functions internally) ────
    packer_sigs = detect_packer_signatures(binary_path)
    segments = (features.get("binary") or {}).get("segments", [])
    entropy_analysis = analyze_section_entropy(binary_path, segments)
    string_density = analyze_string_density(binary_path, file_size)
    symbol_analysis = analyze_symbol_table(binary_path)
    section_analysis = check_section_names(binary_path)
    runtime = detect_language_runtime(binary_path, packer_sigs)
    binary_features = features.get("binary") or {}
    has_encryption = binary_features.get("has_encryption", False)

    bundle_info = features.get("bundle") or {}
    applescript_paths = [
        p for p in bundle_info.get("embedded_scripts", [])
        if p.lower().endswith(APPLESCRIPT_EXTENSIONS)
    ]
    applescript_analysis = scan_applescript_analysis(binary_path, applescript_paths)

    # ── Aggregation (single shared core) ────────────────────────────────────
    result = score_obfuscation(
        entropy_analysis=entropy_analysis,
        string_density=string_density,
        symbol_analysis=symbol_analysis,
        section_analysis=section_analysis,
        runtime=runtime,
        is_swift=is_swift,
        has_encryption=has_encryption,
        packer_signatures=packer_sigs,
        applescript_analysis=applescript_analysis,
    )
    result["applescript_analysis"] = applescript_analysis
    return result
