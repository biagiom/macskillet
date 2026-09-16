#!/usr/bin/env python3
"""
feature_extractor.py — macOS App Static Feature Extractor

Delegates all binary analysis to src/machopy, which provides LIEF-based
Mach-O parsing and macOS codesign/bundle introspection.

Usage:
    python feature_extractor.py /path/to/App.app
    python feature_extractor.py /path/to/binary
    python feature_extractor.py --dir /path/to/samples/ --output results.jsonl
"""

import argparse
import json
import os
import sys
from pathlib import Path


from macskillet.machopy.bundle_analyzer import analyze_bundle
from macskillet.machopy.macho_analyzer import analyze_macho, is_macho, sha256, md5
from macskillet.machopy.signature_analyzer import analyze_signature
from macskillet.machopy.string_extractor import extract_strings_of_interest
from macskillet.common.deep_scan import (
    APPLESCRIPT_EXTENSIONS, bucket_candidates, build_deep_scan_result,
    scan_applescript_analysis, scan_applescript_item, select_within_limit,
)
from macskillet.common.obfuscation_signals import (
    detect_runtime_markers, is_swift_binary, score_obfuscation, score_section_names,
    score_segment_entropy, score_string_density, score_symbol_anomalies,
)
from macskillet.common.packer_signatures import detect_packer_signatures
from macskillet.common.signature_trust import assess_signature_trust
from macskillet.common.strings import read_strings


def _pick_primary_arch(macho_result: dict) -> dict:
    """Pick one arch's data out of analyze_macho()'s arch-keyed result for
    obfuscation scoring — prefer arm64 (Apple Silicon), else the first arch
    present, else an empty dict (e.g. on a parse error)."""
    if not macho_result or "error" in macho_result:
        return {}
    if "arm64" in macho_result:
        return macho_result["arm64"]
    return next(iter(macho_result.values()), {})


def detect_obfuscation_portable(features: dict) -> dict:
    """Portable-pipeline counterpart of native's detect_obfuscation(features: dict),
    same single-argument signature. Resolves the main binary path from
    features["sample"]/features["bundle"] exactly like native does (including
    native's own limitation: no fallback to bundle_info["all_binaries"][0] if the
    declared main executable path doesn't exist — matching native's actual
    behavior, not extending it).

    Uses LIEF-derived data (via macho_analyzer.py) instead of otool/nm, and
    common/strings.py::read_strings() instead of the strings CLI — neither
    shells out to a macOS-only tool. Scoring itself is 100% shared with
    native via common/obfuscation_signals.py, so a threshold or formula can
    never drift between pipelines.
    """
    empty_result = {
        "obfuscation_suspected": False, "packing_suspected": False, "confidence": "NONE",
        "techniques_detected": [], "packer_signatures": [], "entropy_analysis": {},
        "string_density": {}, "symbol_analysis": {}, "section_analysis": {}, "runtime": {},
        "has_encryption": False, "score": 0, "summary": "",
    }

    sample = features.get("sample") or {}
    binary_path = None
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

    macho_result = features.get("macho") or {}
    packer_signatures = features.get("packer_signatures") or []
    applescript_analysis = features.get("applescript_analysis") or {}

    arch_data = _pick_primary_arch(macho_result)
    try:
        file_size_bytes = os.path.getsize(binary_path)
    except OSError:
        file_size_bytes = 0

    segments = [
        {"name": s["segment_name"], "filesize": s["filesize"], "entropy": s["entropy"]}
        for s in arch_data.get("segments", [])
    ]
    try:
        string_count = sum(1 for _ in read_strings(binary_path, min_len=6))
        runtime_text_sample = "\n".join(read_strings(binary_path, min_len=8))[:50000]
    except OSError:
        string_count = 0
        runtime_text_sample = ""

    entropy_analysis = score_segment_entropy(segments)
    string_density = score_string_density(string_count, file_size_bytes)
    symbol_analysis = score_symbol_anomalies(
        arch_data.get("import_count", 0), arch_data.get("export_count", 0),
        arch_data.get("total_symbol_count", 0), file_size_bytes,
    )
    section_analysis = score_section_names(arch_data.get("section_names", []))
    runtime = detect_runtime_markers(runtime_text_sample, packer_signatures, file_size_bytes)
    is_swift = is_swift_binary(
        arch_data.get("section_names", []), arch_data.get("symbol_names_sample", []),
    )

    result = score_obfuscation(
        entropy_analysis=entropy_analysis,
        string_density=string_density,
        symbol_analysis=symbol_analysis,
        section_analysis=section_analysis,
        runtime=runtime,
        is_swift=is_swift,
        has_encryption=arch_data.get("has_encryption", False),
        packer_signatures=packer_signatures,
        applescript_analysis=applescript_analysis,
    )
    return result


def _deep_scan_bundle(bundle_info: dict, main_binary: str | None, deep_limit: int) -> dict:
    """Portable-pipeline counterpart of the native extractor's deep scan.

    Same bucketing/priority/shape as the native pipeline (see
    macskillet.common.deep_scan) — only the Mach-O analysis call differs
    (analyze_macho instead of analyze_binary), since that's LIEF-based here.
    """
    buckets = bucket_candidates(
        bundle_info.get("all_binaries", []),
        bundle_info.get("embedded_scripts", []),
        main_binary=main_binary,
    )
    selected, skipped_by_kind = select_within_limit(buckets, deep_limit)

    scanned = []
    for item_path, kind in selected:
        entry = {"path": item_path, "kind": kind}
        try:
            if kind == "applescript":
                entry["analysis"] = scan_applescript_item(item_path)
            else:
                analysis = analyze_macho(item_path)
                analysis["packer_signatures"] = detect_packer_signatures(item_path)
                entry["analysis"] = analysis
        except Exception as e:
            entry["error"] = str(e)
        scanned.append(entry)

    return build_deep_scan_result(scanned, skipped_by_kind, deep_limit)


# ---------------------------------------------------------------------------
# Main extraction pipeline
# ---------------------------------------------------------------------------

def extract(path: str, deep_limit: int | None = None) -> dict:
    """Full feature extraction for a .app bundle or Mach-O binary."""
    path = os.path.abspath(path)

    features = {
        "sample": {
            "name": os.path.basename(path),
            "path": path,
            "type": None,
            "sha256": None,
            "md5": None,
            "filesize_bytes": None,
        },
        "bundle": None,
        "signature": None,
        "macho": None,
        "strings_of_interest": [],
        "packer_signatures": [],
        "applescript_analysis": {},
        "obfuscation": {},
        "deep_scan": {"enabled": False},
        "signature_trust": None,
        "errors": [],
    }

    if path.endswith(".app") and os.path.isdir(path):
        features["sample"]["type"] = "app_bundle"
        features["sample"]["sha256"] = "N/A (bundle)"
        features["sample"]["md5"] = "N/A (bundle)"

        bundle_info = analyze_bundle(path)
        features["bundle"] = bundle_info

        main_exec_name = bundle_info.get("main_executable")
        main_binary = os.path.join(path, "Contents", "MacOS", main_exec_name or "")
        if not os.path.exists(main_binary):
            binaries = bundle_info.get("all_binaries", [])
            main_binary = binaries[0] if binaries else None

        if main_binary and os.path.exists(main_binary):
            features["sample"]["sha256"] = sha256(main_binary)
            features["sample"]["md5"] = md5(main_binary)
            features["sample"]["filesize_bytes"] = os.path.getsize(main_binary)
            features["macho"] = analyze_macho(main_binary)
            features["signature"] = analyze_signature(path)
            features["strings_of_interest"] = extract_strings_of_interest(main_binary)
            features["packer_signatures"] = detect_packer_signatures(main_binary)
            applescript_paths = [
                p for p in bundle_info.get("embedded_scripts", [])
                if p.lower().endswith(APPLESCRIPT_EXTENSIONS)
            ]
            features["applescript_analysis"] = scan_applescript_analysis(
                main_binary, applescript_paths
            )
            features["obfuscation"] = detect_obfuscation_portable(features)
        else:
            features["errors"].append("Could not locate main executable")

        if deep_limit is not None:
            try:
                features["deep_scan"] = _deep_scan_bundle(bundle_info, main_binary, deep_limit)
            except Exception as e:
                features["errors"].append(f"Deep scan error: {e}")

    elif os.path.isfile(path) and is_macho(path):
        features["sample"]["type"] = "macho_binary"
        features["sample"]["sha256"] = sha256(path)
        features["sample"]["md5"] = md5(path)
        features["sample"]["filesize_bytes"] = os.path.getsize(path)
        features["macho"] = analyze_macho(path)
        features["signature"] = analyze_signature(path)
        features["strings_of_interest"] = extract_strings_of_interest(path)
        features["packer_signatures"] = detect_packer_signatures(path)
        features["applescript_analysis"] = scan_applescript_analysis(path, [])
        features["obfuscation"] = detect_obfuscation_portable(features)

    elif os.path.isfile(path):
        features["sample"]["type"] = "unknown"
        features["errors"].append(f"Not a recognized Mach-O binary or .app bundle: {path}")
    else:
        features["errors"].append(f"Path does not exist: {path}")

    # Score signing trust from the verification level analyze_signature() set
    # (cryptographic / invalid / unverified) — see macskillet.common.signature_trust
    # for why unverified "signed" claims earn no credit. features["obfuscation"]
    # (entropy/symbol/section/runtime scoring, via the shared
    # common/obfuscation_signals.py core) and the behavioral-suspicion gate's two
    # triggers all work here: features["applescript_analysis"] (run-only/compiled
    # AppleScript on the main binary and bundle scripts, via the shared
    # common/deep_scan.py function) and features["strings_of_interest"] (the same
    # shared category taxonomy the native pipeline uses).
    try:
        features["signature_trust"] = assess_signature_trust(features)
    except Exception as e:
        features["errors"].append(f"Signature-trust assessment error: {e}")

    return features


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Extract static features from macOS app/binary")
    parser.add_argument("-f", "--file", help="Path to .app bundle or Mach-O binary")
    parser.add_argument("--dir", help="Directory of samples to process in bulk")
    parser.add_argument("-o", "--output", help="Output file (JSON or JSONL for bulk)")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = parser.parse_args()

    if args.file:
        result = extract(args.file)
        output = json.dumps(result, indent=2 if args.pretty else None, default=str)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
        else:
            print(output)

    elif args.dir:
        samples = []
        for root, dirs, files in os.walk(args.dir):
            for name in files:
                full = os.path.join(root, name)
                if is_macho(full) or full.endswith(".app"):
                    samples.append(full)
            for d in dirs:
                if d.endswith(".app"):
                    samples.append(os.path.join(root, d))

        out_file = open(args.output, "w") if args.output else sys.stdout
        for sample in samples:
            result = extract(sample)
            out_file.write(json.dumps(result, default=str) + "\n")
            sys.stderr.write(f"[+] {sample} → {result['sample'].get('sha256', '?')}\n")
        if args.output:
            out_file.close()

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
