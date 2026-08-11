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


# ---------------------------------------------------------------------------
# Main extraction pipeline
# ---------------------------------------------------------------------------

def extract(path: str) -> dict:
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
        else:
            features["errors"].append("Could not locate main executable")

    elif os.path.isfile(path) and is_macho(path):
        features["sample"]["type"] = "macho_binary"
        features["sample"]["sha256"] = sha256(path)
        features["sample"]["md5"] = md5(path)
        features["sample"]["filesize_bytes"] = os.path.getsize(path)
        features["macho"] = analyze_macho(path)
        features["signature"] = analyze_signature(path)
        features["strings_of_interest"] = extract_strings_of_interest(path)

    elif os.path.isfile(path):
        features["sample"]["type"] = "unknown"
        features["errors"].append(f"Not a recognized Mach-O binary or .app bundle: {path}")
    else:
        features["errors"].append(f"Path does not exist: {path}")

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
