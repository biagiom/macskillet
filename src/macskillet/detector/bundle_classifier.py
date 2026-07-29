#!/usr/bin/env python3
"""
bundle_classifier.py — End-to-end CLI: macOS app in → classification report out.

This is the main entry point that chains together:
  1. Feature extraction (feature_extractor.py)
  2. Agentic classification (agent_runner.py)
  3. Formatted report output

Usage:
    python bundle_classifier.py /path/to/App.app
    python bundle_classifier.py /path/to/binary --output report.json
    python bundle_classifier.py --batch /path/to/samples/ --output results.jsonl

Requirements:
    uv sync --extra claude --extra detector
    export ANTHROPIC_API_KEY=your_key
"""

import argparse
import json
import os
import sys
from pathlib import Path

from macskillet.detector.feature_extractor import extract, is_macho
from macskillet.detector.agent_runner import run_agent


VERDICT_COLORS = {
    "MALICIOUS": "\033[91m",   # red
    "SUSPICIOUS": "\033[93m",  # yellow
    "BENIGN": "\033[92m",      # green
}
RESET = "\033[0m"
BOLD = "\033[1m"


def print_report(report: dict, color: bool = True):
    """Print a human-readable summary to stderr."""
    verdict = report.get("verdict", "UNKNOWN")
    confidence = report.get("confidence", "?")
    score = report.get("risk_score", "?")
    name = report.get("sample", {}).get("name", "?")
    sha = report.get("sample", {}).get("sha256", "?")

    color_code = VERDICT_COLORS.get(verdict, "") if color else ""

    print(f"\n{'='*60}", file=sys.stderr)
    print(f"{BOLD}Sample:{RESET}  {name}", file=sys.stderr)
    print(f"{BOLD}SHA256:{RESET}  {sha[:16]}...", file=sys.stderr)
    print(f"{BOLD}Verdict:{RESET} {color_code}{BOLD}{verdict}{RESET} ({confidence} confidence, score={score})", file=sys.stderr)
    print(f"{BOLD}Action:{RESET}  {report.get('recommendation', '?')}", file=sys.stderr)
    print(f"\n{BOLD}Summary:{RESET}", file=sys.stderr)
    print(f"  {report.get('summary', '')}", file=sys.stderr)

    indicators = report.get("key_indicators", [])
    if indicators:
        print(f"\n{BOLD}Key indicators:{RESET}", file=sys.stderr)
        for ind in indicators[:5]:
            print(f"  • {ind}", file=sys.stderr)

    chain = report.get("reasoning_chain", [])
    if chain:
        print(f"\n{BOLD}Reasoning chain ({len(chain)} steps):{RESET}", file=sys.stderr)
        for step in chain:
            delta = step.get("risk_delta", 0)
            delta_str = f"+{delta}" if delta > 0 else str(delta)
            print(f"  [{step.get('step', '?')}] {step.get('observation', '')} → {step.get('inference', '')} (Δ{delta_str})", file=sys.stderr)

    print(f"{'='*60}\n", file=sys.stderr)


def classify_one(path: str, output_path: str = None, pretty: bool = False) -> dict:
    """Classify a single sample."""
    print(f"[*] Extracting features: {path}", file=sys.stderr)
    features = extract(path)

    if features.get("errors"):
        print(f"[!] Extraction errors: {features['errors']}", file=sys.stderr)

    print(f"[*] Running agent classification...", file=sys.stderr)
    report = run_agent(features)

    print_report(report)

    if output_path:
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2 if pretty else None)
        print(f"[*] Report saved to: {output_path}", file=sys.stderr)

    return report


def classify_batch(input_dir: str, output_path: str, pretty: bool = False):
    """Classify all samples in a directory."""
    samples = []
    for root, dirs, files in os.walk(input_dir):
        for name in files:
            full = os.path.join(root, name)
            if is_macho(full):
                samples.append(full)
        for d in dirs:
            if d.endswith(".app"):
                samples.append(os.path.join(root, d))
                dirs.remove(d)  # don't recurse into .app bundles

    print(f"[*] Found {len(samples)} samples in {input_dir}", file=sys.stderr)

    with open(output_path, "w") as out:
        for i, sample in enumerate(samples):
            print(f"\n[{i+1}/{len(samples)}] Processing: {sample}", file=sys.stderr)
            try:
                features = extract(sample)
                report = run_agent(features)
                print_report(report)
                out.write(json.dumps(report) + "\n")
                out.flush()
            except Exception as e:
                print(f"[!] Error processing {sample}: {e}", file=sys.stderr)
                error_record = {
                    "sample": {"path": sample, "name": os.path.basename(sample)},
                    "verdict": "ERROR",
                    "error": str(e),
                }
                out.write(json.dumps(error_record) + "\n")
                out.flush()

    print(f"\n[*] Batch complete. Results written to: {output_path}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="macOS App Classifier — static analysis + agentic AI verdict",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/App.app
  %(prog)s /path/to/binary --output report.json --pretty
  %(prog)s --batch /path/to/samples/ --output results.jsonl
        """
    )
    parser.add_argument("sample", nargs="?", help="Path to .app bundle or Mach-O binary")
    parser.add_argument("--batch", metavar="DIR", help="Classify all samples in directory")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    parser.add_argument("--json", action="store_true", help="Print full JSON report to stdout")
    args = parser.parse_args()

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("[!] Error: ANTHROPIC_API_KEY environment variable not set", file=sys.stderr)
        sys.exit(1)

    if args.batch:
        if not args.output:
            print("[!] --batch requires --output", file=sys.stderr)
            sys.exit(1)
        classify_batch(args.batch, args.output, args.pretty)

    elif args.sample:
        report = classify_one(args.sample, args.output, args.pretty)
        if args.json or not args.output:
            print(json.dumps(report, indent=2 if args.pretty else None))

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
